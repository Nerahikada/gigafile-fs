// Package backend implements a gofakes3.Backend that stores objects on gigafile.nu.
package backend

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/johannesboyne/gofakes3"
	"github.com/Nerahikada/gigafile-fs/db"
	"github.com/Nerahikada/gigafile-fs/gigafile"
)

// Backend implements gofakes3.Backend backed by gigafile.nu.
// It also implements gofakes3.MultipartBackend to store upload parts on disk
// instead of in memory, avoiding buffering the full file in RAM.
type Backend struct {
	db      *db.DB
	gf      *gigafile.Client
	tempDir string
	encKey  []byte // AES-256 key; nil means encryption disabled

	// multipart upload tracking
	uploads   map[gofakes3.UploadID]*mpUpload
	uploadsMu sync.Mutex
	nextID    uint64 // atomically incremented to generate upload IDs
}

// New creates a Backend using the given database, temp directory, and optional
// encryption key. Pass nil for encKey to disable encryption.
func New(database *db.DB, tempDir string, encKey []byte) *Backend {
	return &Backend{
		db:      database,
		gf:      gigafile.New(),
		tempDir: tempDir,
		encKey:  encKey,
		uploads: make(map[gofakes3.UploadID]*mpUpload),
	}
}

// ---------- bucket operations ----------

func (b *Backend) ListBuckets() ([]gofakes3.BucketInfo, error) {
	buckets, err := b.db.ListBuckets()
	if err != nil {
		return nil, err
	}
	out := make([]gofakes3.BucketInfo, 0, len(buckets))
	for _, bkt := range buckets {
		out = append(out, gofakes3.BucketInfo{
			Name:         bkt.Name,
			CreationDate: gofakes3.NewContentTime(bkt.CreatedAt),
		})
	}
	return out, nil
}

func (b *Backend) BucketExists(name string) (bool, error) {
	return b.db.BucketExists(name)
}

func (b *Backend) CreateBucket(name string) error {
	created, err := b.db.CreateBucket(name, time.Now())
	if err != nil {
		return err
	}
	if !created {
		return gofakes3.ResourceError(gofakes3.ErrBucketAlreadyExists, name)
	}
	return nil
}

func (b *Backend) DeleteBucket(name string) error {
	exists, err := b.db.BucketExists(name)
	if err != nil {
		return err
	}
	if !exists {
		return gofakes3.BucketNotFound(name)
	}
	objects, err := b.db.List(name, "")
	if err != nil {
		return err
	}
	if len(objects) > 0 {
		return gofakes3.ResourceError(gofakes3.ErrBucketNotEmpty, name)
	}
	return b.db.DeleteBucket(name)
}

func (b *Backend) ForceDeleteBucket(name string) error {
	return b.db.DeleteBucket(name)
}

// ---------- object list ----------

func (b *Backend) ListBucket(name string, prefix *gofakes3.Prefix, page gofakes3.ListBucketPage) (*gofakes3.ObjectList, error) {
	if ok, err := b.db.BucketExists(name); err != nil {
		return nil, err
	} else if !ok {
		return nil, gofakes3.BucketNotFound(name)
	}

	pfx := ""
	if prefix != nil {
		pfx = prefix.Prefix
	}

	objects, err := b.db.List(name, pfx)
	if err != nil {
		return nil, err
	}

	result := gofakes3.NewObjectList()

	for _, obj := range objects {
		if prefix != nil {
			var match gofakes3.PrefixMatch
			if !prefix.Match(obj.Key, &match) {
				continue
			}
			if match.CommonPrefix {
				result.AddPrefix(match.MatchedPart)
				continue
			}
		}

		result.Add(&gofakes3.Content{
			Key:          obj.Key,
			LastModified: gofakes3.NewContentTime(obj.UploadTime),
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: "STANDARD",
			Owner: &gofakes3.UserInfo{
				ID:          "gigafile",
				DisplayName: "gigafile",
			},
		})
	}
	return result, nil
}

// ---------- HeadObject ----------

func (b *Backend) HeadObject(bucketName, objectName string) (*gofakes3.Object, error) {
	if ok, err := b.db.BucketExists(bucketName); err != nil {
		return nil, err
	} else if !ok {
		return nil, gofakes3.BucketNotFound(bucketName)
	}

	obj, err := b.db.Get(bucketName, objectName)
	if err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, gofakes3.KeyNotFound(objectName)
	}

	hash, _ := hex.DecodeString(strings.Trim(obj.ETag, `"`))
	return &gofakes3.Object{
		Name:     objectName,
		Hash:     hash,
		Metadata: map[string]string{"content-type": obj.ContentType},
		Size:     obj.Size,
		Contents: io.NopCloser(bytes.NewReader(nil)),
	}, nil
}

// ---------- GetObject ----------

func (b *Backend) GetObject(bucketName, objectName string, rangeRequest *gofakes3.ObjectRangeRequest) (*gofakes3.Object, error) {
	if ok, err := b.db.BucketExists(bucketName); err != nil {
		return nil, err
	} else if !ok {
		return nil, gofakes3.BucketNotFound(bucketName)
	}

	obj, err := b.db.Get(bucketName, objectName)
	if err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, gofakes3.KeyNotFound(objectName)
	}

	hash, _ := hex.DecodeString(strings.Trim(obj.ETag, `"`))

	if b.encKey != nil {
		// Encrypted path: download full ciphertext, decrypt, then apply range.
		ctTmp, err := os.CreateTemp(b.tempDir, "gigafile-ct-*")
		if err != nil {
			return nil, fmt.Errorf("create ciphertext temp: %w", err)
		}
		if err := b.gf.Download(obj.GigafileDomain, obj.FileID, ctTmp, ""); err != nil {
			ctTmp.Close()
			os.Remove(ctTmp.Name())
			return nil, fmt.Errorf("gigafile download: %w", err)
		}
		if _, err := ctTmp.Seek(0, io.SeekStart); err != nil {
			ctTmp.Close()
			os.Remove(ctTmp.Name())
			return nil, err
		}

		ptTmp, err := decryptToFile(b.encKey, ctTmp, b.tempDir)
		ctTmp.Close()
		os.Remove(ctTmp.Name())
		if err != nil {
			return nil, fmt.Errorf("decrypt: %w", err)
		}

		size := obj.Size
		var rng *gofakes3.ObjectRange
		var reader io.Reader = ptTmp
		if rangeRequest != nil {
			rng, err = rangeRequest.Range(obj.Size)
			if err != nil {
				ptTmp.Close()
				os.Remove(ptTmp.Name())
				return nil, err
			}
			if rng != nil {
				if _, err := ptTmp.Seek(rng.Start, io.SeekStart); err != nil {
					ptTmp.Close()
					os.Remove(ptTmp.Name())
					return nil, err
				}
				reader = io.LimitReader(ptTmp, rng.Length)
				size = rng.Length
			}
		}

		return &gofakes3.Object{
			Name:     objectName,
			Hash:     hash,
			Metadata: map[string]string{"content-type": obj.ContentType},
			Size:     size,
			Contents: &tempFileBody{file: ptTmp, reader: reader},
			Range:    rng,
		}, nil
	}

	// Unencrypted path: stream directly from gigafile.nu (supports Range header).
	rangeHeader := ""
	if rangeRequest != nil {
		r, err := rangeRequest.Range(obj.Size)
		if err != nil {
			return nil, err
		}
		if r != nil {
			rangeHeader = fmt.Sprintf("bytes=%d-%d", r.Start, r.Start+r.Length-1)
		}
	}

	resp, err := b.gf.DownloadResponse(obj.GigafileDomain, obj.FileID, rangeHeader)
	if err != nil {
		return nil, fmt.Errorf("gigafile download: %w", err)
	}

	size := obj.Size
	var rng *gofakes3.ObjectRange
	if rangeRequest != nil {
		rng, _ = rangeRequest.Range(obj.Size)
		if rng != nil {
			size = rng.Length
		}
	}

	return &gofakes3.Object{
		Name:     objectName,
		Hash:     hash,
		Metadata: map[string]string{"content-type": obj.ContentType},
		Size:     size,
		Contents: resp.Body,
		Range:    rng,
	}, nil
}

// ---------- PutObject ----------

func (b *Backend) PutObject(bucketName, key string, meta map[string]string, input io.Reader, size int64, conditions *gofakes3.PutConditions) (gofakes3.PutObjectResult, error) {
	if ok, err := b.db.BucketExists(bucketName); err != nil {
		return gofakes3.PutObjectResult{}, err
	} else if !ok {
		return gofakes3.PutObjectResult{}, gofakes3.BucketNotFound(bucketName)
	}

	if conditions != nil {
		existing, err := b.db.Get(bucketName, key)
		if err != nil {
			return gofakes3.PutObjectResult{}, err
		}
		var objInfo gofakes3.ConditionalObjectInfo
		if existing != nil {
			hash, _ := hex.DecodeString(strings.Trim(existing.ETag, `"`))
			objInfo = gofakes3.ConditionalObjectInfo{Exists: true, Hash: hash}
		}
		if err := gofakes3.CheckPutConditions(conditions, &objInfo); err != nil {
			return gofakes3.PutObjectResult{}, err
		}
	}

	// Buffer to temp file so we know the size and can compute hash
	tmp, err := os.CreateTemp(b.tempDir, "gigafile-put-*")
	if err != nil {
		return gofakes3.PutObjectResult{}, fmt.Errorf("create temp: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	h := md5.New()
	w := io.MultiWriter(tmp, h)
	written, err := io.Copy(w, input)
	if err != nil {
		return gofakes3.PutObjectResult{}, fmt.Errorf("buffer input: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return gofakes3.PutObjectResult{}, err
	}
	if size <= 0 {
		size = written
	}

	etag := `"` + hex.EncodeToString(h.Sum(nil)) + `"`

	contentType := "application/octet-stream"
	if ct, ok := meta["content-type"]; ok && ct != "" {
		contentType = ct
	}

	// uploadReader is what we actually send to gigafile.nu.
	// With encryption it is the ciphertext temp file; without it is the plaintext temp file.
	uploadReader := io.ReadSeeker(tmp)
	uploadSize := size
	if b.encKey != nil {
		encTmp, encSize, err := encryptToFile(b.encKey, tmp, b.tempDir)
		if err != nil {
			return gofakes3.PutObjectResult{}, fmt.Errorf("encrypt: %w", err)
		}
		defer os.Remove(encTmp.Name())
		defer encTmp.Close()
		uploadReader = encTmp
		uploadSize = encSize
	}

	result, err := b.gf.Upload(key, uploadSize, uploadReader)
	if err != nil {
		return gofakes3.PutObjectResult{}, fmt.Errorf("gigafile upload: %w", err)
	}

	now := time.Now()
	if err := b.db.Put(db.Object{
		Bucket:         bucketName,
		Key:            key,
		GigafileURL:    result.URL,
		FileID:         result.FileID,
		GigafileDomain: result.Domain,
		DelKey:         result.DelKey,
		UploadTime:     now,
		ExpiryTime:     now.Add(100 * 24 * time.Hour),
		Size:           size,
		ContentType:    contentType,
		ETag:           etag,
	}); err != nil {
		return gofakes3.PutObjectResult{}, fmt.Errorf("db put: %w", err)
	}

	log.Printf("PUT s3://%s/%s → %s (size=%d)", bucketName, key, result.URL, size)
	return gofakes3.PutObjectResult{}, nil
}

// ---------- DeleteObject ----------

func (b *Backend) DeleteObject(bucketName, objectName string) (gofakes3.ObjectDeleteResult, error) {
	if ok, err := b.db.BucketExists(bucketName); err != nil {
		return gofakes3.ObjectDeleteResult{}, err
	} else if !ok {
		return gofakes3.ObjectDeleteResult{}, gofakes3.BucketNotFound(bucketName)
	}
	obj, err := b.db.Get(bucketName, objectName)
	if err != nil {
		return gofakes3.ObjectDeleteResult{}, err
	}
	if obj != nil && obj.DelKey != "" {
		if err := b.gf.DeleteFile(obj.GigafileDomain, obj.FileID, obj.DelKey); err != nil {
			log.Printf("DELETE %s/%s: gigafile remove failed (file may remain on server): %v", bucketName, objectName, err)
		}
	}
	_ = b.db.SoftDelete(bucketName, objectName)
	return gofakes3.ObjectDeleteResult{}, nil
}

// ---------- DeleteMulti ----------

func (b *Backend) DeleteMulti(bucketName string, objects ...string) (gofakes3.MultiDeleteResult, error) {
	var result gofakes3.MultiDeleteResult
	for _, key := range objects {
		obj, err := b.db.Get(bucketName, key)
		if err != nil {
			result.Error = append(result.Error, gofakes3.ErrorResult{
				Key:     key,
				Code:    "InternalError",
				Message: err.Error(),
			})
			continue
		}
		if obj != nil && obj.DelKey != "" {
			if err := b.gf.DeleteFile(obj.GigafileDomain, obj.FileID, obj.DelKey); err != nil {
				log.Printf("DELETE %s/%s: gigafile remove failed (file may remain on server): %v", bucketName, key, err)
			}
		}
		if err := b.db.SoftDelete(bucketName, key); err != nil {
			result.Error = append(result.Error, gofakes3.ErrorResult{
				Key:     key,
				Code:    "InternalError",
				Message: err.Error(),
			})
		} else {
			result.Deleted = append(result.Deleted, gofakes3.ObjectID{Key: key})
		}
	}
	return result, nil
}

// ---------- CopyObject ----------

func (b *Backend) CopyObject(srcBucket, srcKey, dstBucket, dstKey string, meta map[string]string) (gofakes3.CopyObjectResult, error) {
	return gofakes3.CopyObject(b, srcBucket, srcKey, dstBucket, dstKey, meta)
}

// ---------- auto-renewal ----------

// RenewExpiring downloads files expiring within `within` and re-uploads them to gigafile.nu.
func (b *Backend) RenewExpiring(within time.Duration) {
	objects, err := b.db.ListExpiringSoon(within)
	if err != nil {
		log.Printf("renewal: list expiring: %v", err)
		return
	}
	for _, obj := range objects {
		if err := b.renewObject(obj); err != nil {
			log.Printf("renewal: %s/%s: %v", obj.Bucket, obj.Key, err)
		} else {
			log.Printf("renewal: refreshed %s/%s → expires %s", obj.Bucket, obj.Key, obj.ExpiryTime.Format(time.DateOnly))
		}
	}
}

func (b *Backend) renewObject(obj db.Object) error {
	// Download from gigafile.nu into a temp file
	tmp, err := os.CreateTemp(b.tempDir, "gigafile-renew-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if err := b.gf.Download(obj.GigafileDomain, obj.FileID, tmp, ""); err != nil {
		return fmt.Errorf("download for renewal: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}

	// Re-upload to gigafile.nu
	result, err := b.gf.Upload(obj.Key, obj.Size, tmp)
	if err != nil {
		return fmt.Errorf("re-upload: %w", err)
	}

	// Update metadata
	now := time.Now()
	if err := b.db.Put(db.Object{
		Bucket:         obj.Bucket,
		Key:            obj.Key,
		GigafileURL:    result.URL,
		FileID:         result.FileID,
		GigafileDomain: result.Domain,
		DelKey:         result.DelKey,
		UploadTime:     now,
		ExpiryTime:     now.Add(100 * 24 * time.Hour),
		Size:           obj.Size,
		ContentType:    obj.ContentType,
		ETag:           obj.ETag,
	}); err != nil {
		return err
	}

	// Delete the old file from gigafile.nu now that the new one is recorded
	if obj.DelKey != "" {
		if err := b.gf.DeleteFile(obj.GigafileDomain, obj.FileID, obj.DelKey); err != nil {
			log.Printf("renewal: delete old file %s: %v", obj.FileID, err)
		}
	}
	return nil
}

// EnsureBucket creates a bucket if it doesn't already exist (idempotent).
func (b *Backend) EnsureBucket(name string) {
	if _, err := b.db.CreateBucket(name, time.Now()); err != nil {
		log.Printf("EnsureBucket %q: %v", name, err)
	}
}
