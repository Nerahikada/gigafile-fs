package backend

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/johannesboyne/gofakes3"
	"github.com/Nerahikada/gigafile-fs/db"
	"github.com/Nerahikada/gigafile-fs/gigafile"
)

// mpPart is one upload part stored as a temp file on disk.
type mpPart struct {
	file         *os.File
	size         int64
	etag         string
	lastModified time.Time
}

// mpUpload tracks an in-progress multipart upload.
type mpUpload struct {
	bucket    string
	object    string
	meta      map[string]string
	initiated time.Time
	parts     map[int]*mpPart
	mu        sync.Mutex
}

// Compile-time assertion that Backend implements gofakes3.MultipartBackend.
var _ gofakes3.MultipartBackend = (*Backend)(nil)

// CreateMultipartUpload begins a new multipart upload.
func (b *Backend) CreateMultipartUpload(bucket, object string, meta map[string]string) (gofakes3.UploadID, error) {
	id := gofakes3.UploadID(fmt.Sprintf("%d", atomic.AddUint64(&b.nextID, 1)))
	mpu := &mpUpload{
		bucket:    bucket,
		object:    object,
		meta:      meta,
		initiated: time.Now(),
		parts:     make(map[int]*mpPart),
	}
	b.uploadsMu.Lock()
	b.uploads[id] = mpu
	b.uploadsMu.Unlock()
	return id, nil
}

// UploadPart writes a single part to a temp file on disk.
func (b *Backend) UploadPart(bucket, object string, id gofakes3.UploadID, partNumber int, contentLength int64, input io.Reader) (string, error) {
	b.uploadsMu.Lock()
	mpu, ok := b.uploads[id]
	b.uploadsMu.Unlock()
	if !ok || mpu.bucket != bucket || mpu.object != object {
		return "", gofakes3.ErrNoSuchUpload
	}

	tmp, err := os.CreateTemp(b.tempDir, fmt.Sprintf("gigafile-part-%s-%d-*", id, partNumber))
	if err != nil {
		return "", fmt.Errorf("create part temp: %w", err)
	}

	h := md5.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), input)
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", fmt.Errorf("write part: %w", err)
	}
	if contentLength >= 0 && n != contentLength {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", gofakes3.ErrIncompleteBody
	}

	etag := fmt.Sprintf(`"%s"`, hex.EncodeToString(h.Sum(nil)))

	mpu.mu.Lock()
	defer mpu.mu.Unlock()
	// Replace any previously uploaded part with the same number.
	if old, exists := mpu.parts[partNumber]; exists {
		old.file.Close()
		os.Remove(old.file.Name())
	}
	mpu.parts[partNumber] = &mpPart{
		file:         tmp,
		size:         n,
		etag:         etag,
		lastModified: time.Now(),
	}
	return etag, nil
}

// AbortMultipartUpload cancels an upload and removes all temp files.
func (b *Backend) AbortMultipartUpload(bucket, object string, id gofakes3.UploadID) error {
	b.uploadsMu.Lock()
	mpu, ok := b.uploads[id]
	if !ok || mpu.bucket != bucket || mpu.object != object {
		b.uploadsMu.Unlock()
		return gofakes3.ErrNoSuchUpload
	}
	delete(b.uploads, id)
	b.uploadsMu.Unlock()

	b.cleanupUpload(mpu)
	return nil
}

// ListMultipartUploads returns in-progress uploads for a bucket.
func (b *Backend) ListMultipartUploads(bucket string, marker *gofakes3.UploadListMarker, prefix gofakes3.Prefix, limit int64) (*gofakes3.ListMultipartUploadsResult, error) {
	b.uploadsMu.Lock()
	defer b.uploadsMu.Unlock()

	result := &gofakes3.ListMultipartUploadsResult{
		Bucket:     bucket,
		MaxUploads: limit,
	}

	type entry struct {
		id  gofakes3.UploadID
		mpu *mpUpload
	}
	var entries []entry
	for id, mpu := range b.uploads {
		if mpu.bucket == bucket {
			entries = append(entries, entry{id, mpu})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].mpu.object != entries[j].mpu.object {
			return entries[i].mpu.object < entries[j].mpu.object
		}
		return string(entries[i].id) < string(entries[j].id)
	})

	pastMarker := marker == nil
	var cnt int64
	for _, e := range entries {
		if !pastMarker {
			if e.mpu.object > marker.Object ||
				(e.mpu.object == marker.Object && string(e.id) > string(marker.UploadID)) {
				pastMarker = true
			} else {
				continue
			}
		}
		var match gofakes3.PrefixMatch
		if !prefix.Match(e.mpu.object, &match) || match.CommonPrefix {
			continue
		}
		if cnt >= limit {
			result.IsTruncated = true
			break
		}
		result.Uploads = append(result.Uploads, gofakes3.ListMultipartUploadItem{
			Key:          e.mpu.object,
			UploadID:     e.id,
			StorageClass: "STANDARD",
			Initiated:    gofakes3.NewContentTime(e.mpu.initiated),
		})
		cnt++
	}
	return result, nil
}

// ListParts returns metadata for the uploaded parts of a multipart upload.
func (b *Backend) ListParts(bucket, object string, uploadID gofakes3.UploadID, marker int, limit int64) (*gofakes3.ListMultipartUploadPartsResult, error) {
	b.uploadsMu.Lock()
	mpu, ok := b.uploads[uploadID]
	b.uploadsMu.Unlock()
	if !ok || mpu.bucket != bucket || mpu.object != object {
		return nil, gofakes3.ErrNoSuchUpload
	}

	mpu.mu.Lock()
	defer mpu.mu.Unlock()

	result := &gofakes3.ListMultipartUploadPartsResult{
		Bucket:           bucket,
		Key:              object,
		UploadID:         uploadID,
		MaxParts:         limit,
		PartNumberMarker: marker,
		StorageClass:     "STANDARD",
	}

	var partNums []int
	for pn := range mpu.parts {
		if pn > marker {
			partNums = append(partNums, pn)
		}
	}
	sort.Ints(partNums)

	var cnt int64
	for _, pn := range partNums {
		if cnt >= limit {
			result.IsTruncated = true
			result.NextPartNumberMarker = pn
			break
		}
		p := mpu.parts[pn]
		result.Parts = append(result.Parts, gofakes3.ListMultipartUploadPartItem{
			PartNumber:   pn,
			LastModified: gofakes3.NewContentTime(p.lastModified),
			ETag:         p.etag,
			Size:         p.size,
		})
		cnt++
	}
	return result, nil
}

// CompleteMultipartUpload assembles the parts and streams them to gigafile.nu.
// Parts are read directly from disk temp files — no full-file memory buffer.
func (b *Backend) CompleteMultipartUpload(bucket, object string, id gofakes3.UploadID, input *gofakes3.CompleteMultipartUploadRequest) (gofakes3.VersionID, string, error) {
	// Remove from the map immediately so no concurrent operation can interfere.
	b.uploadsMu.Lock()
	mpu, ok := b.uploads[id]
	if !ok || mpu.bucket != bucket || mpu.object != object {
		b.uploadsMu.Unlock()
		return "", "", gofakes3.ErrNoSuchUpload
	}
	delete(b.uploads, id)
	b.uploadsMu.Unlock()

	mpu.mu.Lock()

	// Validate parts and build the streaming reader list.
	var readers []io.Reader
	var totalSize int64
	hashParts := md5.New()

	for _, inPart := range input.Parts {
		p, exists := mpu.parts[inPart.PartNumber]
		if !exists {
			mpu.mu.Unlock()
			b.cleanupUpload(mpu)
			return "", "", gofakes3.ErrorMessagef(gofakes3.ErrInvalidPart, "part %d not found", inPart.PartNumber)
		}
		if strings.Trim(inPart.ETag, `"`) != strings.Trim(p.etag, `"`) {
			mpu.mu.Unlock()
			b.cleanupUpload(mpu)
			return "", "", gofakes3.ErrorMessagef(gofakes3.ErrInvalidPart, "etag mismatch for part %d", inPart.PartNumber)
		}
		if _, err := p.file.Seek(0, io.SeekStart); err != nil {
			mpu.mu.Unlock()
			b.cleanupUpload(mpu)
			return "", "", fmt.Errorf("seek part %d: %w", inPart.PartNumber, err)
		}
		readers = append(readers, p.file)
		totalSize += p.size
		hashBytes, _ := hex.DecodeString(strings.Trim(p.etag, `"`))
		hashParts.Write(hashBytes)
	}

	etag := fmt.Sprintf(`"%s-%d"`, hex.EncodeToString(hashParts.Sum(nil)), len(input.Parts))
	meta := mpu.meta
	mpu.mu.Unlock()

	// Assemble and upload to gigafile.nu.
	// With encryption the plaintext must be fully assembled first so it can be
	// encrypted chunk-by-chunk before upload. Without encryption we stream parts
	// directly to save disk space.
	// Stream parts to gigafile.nu, encrypting on the fly if enabled.
	// Part temp files are cleaned up after the upload reads them.
	var (
		result    *gigafile.UploadResult
		uploadErr error
	)
	if b.encKey != nil {
		se, err := newStreamEncryptor(b.encKey, io.MultiReader(readers...))
		if err != nil {
			b.cleanupUpload(mpu)
			return "", "", fmt.Errorf("encrypt: %w", err)
		}
		result, uploadErr = b.gf.Upload(object, calcCiphertextSize(totalSize), se)
		b.cleanupUpload(mpu)
	} else {
		result, uploadErr = b.gf.Upload(object, totalSize, io.MultiReader(readers...))
		b.cleanupUpload(mpu)
	}
	if uploadErr != nil {
		return "", "", fmt.Errorf("gigafile upload: %w", uploadErr)
	}

	contentType := "application/octet-stream"
	if ct, ok := meta["content-type"]; ok && ct != "" {
		contentType = ct
	}

	now := time.Now()
	if err := b.db.Put(db.Object{
		Bucket:         bucket,
		Key:            object,
		GigafileURL:    result.URL,
		FileID:         result.FileID,
		GigafileDomain: result.Domain,
		DelKey:         result.DelKey,
		UploadTime:     now,
		ExpiryTime:     now.Add(100 * 24 * time.Hour),
		Size:           totalSize,
		ContentType:    contentType,
		ETag:           etag,
	}); err != nil {
		return "", "", fmt.Errorf("db put: %w", err)
	}

	log.Printf("PUT (multipart) s3://%s/%s → %s (size=%d, parts=%d)", bucket, object, result.URL, totalSize, len(input.Parts))
	return "", etag, nil
}

// cleanupUpload closes and removes all temp files for an upload.
func (b *Backend) cleanupUpload(mpu *mpUpload) {
	mpu.mu.Lock()
	defer mpu.mu.Unlock()
	for _, p := range mpu.parts {
		p.file.Close()
		os.Remove(p.file.Name())
	}
}
