package backend

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// Encrypted file format:
//
//	[4B magic "GFSE"] [1B version=1] [4B chunk_size_BE]
//	[chunk: 12B nonce + N bytes ciphertext + 16B GCM tag] × …
//
// Each chunk is encrypted independently with AES-256-GCM, allowing streaming
// decryption without buffering the entire file in memory. The final chunk may
// be shorter than chunk_size.

var encMagic = [4]byte{'G', 'F', 'S', 'E'}

const (
	encVersion    = 1
	encChunkSize  = 32 * 1024 * 1024 // 32 MB per chunk
	gcmNonceSize  = 12
	gcmTagSize    = 16
	encHeaderSize = 4 + 1 + 4 // magic + version + chunk_size
)

// encryptToFile reads plaintext from r and writes the encrypted file format to
// a new temp file. Returns the temp file (seeked to start) and its size.
// Caller must close and remove the file.
func encryptToFile(key []byte, r io.Reader, tempDir string) (*os.File, int64, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, fmt.Errorf("gcm: %w", err)
	}

	tmp, err := os.CreateTemp(tempDir, "gigafile-enc-*")
	if err != nil {
		return nil, 0, fmt.Errorf("create encrypted temp: %w", err)
	}

	// Write header
	var header [encHeaderSize]byte
	copy(header[:4], encMagic[:])
	header[4] = encVersion
	binary.BigEndian.PutUint32(header[5:9], encChunkSize)
	if _, err := tmp.Write(header[:]); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, 0, err
	}

	buf := make([]byte, encChunkSize)
	nonce := make([]byte, gcmNonceSize)
	var written int64 = encHeaderSize

	for {
		n, readErr := io.ReadFull(r, buf)
		if n > 0 {
			if _, err := rand.Read(nonce); err != nil {
				tmp.Close()
				os.Remove(tmp.Name())
				return nil, 0, fmt.Errorf("rand nonce: %w", err)
			}
			if _, err := tmp.Write(nonce); err != nil {
				tmp.Close()
				os.Remove(tmp.Name())
				return nil, 0, err
			}
			ct := gcm.Seal(nil, nonce, buf[:n], nil)
			if _, err := tmp.Write(ct); err != nil {
				tmp.Close()
				os.Remove(tmp.Name())
				return nil, 0, err
			}
			written += int64(gcmNonceSize + len(ct))
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, 0, fmt.Errorf("read plaintext: %w", readErr)
		}
	}

	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, 0, err
	}
	return tmp, written, nil
}

// streamDecryptor decrypts an AES-256-GCM chunked ciphertext stream on the fly.
// Each 32 MB chunk is verified and decrypted as it arrives, so the caller
// receives plaintext immediately instead of waiting for the full download.
// It implements io.ReadCloser; closing it closes the underlying source.
type streamDecryptor struct {
	gcm       cipher.AEAD
	src       io.ReadCloser
	chunkSize int
	nonce     []byte
	ctBuf     []byte
	plain     []byte // buffered plaintext from the most recently decrypted chunk
	done      bool
}

// newStreamDecryptor reads and validates the GFSE header from src, then returns
// a streaming decryptor. src is owned by the returned decryptor.
func newStreamDecryptor(key []byte, src io.ReadCloser) (*streamDecryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	var header [encHeaderSize]byte
	if _, err := io.ReadFull(src, header[:]); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if [4]byte(header[:4]) != encMagic {
		return nil, fmt.Errorf("invalid magic: not an encrypted gigafile-fs object")
	}
	if header[4] != encVersion {
		return nil, fmt.Errorf("unsupported encryption version: %d", header[4])
	}
	chunkSize := int(binary.BigEndian.Uint32(header[5:9]))

	return &streamDecryptor{
		gcm:       gcm,
		src:       src,
		chunkSize: chunkSize,
		nonce:     make([]byte, gcmNonceSize),
		ctBuf:     make([]byte, chunkSize+gcmTagSize),
	}, nil
}

func (d *streamDecryptor) Read(p []byte) (int, error) {
	for {
		if len(d.plain) > 0 {
			n := copy(p, d.plain)
			d.plain = d.plain[n:]
			return n, nil
		}
		if d.done {
			return 0, io.EOF
		}
		if err := d.nextChunk(); err != nil {
			return 0, err
		}
	}
}

func (d *streamDecryptor) nextChunk() error {
	if _, err := io.ReadFull(d.src, d.nonce); err == io.EOF {
		d.done = true
		return nil
	} else if err != nil {
		return fmt.Errorf("read nonce: %w", err)
	}

	n, readErr := io.ReadFull(d.src, d.ctBuf)
	if n == 0 {
		d.done = true
		return nil
	}

	plain, err := d.gcm.Open(nil, d.nonce, d.ctBuf[:n], nil)
	if err != nil {
		return fmt.Errorf("decrypt chunk: %w", err)
	}
	d.plain = plain

	if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
		d.done = true
	}
	return nil
}

func (d *streamDecryptor) Close() error { return d.src.Close() }

// closerWithReader pairs an io.Closer with a (possibly wrapped) io.Reader.
// Used when the close target and the read source differ, e.g. LimitReader over a stream.
type closerWithReader struct {
	io.Closer
	reader io.Reader
}

func (c *closerWithReader) Read(p []byte) (int, error) { return c.reader.Read(p) }
