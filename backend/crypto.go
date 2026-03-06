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

// decryptToFile reads the encrypted file format from r and writes decrypted
// plaintext to a new temp file. Returns the temp file (seeked to start).
// Caller must close and remove the file.
func decryptToFile(key []byte, r io.Reader, tempDir string) (*os.File, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	// Read and validate header
	var header [encHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	if [4]byte(header[:4]) != encMagic {
		return nil, fmt.Errorf("invalid magic: not an encrypted gigafile-fs object")
	}
	if header[4] != encVersion {
		return nil, fmt.Errorf("unsupported encryption version: %d", header[4])
	}
	chunkSize := int(binary.BigEndian.Uint32(header[5:9]))

	tmp, err := os.CreateTemp(tempDir, "gigafile-dec-*")
	if err != nil {
		return nil, fmt.Errorf("create decrypted temp: %w", err)
	}

	nonce := make([]byte, gcmNonceSize)
	ctBuf := make([]byte, chunkSize+gcmTagSize)

	for {
		// Read nonce — EOF here means we finished all chunks cleanly.
		if _, err := io.ReadFull(r, nonce); err == io.EOF {
			break
		} else if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, fmt.Errorf("read nonce: %w", err)
		}

		// Read ciphertext+tag for this chunk.
		n, readErr := io.ReadFull(r, ctBuf)
		if n == 0 {
			if readErr == io.EOF {
				break
			}
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, fmt.Errorf("read ciphertext: %w", readErr)
		}

		plaintext, err := gcm.Open(nil, nonce, ctBuf[:n], nil)
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, fmt.Errorf("decrypt chunk: %w", err)
		}
		if _, err := tmp.Write(plaintext); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, err
		}

		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			break
		}
		if readErr != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return nil, fmt.Errorf("read ciphertext: %w", readErr)
		}
	}

	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	return tmp, nil
}

// tempFileBody is an io.ReadCloser backed by a temp file that removes the file on Close.
type tempFileBody struct {
	file   *os.File
	reader io.Reader
}

func (t *tempFileBody) Read(p []byte) (int, error) { return t.reader.Read(p) }
func (t *tempFileBody) Close() error {
	name := t.file.Name()
	err := t.file.Close()
	os.Remove(name)
	return err
}
