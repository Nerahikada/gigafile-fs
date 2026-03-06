package backend

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
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

// calcCiphertextSize returns the encrypted byte count for a given plaintext size.
// Formula: header + numChunks × (nonce + tag) + plaintextSize
func calcCiphertextSize(plaintextSize int64) int64 {
	numChunks := (plaintextSize + int64(encChunkSize) - 1) / int64(encChunkSize)
	return int64(encHeaderSize) + numChunks*int64(gcmNonceSize+gcmTagSize) + plaintextSize
}

// streamEncryptor is an io.Reader that encrypts plaintext from src on the fly,
// producing the GFSE chunked format without buffering the entire file.
// Zero-allocation per chunk: nonce and ciphertext reuse pre-allocated slices.
type streamEncryptor struct {
	gcm        cipher.AEAD
	src        io.Reader
	nonce      [gcmNonceSize]byte
	plainBuf   []byte // scratch buffer for reading one plaintext chunk
	pendingBuf []byte // scratch buffer for nonce + ciphertext + tag
	pending    []byte // unread portion of pendingBuf (or header)
	header     [encHeaderSize]byte
	done       bool
}

// newStreamEncryptor returns a streaming encryptor whose first Read emits the
// GFSE header followed by encrypted chunks read from src.
func newStreamEncryptor(key []byte, src io.Reader) (*streamEncryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	se := &streamEncryptor{
		gcm:        gcm,
		src:        src,
		plainBuf:   make([]byte, encChunkSize),
		pendingBuf: make([]byte, gcmNonceSize+encChunkSize+gcmTagSize),
	}
	copy(se.header[:4], encMagic[:])
	se.header[4] = encVersion
	binary.BigEndian.PutUint32(se.header[5:9], encChunkSize)
	se.pending = se.header[:] // emit header on first Read
	return se, nil
}

func (e *streamEncryptor) Read(p []byte) (int, error) {
	for {
		if len(e.pending) > 0 {
			n := copy(p, e.pending)
			e.pending = e.pending[n:]
			return n, nil
		}
		if e.done {
			return 0, io.EOF
		}
		n, readErr := io.ReadFull(e.src, e.plainBuf)
		if n == 0 {
			e.done = true
			return 0, io.EOF
		}
		if _, err := rand.Read(e.nonce[:]); err != nil {
			return 0, fmt.Errorf("rand nonce: %w", err)
		}
		copy(e.pendingBuf[:gcmNonceSize], e.nonce[:])
		// Seal appends ciphertext+tag into pendingBuf[gcmNonceSize:], reusing the allocation.
		sealed := e.gcm.Seal(e.pendingBuf[gcmNonceSize:gcmNonceSize], e.nonce[:], e.plainBuf[:n], nil)
		e.pending = e.pendingBuf[:gcmNonceSize+len(sealed)]
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			e.done = true
		} else if readErr != nil {
			return 0, fmt.Errorf("read plaintext: %w", readErr)
		}
	}
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
