package main

import (
	"crypto/sha256"
	"os"
	"time"
)

type Config struct {
	Listen    string
	AccessKey string
	SecretKey string
	DBPath    string
	TempDir   string
	// Bucket to auto-create on startup (optional)
	DefaultBucket string
	// How far in advance to renew files (default 14 days)
	RenewalWindow time.Duration
	// EncryptionKey is a 32-byte AES-256 key derived from GIGAFILE_ENCRYPTION_KEY.
	// Nil means encryption is disabled.
	EncryptionKey []byte
}

func loadConfig() Config {
	cfg := Config{
		Listen:        envOr("GIGAFILE_LISTEN", "0.0.0.0:9000"),
		AccessKey:     envOr("GIGAFILE_ACCESS_KEY", "gigafile"),
		SecretKey:     envOr("GIGAFILE_SECRET_KEY", "gigafile_secret"),
		DBPath:        envOr("GIGAFILE_DB_PATH", "gigafile.db"),
		TempDir:       envOr("GIGAFILE_TEMP_DIR", os.TempDir()),
		DefaultBucket: os.Getenv("GIGAFILE_BUCKET"),
		RenewalWindow: 14 * 24 * time.Hour,
	}
	if passphrase := os.Getenv("GIGAFILE_ENCRYPTION_KEY"); passphrase != "" {
		key := sha256.Sum256([]byte(passphrase))
		cfg.EncryptionKey = key[:]
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
