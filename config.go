package main

import (
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
}

func loadConfig() Config {
	return Config{
		Listen:        envOr("GIGAFILE_LISTEN", "0.0.0.0:9000"),
		AccessKey:     envOr("GIGAFILE_ACCESS_KEY", "gigafile"),
		SecretKey:     envOr("GIGAFILE_SECRET_KEY", "gigafile_secret"),
		DBPath:        envOr("GIGAFILE_DB_PATH", "gigafile.db"),
		TempDir:       envOr("GIGAFILE_TEMP_DIR", os.TempDir()),
		DefaultBucket: os.Getenv("GIGAFILE_BUCKET"),
		RenewalWindow: 14 * 24 * time.Hour,
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
