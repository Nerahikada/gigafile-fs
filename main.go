package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/johannesboyne/gofakes3"
	"github.com/Nerahikada/gigafile-fs/backend"
	"github.com/Nerahikada/gigafile-fs/db"
)

func main() {
	cfg := loadConfig()

	if err := os.MkdirAll(cfg.TempDir, 0o755); err != nil {
		log.Fatalf("create temp dir: %v", err)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()

	be := backend.New(database, cfg.TempDir)

	// Ensure the default bucket exists on startup
	if cfg.DefaultBucket != "" {
		be.EnsureBucket(cfg.DefaultBucket)
		log.Printf("bucket %q ready", cfg.DefaultBucket)
	}

	// Auto-renewal goroutine: re-upload files expiring within RenewalWindow
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		// Run once immediately on startup
		log.Println("renewal: checking for files expiring soon...")
		be.RenewExpiring(cfg.RenewalWindow)
		for range ticker.C {
			log.Println("renewal: checking for files expiring soon...")
			be.RenewExpiring(cfg.RenewalWindow)
		}
	}()

	faker := gofakes3.New(be,
		gofakes3.WithAutoBucket(true),
	)

	log.Printf("gigafile-s3 listening on %s", cfg.Listen)
	log.Printf("  access key : %s", cfg.AccessKey)
	log.Printf("  db path    : %s", cfg.DBPath)
	log.Printf("  temp dir   : %s", cfg.TempDir)
	log.Printf("  renewal    : %s before expiry", cfg.RenewalWindow)

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: withAuth(cfg, faker.Server()),
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// withAuth wraps an http.Handler with simple AWS Signature V4 key/secret validation.
// It only checks the access key ID present in the Authorization header.
// For production use, implement full SigV4 verification.
func withAuth(cfg Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.AccessKey != "" {
			auth := r.Header.Get("Authorization")
			query := r.URL.Query()
			keyFromQuery := query.Get("X-Amz-Credential")

			keyPresent := false
			if auth != "" {
				keyPresent = containsAccessKey(auth, cfg.AccessKey)
			} else if keyFromQuery != "" {
				// presigned URL: Credential=KEY/...
				keyPresent = len(keyFromQuery) >= len(cfg.AccessKey) &&
					keyFromQuery[:len(cfg.AccessKey)] == cfg.AccessKey
			} else {
				// No auth header - allow anonymous for health checks
				keyPresent = true
			}

			if !keyPresent {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// containsAccessKey checks whether the Authorization header contains our access key.
func containsAccessKey(authHeader, accessKey string) bool {
	// AWS SigV4 Authorization header contains: Credential=ACCESSKEY/...
	const prefix = "Credential="
	idx := 0
	for i := 0; i+len(prefix) < len(authHeader); i++ {
		if authHeader[i:i+len(prefix)] == prefix {
			idx = i + len(prefix)
			break
		}
	}
	if idx == 0 {
		return false
	}
	rest := authHeader[idx:]
	if len(rest) < len(accessKey) {
		return false
	}
	return rest[:len(accessKey)] == accessKey
}
