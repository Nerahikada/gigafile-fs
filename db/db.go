package db

import (
	"database/sql"
	"time"

	_ "modernc.org/sqlite"
)

// Object represents a stored S3 object backed by gigafile.nu
type Object struct {
	Bucket         string
	Key            string
	GigafileURL    string
	FileID         string
	GigafileDomain string
	DelKey         string // deletion key from upload response; see gigafile.Client.DeleteFile
	UploadTime     time.Time
	ExpiryTime     time.Time
	Size           int64
	ContentType    string
	ETag           string
	DeletedAt      *time.Time
}

// DB wraps sqlite connection
type DB struct {
	conn *sql.DB
}

// Open opens (or creates) the SQLite database at the given path
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(1) // sqlite doesn't support concurrent writes
	d := &DB{conn: conn}
	if err := d.migrate(); err != nil {
		conn.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) migrate() error {
	_, err := d.conn.Exec(`
		CREATE TABLE IF NOT EXISTS objects (
			bucket          TEXT NOT NULL,
			key             TEXT NOT NULL,
			gigafile_url    TEXT NOT NULL,
			file_id         TEXT NOT NULL,
			gigafile_domain TEXT NOT NULL,
			del_key         TEXT NOT NULL DEFAULT '',
			upload_time     INTEGER NOT NULL,
			expiry_time     INTEGER NOT NULL,
			size            INTEGER NOT NULL,
			content_type    TEXT NOT NULL DEFAULT '',
			etag            TEXT NOT NULL DEFAULT '',
			deleted_at      INTEGER,
			PRIMARY KEY (bucket, key)
		);
		CREATE INDEX IF NOT EXISTS idx_expiry ON objects (expiry_time) WHERE deleted_at IS NULL;
	`)
	return err
}

// Close closes the database connection
func (d *DB) Close() error {
	return d.conn.Close()
}

// Put inserts or replaces an object record
func (d *DB) Put(obj Object) error {
	_, err := d.conn.Exec(`
		INSERT OR REPLACE INTO objects
			(bucket, key, gigafile_url, file_id, gigafile_domain, del_key,
			 upload_time, expiry_time, size, content_type, etag, deleted_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		obj.Bucket, obj.Key, obj.GigafileURL, obj.FileID, obj.GigafileDomain, obj.DelKey,
		obj.UploadTime.Unix(), obj.ExpiryTime.Unix(),
		obj.Size, obj.ContentType, obj.ETag,
	)
	return err
}

// Get retrieves a non-deleted object by bucket+key
func (d *DB) Get(bucket, key string) (*Object, error) {
	row := d.conn.QueryRow(`
		SELECT bucket, key, gigafile_url, file_id, gigafile_domain, del_key,
		       upload_time, expiry_time, size, content_type, etag
		FROM objects
		WHERE bucket = ? AND key = ? AND deleted_at IS NULL`,
		bucket, key,
	)
	return scanObject(row)
}

// SoftDelete marks an object as deleted
func (d *DB) SoftDelete(bucket, key string) error {
	_, err := d.conn.Exec(
		`UPDATE objects SET deleted_at = ? WHERE bucket = ? AND key = ? AND deleted_at IS NULL`,
		time.Now().Unix(), bucket, key,
	)
	return err
}

// List returns all non-deleted objects in a bucket with key >= prefix
func (d *DB) List(bucket, prefix string) ([]Object, error) {
	rows, err := d.conn.Query(`
		SELECT bucket, key, gigafile_url, file_id, gigafile_domain, del_key,
		       upload_time, expiry_time, size, content_type, etag
		FROM objects
		WHERE bucket = ? AND key LIKE ? AND deleted_at IS NULL
		ORDER BY key`,
		bucket, prefix+"%",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var objects []Object
	for rows.Next() {
		obj, err := scanObject(rows)
		if err != nil {
			return nil, err
		}
		objects = append(objects, *obj)
	}
	return objects, rows.Err()
}

// ListExpiringSoon returns non-deleted objects expiring within the given duration
func (d *DB) ListExpiringSoon(within time.Duration) ([]Object, error) {
	threshold := time.Now().Add(within).Unix()
	rows, err := d.conn.Query(`
		SELECT bucket, key, gigafile_url, file_id, gigafile_domain, del_key,
		       upload_time, expiry_time, size, content_type, etag
		FROM objects
		WHERE deleted_at IS NULL AND expiry_time <= ?
		ORDER BY expiry_time`,
		threshold,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var objects []Object
	for rows.Next() {
		obj, err := scanObject(rows)
		if err != nil {
			return nil, err
		}
		objects = append(objects, *obj)
	}
	return objects, rows.Err()
}

type scanner interface {
	Scan(dest ...any) error
}

func scanObject(s scanner) (*Object, error) {
	var obj Object
	var uploadUnix, expiryUnix int64
	err := s.Scan(
		&obj.Bucket, &obj.Key,
		&obj.GigafileURL, &obj.FileID, &obj.GigafileDomain, &obj.DelKey,
		&uploadUnix, &expiryUnix,
		&obj.Size, &obj.ContentType, &obj.ETag,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	obj.UploadTime = time.Unix(uploadUnix, 0)
	obj.ExpiryTime = time.Unix(expiryUnix, 0)
	return &obj, nil
}
