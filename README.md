# gigafile-fs

An S3-compatible proxy that uses [gigafile.nu](https://gigafile.nu/) as its storage backend.
Translates AWS S3 API calls into gigafile.nu HTTP API requests and persists metadata in SQLite.

> **Not for public exposure.** Designed to run inside a closed network (Docker `internal` network or `127.0.0.1` binding).
> HMAC signature verification is intentionally not implemented; network isolation is the primary security boundary.

## Features

- PutObject, GetObject, HeadObject, DeleteObject, ListBucket, Multipart Upload
- 100 MB chunked upload; Range request forwarding
- AES-256-GCM client-side encryption (optional)
- Files auto-renewed 14 days before the 100-day gigafile.nu expiry

## Build

```bash
go build -o gigafile-fs .
# or with Docker
docker build -t gigafile-fs .
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `GIGAFILE_LISTEN` | `0.0.0.0:9000` | Listen address |
| `GIGAFILE_ACCESS_KEY` | `gigafile` | S3 access key ID |
| `GIGAFILE_SECRET_KEY` | `gigafile_secret` | S3 secret key (checked for presence, not verified) |
| `GIGAFILE_DB_PATH` | `gigafile.db` | SQLite database path |
| `GIGAFILE_TEMP_DIR` | `/tmp` | Temporary directory for multipart parts |
| `GIGAFILE_BUCKET` | *(empty)* | Bucket to create automatically on startup |
| `GIGAFILE_ENCRYPTION_KEY` | *(empty)* | Passphrase for AES-256-GCM client-side encryption (SHA-256 stretched to 32 bytes); disabled if unset |

## Known limitations

gigafile.nu's deletion key (`delkey`) is only 4 characters. Anyone who knows a file URL can brute-force the deletion key in seconds. Auto-renewal does not protect against this.
