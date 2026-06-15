package models

import "time"

// Generic file-delivery portal model. A "bundle" is one shareable, token-gated
// link holding N files. Upload happens at the portal itself (POST /api/upload);
// files live in private S3 and are only ever streamed through token-validated
// handlers — never via a public URL.

type Status string

const (
	StatusActive  Status = "active"
	StatusRevoked Status = "revoked"
)

// AccessMode controls link lifetime.
//   - open: the link can be opened/downloaded freely until manual revoke/expiry.
//   - once: the link is consumed (revoked) after the first file download.
type AccessMode string

const (
	AccessOpen AccessMode = "open"
	AccessOnce AccessMode = "once"
)

// Bundle is one shareable link.
type Bundle struct {
	ID          int        `db:"id"`
	Token       string     `db:"token"`
	Title       string     `db:"title"`
	Note        *string    `db:"note"`
	AccessMode  AccessMode `db:"access_mode"`
	Status      Status     `db:"status"`
	CreatedBy   *string    `db:"created_by"`
	ConfirmedAt *time.Time `db:"confirmed_at"`
	ExpiresAt   *time.Time `db:"expires_at"`
	CreatedAt   time.Time  `db:"created_at"`
	UpdatedAt   time.Time  `db:"updated_at"`
}

// File is one stored file within a bundle.
type File struct {
	ID          int       `db:"id"`
	BundleID    int       `db:"bundle_id"`
	Token       string    `db:"token"`
	DocName     *string   `db:"doc_name"` // optional human label, e.g. "KTP Pemilik"
	FileName    string    `db:"file_name"`
	ContentType string    `db:"content_type"`
	SizeBytes   int64     `db:"size_bytes"`
	StorageKey  string    `db:"storage_key"`
	Checksum    *string   `db:"checksum"`
	CreatedAt   time.Time `db:"created_at"`
}
