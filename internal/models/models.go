package models

import "time"

// Mirror of the shared qris_doc_* tables (migration 000065). The portal is a
// separate module and cannot import the gateway's internal packages, so the
// row types it needs are defined locally.

type DocStatus string

const (
	StatusActive  DocStatus = "active"
	StatusRevoked DocStatus = "revoked"
)

type DocType string

const (
	DocTypeKTP              DocType = "ktp"
	DocTypeSelfieKTP        DocType = "selfie_ktp"
	DocTypeBusinessLocation DocType = "business_location"
	DocTypeExtra            DocType = "extra"
)

// Label returns a human-readable Indonesian label for a doc type.
func (d DocType) Label() string {
	switch d {
	case DocTypeKTP:
		return "KTP"
	case DocTypeSelfieKTP:
		return "Foto Diri dengan KTP"
	case DocTypeBusinessLocation:
		return "Foto Lokasi Usaha"
	case DocTypeExtra:
		return "Foto Tambahan"
	default:
		return string(d)
	}
}

type Bundle struct {
	ID           int        `db:"id"`
	Token        string     `db:"token"`
	MerchantName string     `db:"merchant_name"`
	Status       DocStatus  `db:"status"`
	Note         *string    `db:"note"`
	ConfirmedAt  *time.Time `db:"confirmed_at"`
	ExpiresAt    *time.Time `db:"expires_at"`
	CreatedAt    time.Time  `db:"created_at"`
}

type File struct {
	ID          int       `db:"id"`
	BundleID    int       `db:"bundle_id"`
	Token       string    `db:"token"`
	DocType     DocType   `db:"doc_type"`
	FileName    string    `db:"file_name"`
	ContentType string    `db:"content_type"`
	SizeBytes   int64     `db:"size_bytes"`
	StorageKey  string    `db:"storage_key"`
	CreatedAt   time.Time `db:"created_at"`
}
