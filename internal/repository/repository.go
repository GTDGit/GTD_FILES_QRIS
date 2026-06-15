package repository

import (
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"

	"github.com/GTDGit/gtd_files_qris/internal/models"
)

// Repository provides token-scoped access plus PDP audit logging for the
// portal. Read paths deliberately expose no listing/enumeration: callers must
// present a valid UUID token. The portal owns and bootstraps its own schema.
type Repository struct {
	db *sqlx.DB
}

func New(db *sqlx.DB) *Repository {
	return &Repository{db: db}
}

// schemaDDL is applied on startup. The portal is a standalone product and owns
// its own tables; it no longer depends on the api/migrations pipeline.
const schemaDDL = `
CREATE TABLE IF NOT EXISTS file_bundles (
	id           SERIAL PRIMARY KEY,
	token        TEXT NOT NULL UNIQUE,
	title        TEXT NOT NULL DEFAULT '',
	note         TEXT,
	once_note    TEXT,
	access_mode  TEXT NOT NULL DEFAULT 'open',
	status       TEXT NOT NULL DEFAULT 'active',
	created_by   TEXT,
	confirmed_at TIMESTAMPTZ,
	expires_at   TIMESTAMPTZ,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Backfill column on pre-existing deployments (CREATE TABLE IF NOT EXISTS is a no-op there).
ALTER TABLE file_bundles ADD COLUMN IF NOT EXISTS once_note TEXT;

CREATE TABLE IF NOT EXISTS file_items (
	id           SERIAL PRIMARY KEY,
	bundle_id    INTEGER NOT NULL REFERENCES file_bundles(id) ON DELETE CASCADE,
	token        TEXT NOT NULL UNIQUE,
	doc_name     TEXT,
	file_name    TEXT NOT NULL,
	content_type TEXT NOT NULL,
	size_bytes   BIGINT NOT NULL DEFAULT 0,
	storage_key  TEXT NOT NULL,
	checksum     TEXT,
	created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_file_items_bundle ON file_items(bundle_id);

CREATE TABLE IF NOT EXISTS file_access_logs (
	id         SERIAL PRIMARY KEY,
	bundle_id  INTEGER,
	file_id    INTEGER,
	action     TEXT NOT NULL,
	ip         TEXT,
	user_agent TEXT,
	detail     TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`

// EnsureSchema creates the portal's tables if they don't exist (idempotent).
func (r *Repository) EnsureSchema(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, schemaDDL)
	return err
}

const bundleCols = `id, token, title, note, once_note, access_mode, status, created_by, confirmed_at, expires_at, created_at, updated_at`
const fileCols = `id, bundle_id, token, doc_name, file_name, content_type, size_bytes, storage_key, checksum, created_at`

func scanBundle(s interface{ Scan(...any) error }, b *models.Bundle) error {
	return s.Scan(&b.ID, &b.Token, &b.Title, &b.Note, &b.OnceNote, &b.AccessMode, &b.Status,
		&b.CreatedBy, &b.ConfirmedAt, &b.ExpiresAt, &b.CreatedAt, &b.UpdatedAt)
}

func scanFile(s interface{ Scan(...any) error }, f *models.File) error {
	return s.Scan(&f.ID, &f.BundleID, &f.Token, &f.DocName, &f.FileName,
		&f.ContentType, &f.SizeBytes, &f.StorageKey, &f.Checksum, &f.CreatedAt)
}

// CreateBundle inserts a new bundle and returns it (with id/timestamps filled).
func (r *Repository) CreateBundle(ctx context.Context, b *models.Bundle) (*models.Bundle, error) {
	row := r.db.QueryRowxContext(ctx,
		`INSERT INTO file_bundles (token, title, note, once_note, access_mode, status, created_by, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING `+bundleCols,
		b.Token, b.Title, b.Note, b.OnceNote, b.AccessMode, b.Status, b.CreatedBy, b.ExpiresAt)
	var out models.Bundle
	if err := scanBundle(row, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateFile inserts a file row for a bundle and returns it.
func (r *Repository) CreateFile(ctx context.Context, f *models.File) (*models.File, error) {
	row := r.db.QueryRowxContext(ctx,
		`INSERT INTO file_items (bundle_id, token, doc_name, file_name, content_type, size_bytes, storage_key, checksum)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING `+fileCols,
		f.BundleID, f.Token, f.DocName, f.FileName, f.ContentType, f.SizeBytes, f.StorageKey, f.Checksum)
	var out models.File
	if err := scanFile(row, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetBundleByToken returns a bundle by its link token, or sql.ErrNoRows.
func (r *Repository) GetBundleByToken(ctx context.Context, token string) (*models.Bundle, error) {
	row := r.db.QueryRowxContext(ctx,
		`SELECT `+bundleCols+` FROM file_bundles WHERE token = $1 LIMIT 1`, token)
	var b models.Bundle
	if err := scanBundle(row, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// ListFiles returns a bundle's files, oldest first.
func (r *Repository) ListFiles(ctx context.Context, bundleID int) ([]models.File, error) {
	rows, err := r.db.QueryxContext(ctx,
		`SELECT `+fileCols+` FROM file_items WHERE bundle_id = $1 ORDER BY created_at`, bundleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var files []models.File
	for rows.Next() {
		var f models.File
		if err := scanFile(rows, &f); err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

// GetFileByToken returns a single file plus its parent bundle by the file
// token, so the handler can enforce the bundle's revoked/expired state in one
// query.
func (r *Repository) GetFileByToken(ctx context.Context, token string) (*models.File, *models.Bundle, error) {
	row := r.db.QueryRowxContext(ctx,
		`SELECT `+fileCols+` FROM file_items WHERE token = $1 LIMIT 1`, token)
	var f models.File
	if err := scanFile(row, &f); err != nil {
		return nil, nil, err
	}
	b, err := r.getBundleByID(ctx, f.BundleID)
	if err != nil {
		return nil, nil, err
	}
	return &f, b, nil
}

func (r *Repository) getBundleByID(ctx context.Context, id int) (*models.Bundle, error) {
	row := r.db.QueryRowxContext(ctx,
		`SELECT `+bundleCols+` FROM file_bundles WHERE id = $1 LIMIT 1`, id)
	var b models.Bundle
	if err := scanBundle(row, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// RevokeBundle flips a bundle to revoked and stamps confirmed_at (idempotent).
func (r *Repository) RevokeBundle(ctx context.Context, id int) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE file_bundles
         SET status = 'revoked', confirmed_at = COALESCE(confirmed_at, now()), updated_at = now()
         WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// LogAccess appends a PDP audit row. action is view|download|confirm|forbidden|upload.
func (r *Repository) LogAccess(ctx context.Context, bundleID, fileID *int, action, ip, userAgent, detail string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO file_access_logs (bundle_id, file_id, action, ip, user_agent, detail)
         VALUES ($1, $2, $3, $4, $5, $6)`,
		bundleID, fileID, action, nullIfEmpty(ip), nullIfEmpty(userAgent), nullIfEmpty(detail))
	return err
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
