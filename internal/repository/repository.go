package repository

import (
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"

	"github.com/GTDGit/gtd_files_qris/internal/models"
)

// Repository provides token-scoped read access plus PDP audit logging for the
// portal. It deliberately exposes no listing/enumeration: callers must present
// a valid UUID token.
type Repository struct {
	db *sqlx.DB
}

func New(db *sqlx.DB) *Repository {
	return &Repository{db: db}
}

const bundleCols = `id, token, merchant_name, status, note, confirmed_at, expires_at, created_at`
const fileCols = `id, bundle_id, token, doc_type, file_name, content_type, size_bytes, storage_key, created_at`

func scanBundle(s interface{ Scan(...any) error }, b *models.Bundle) error {
	return s.Scan(&b.ID, &b.Token, &b.MerchantName, &b.Status, &b.Note,
		&b.ConfirmedAt, &b.ExpiresAt, &b.CreatedAt)
}

func scanFile(s interface{ Scan(...any) error }, f *models.File) error {
	return s.Scan(&f.ID, &f.BundleID, &f.Token, &f.DocType, &f.FileName,
		&f.ContentType, &f.SizeBytes, &f.StorageKey, &f.CreatedAt)
}

// GetBundleByToken returns a bundle by its link token, or sql.ErrNoRows.
func (r *Repository) GetBundleByToken(ctx context.Context, token string) (*models.Bundle, error) {
	row := r.db.QueryRowxContext(ctx,
		`SELECT `+bundleCols+` FROM qris_doc_bundles WHERE token = $1 LIMIT 1`, token)
	var b models.Bundle
	if err := scanBundle(row, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// ListFiles returns a bundle's files, oldest first.
func (r *Repository) ListFiles(ctx context.Context, bundleID int) ([]models.File, error) {
	rows, err := r.db.QueryxContext(ctx,
		`SELECT `+fileCols+` FROM qris_doc_files WHERE bundle_id = $1 ORDER BY created_at`, bundleID)
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
		`SELECT `+fileCols+` FROM qris_doc_files WHERE token = $1 LIMIT 1`, token)
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
		`SELECT `+bundleCols+` FROM qris_doc_bundles WHERE id = $1 LIMIT 1`, id)
	var b models.Bundle
	if err := scanBundle(row, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// RevokeBundle flips a bundle to revoked and stamps confirmed_at (idempotent).
func (r *Repository) RevokeBundle(ctx context.Context, id int) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE qris_doc_bundles
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

// LogAccess appends a PDP audit row. action is view|download|confirm|forbidden.
func (r *Repository) LogAccess(ctx context.Context, bundleID, fileID *int, action, ip, userAgent, detail string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO qris_doc_access_logs (bundle_id, file_id, action, ip, user_agent, detail)
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
