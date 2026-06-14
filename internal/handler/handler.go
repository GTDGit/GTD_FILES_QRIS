// Package handler implements the public, token-gated QRIS document portal.
//
// Security model:
//   - Every route requires an unguessable UUIDv4 token in the path. No listing,
//     no enumeration. An unknown/missing token returns 403 Forbidden.
//   - A bundle that is revoked (Nobu confirmed, or admin force-closed) or past
//     its expiry returns 403 — files are never served again.
//   - Files live in private S3 and are only ever streamed through these
//     handlers after the token + bundle state are validated. No public URL.
//   - Every access (view/download/confirm) and every rejection (forbidden) is
//     written to the PDP audit log.
package handler

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"html/template"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"github.com/GTDGit/gtd_files_qris/internal/models"
	"github.com/GTDGit/gtd_files_qris/internal/repository"
	"github.com/GTDGit/gtd_files_qris/internal/storage"
)

//go:embed templates/*.html
var templatesFS embed.FS

// Portal handles all public portal routes.
type Portal struct {
	repo  *repository.Repository
	store storage.Storage
	tmpl  *template.Template
}

// NewPortal parses embedded templates and constructs the portal handler.
func NewPortal(repo *repository.Repository, store storage.Storage) (*Portal, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Portal{repo: repo, store: store, tmpl: tmpl}, nil
}

// fileView is the per-file shape passed to the bundle template.
type fileView struct {
	Token     string
	DocType   string
	Label     string
	FileName  string
	IsImage   bool
}

// bundlePageData feeds the bundle template.
type bundlePageData struct {
	MerchantName string
	Token        string
	Note         string
	Files        []fileView
	CreatedAt    string
}

// ViewBundle handles GET /b/:token — the merchant document page.
func (p *Portal) ViewBundle(c *gin.Context) {
	token := c.Param("token")
	bundle, err := p.loadAccessibleBundle(c, token, nil)
	if err != nil {
		p.forbidden(c)
		return
	}

	files, ferr := p.repo.ListFiles(c.Request.Context(), bundle.ID)
	if ferr != nil {
		log.Error().Err(ferr).Int("bundle", bundle.ID).Msg("list files failed")
		c.String(http.StatusInternalServerError, "internal error")
		return
	}

	views := make([]fileView, 0, len(files))
	for _, f := range files {
		views = append(views, fileView{
			Token:    f.Token,
			DocType:  string(f.DocType),
			Label:    f.DocType.Label(),
			FileName: f.FileName,
			IsImage:  isImage(f.ContentType),
		})
	}

	note := ""
	if bundle.Note != nil {
		note = *bundle.Note
	}

	p.logAccess(c, &bundle.ID, nil, "view", "")
	c.Status(http.StatusOK)
	if err := p.tmpl.ExecuteTemplate(c.Writer, "bundle.html", bundlePageData{
		MerchantName: bundle.MerchantName,
		Token:        bundle.Token,
		Note:         note,
		Files:        views,
		CreatedAt:    bundle.CreatedAt.In(wib()).Format("02 Jan 2006 15:04 WIB"),
	}); err != nil {
		log.Error().Err(err).Msg("render bundle page")
	}
}

// ViewFile handles GET /f/:token — streams a file inline (for <img>/preview).
func (p *Portal) ViewFile(c *gin.Context) {
	p.serveFile(c, false)
}

// DownloadFile handles GET /f/:token/download — streams as an attachment.
func (p *Portal) DownloadFile(c *gin.Context) {
	p.serveFile(c, true)
}

func (p *Portal) serveFile(c *gin.Context, asAttachment bool) {
	token := c.Param("token")
	file, bundle, err := p.repo.GetFileByToken(c.Request.Context(), token)
	if err != nil {
		p.logForbidden(c, nil, nil, reason(err))
		p.forbidden(c)
		return
	}
	if !bundleAccessible(bundle) {
		p.logForbidden(c, &bundle.ID, &file.ID, "revoked_or_expired")
		p.forbidden(c)
		return
	}

	data, ct, gerr := p.store.Get(c.Request.Context(), file.StorageKey)
	if gerr != nil {
		log.Error().Err(gerr).Str("key", file.StorageKey).Msg("storage get failed")
		c.String(http.StatusBadGateway, "file unavailable")
		return
	}
	if ct == "" {
		ct = file.ContentType
	}

	action := "view"
	if asAttachment {
		action = "download"
		c.Header("Content-Disposition", "attachment; filename=\""+file.FileName+"\"")
	}
	// Sensitive documents: never cache on disk by intermediaries/browser.
	c.Header("Cache-Control", "no-store, private")
	p.logAccess(c, &bundle.ID, &file.ID, action, "")
	c.Data(http.StatusOK, ct, data)
}

// Confirm handles POST /b/:token/confirm — Nobu confirms they've downloaded.
// This revokes the bundle so every subsequent access returns 403.
func (p *Portal) Confirm(c *gin.Context) {
	token := c.Param("token")
	bundle, err := p.repo.GetBundleByToken(c.Request.Context(), token)
	if err != nil {
		p.logForbidden(c, nil, nil, reason(err))
		p.forbidden(c)
		return
	}
	// If already revoked, treat confirm as idempotent success.
	if bundle.Status != models.StatusRevoked {
		if rerr := p.repo.RevokeBundle(c.Request.Context(), bundle.ID); rerr != nil {
			log.Error().Err(rerr).Int("bundle", bundle.ID).Msg("revoke failed")
			c.String(http.StatusInternalServerError, "internal error")
			return
		}
	}
	p.logAccess(c, &bundle.ID, nil, "confirm", "")

	c.Status(http.StatusOK)
	if err := p.tmpl.ExecuteTemplate(c.Writer, "confirmed.html", gin.H{
		"MerchantName": bundle.MerchantName,
	}); err != nil {
		log.Error().Err(err).Msg("render confirmed page")
	}
}

// loadAccessibleBundle fetches a bundle by token and enforces access. On any
// failure it logs a forbidden audit row and returns an error.
func (p *Portal) loadAccessibleBundle(c *gin.Context, token string, fileID *int) (*models.Bundle, error) {
	bundle, err := p.repo.GetBundleByToken(c.Request.Context(), token)
	if err != nil {
		p.logForbidden(c, nil, fileID, reason(err))
		return nil, err
	}
	if !bundleAccessible(bundle) {
		p.logForbidden(c, &bundle.ID, fileID, "revoked_or_expired")
		return nil, errors.New("forbidden")
	}
	return bundle, nil
}

// forbidden renders the 403 page.
func (p *Portal) forbidden(c *gin.Context) {
	c.Status(http.StatusForbidden)
	_ = p.tmpl.ExecuteTemplate(c.Writer, "forbidden.html", nil)
}

// Forbidden is the public 403 handler for the bare root path (no enumeration).
func (p *Portal) Forbidden(c *gin.Context) {
	p.forbidden(c)
}

func (p *Portal) logAccess(c *gin.Context, bundleID, fileID *int, action, detail string) {
	// Audit logging must never block the user action; log-and-continue.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := p.repo.LogAccess(ctx, bundleID, fileID, action, c.ClientIP(), c.Request.UserAgent(), detail); err != nil {
		log.Warn().Err(err).Str("action", action).Msg("audit log failed")
	}
}

func (p *Portal) logForbidden(c *gin.Context, bundleID, fileID *int, detail string) {
	p.logAccess(c, bundleID, fileID, "forbidden", detail)
}

// bundleAccessible reports whether a bundle may still be viewed.
func bundleAccessible(b *models.Bundle) bool {
	if b.Status == models.StatusRevoked {
		return false
	}
	if b.ExpiresAt != nil && time.Now().After(*b.ExpiresAt) {
		return false
	}
	return true
}

func reason(err error) string {
	if errors.Is(err, sql.ErrNoRows) {
		return "unknown_token"
	}
	return "lookup_error"
}

func isImage(ct string) bool {
	switch ct {
	case "image/jpeg", "image/jpg", "image/png", "image/webp", "image/gif", "image/heic", "image/heif":
		return true
	default:
		return false
	}
}

func wib() *time.Location {
	return time.FixedZone("WIB", 7*3600)
}
