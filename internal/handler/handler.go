// Package handler implements the public file-delivery portal.
//
// Security model:
//   - Delivery routes require an unguessable UUIDv4 token in the path. No
//     listing, no enumeration. An unknown/missing token returns 403 Forbidden.
//   - A bundle that is revoked (confirmed, once-mode consumed, or admin-closed)
//     or past its expiry returns 403 — files are never served again.
//   - Files live in private S3 and are only ever streamed through these
//     handlers after the token + bundle state are validated. No public URL.
//   - Every access (view/download/confirm/upload) and every rejection
//     (forbidden) is written to the PDP audit log.
//
// The upload route (POST /api/upload) is intentionally open (no auth) per
// product requirement. It still enforces a size cap and a content-type
// allow-list, and auto-detects file name + content type server-side.
package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"github.com/GTDGit/gtd_files_qris/internal/models"
	"github.com/GTDGit/gtd_files_qris/internal/repository"
	"github.com/GTDGit/gtd_files_qris/internal/storage"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed assets/*
var assetsFS embed.FS

// Portal handles all portal routes.
type Portal struct {
	repo      *repository.Repository
	store     storage.Storage
	tmpl      *template.Template
	baseURL   string // public origin for building links; empty = derive from request
	keyPrefix string // S3 key namespace, e.g. "files/"
	maxBytes  int64
}

// Options configures the portal handler.
type Options struct {
	BaseURL   string
	KeyPrefix string
	MaxBytes  int64
}

// NewPortal parses embedded templates and constructs the portal handler.
func NewPortal(repo *repository.Repository, store storage.Storage, opts Options) (*Portal, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 15 * 1024 * 1024
	}
	return &Portal{
		repo:      repo,
		store:     store,
		tmpl:      tmpl,
		baseURL:   strings.TrimRight(opts.BaseURL, "/"),
		keyPrefix: opts.KeyPrefix,
		maxBytes:  opts.MaxBytes,
	}, nil
}

// allowedContentTypes is the upload allow-list (images + common documents).
var allowedContentTypes = map[string]bool{
	"image/jpeg":      true,
	"image/png":       true,
	"image/webp":      true,
	"image/gif":       true,
	"image/heic":      true,
	"image/heif":      true,
	"application/pdf": true,
	"application/msword": true,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document": true,
	"application/vnd.ms-excel": true,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": true,
	"text/plain": true,
	"text/csv":   true,
}

// fileView is the per-file shape passed to the bundle template.
type fileView struct {
	Token    string
	Label    string
	FileName string
	IsImage  bool
}

// bundlePageData feeds the bundle template.
type bundlePageData struct {
	Title     string
	Token     string
	Note      string
	Files     []fileView
	CreatedAt string
	Once      bool
}

// ShowUpload renders the public upload form at GET /api (and "/").
func (p *Portal) ShowUpload(c *gin.Context) {
	c.Status(http.StatusOK)
	if err := p.tmpl.ExecuteTemplate(c.Writer, "upload.html", gin.H{
		"MaxMB": p.maxBytes / (1024 * 1024),
	}); err != nil {
		log.Error().Err(err).Msg("render upload page")
	}
}

// Asset serves an embedded static asset (logo, favicon) by file name.
func (p *Portal) Asset(c *gin.Context) {
	p.serveAsset(c, path.Base(c.Param("name")))
}

// Favicon serves the GTD logo as the site favicon.
func (p *Portal) Favicon(c *gin.Context) {
	p.serveAsset(c, "logo_gtd.png")
}

func (p *Portal) serveAsset(c *gin.Context, name string) {
	data, err := assetsFS.ReadFile("assets/" + name)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	ct := "application/octet-stream"
	switch strings.ToLower(path.Ext(name)) {
	case ".png":
		ct = "image/png"
	case ".jpg", ".jpeg":
		ct = "image/jpeg"
	case ".svg":
		ct = "image/svg+xml"
	case ".ico":
		ct = "image/x-icon"
	}
	c.Header("Cache-Control", "public, max-age=86400")
	c.Data(http.StatusOK, ct, data)
}

// Upload handles POST /api/upload — open, no auth. Accepts multipart form-data
// with one or more "files", an optional "title", "note", "docName", and
// "accessMode" (open|once, default open). File name and content type are
// detected server-side, never trusted from the client.
func (p *Portal) Upload(c *gin.Context) {
	// Cap the whole request body to maxBytes * a small fanout for multi-file.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, p.maxBytes*10+(1<<20))

	if err := c.Request.ParseMultipartForm(p.maxBytes); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": "INVALID_FORM", "message": "could not parse upload form"})
		return
	}
	form := c.Request.MultipartForm
	if form == nil || len(form.File["files"]) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"code": "NO_FILES", "message": "at least one file is required under field 'files'"})
		return
	}

	title := strings.TrimSpace(c.PostForm("title"))
	if title == "" {
		title = "Untitled"
	}
	accessMode := models.AccessOpen
	if strings.EqualFold(c.PostForm("accessMode"), string(models.AccessOnce)) {
		accessMode = models.AccessOnce
	}
	var notePtr *string
	if n := strings.TrimSpace(c.PostForm("note")); n != "" {
		notePtr = &n
	}
	var docNamePtr *string
	if d := strings.TrimSpace(c.PostForm("docName")); d != "" {
		docNamePtr = &d
	}

	ctx := c.Request.Context()

	bundle, err := p.repo.CreateBundle(ctx, &models.Bundle{
		Token:      newToken(),
		Title:      title,
		Note:       notePtr,
		AccessMode: accessMode,
		Status:     models.StatusActive,
	})
	if err != nil {
		log.Error().Err(err).Msg("create bundle failed")
		c.JSON(http.StatusInternalServerError, gin.H{"code": "DB_ERROR", "message": "could not create bundle"})
		return
	}

	type uploaded struct {
		Token    string `json:"token"`
		FileName string `json:"fileName"`
		ViewURL  string `json:"viewUrl"`
	}
	var results []uploaded

	for _, fh := range form.File["files"] {
		if fh.Size > p.maxBytes {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"code": "FILE_TOO_LARGE",
				"message": fmt.Sprintf("%s exceeds the %d MB limit", fh.Filename, p.maxBytes/(1024*1024)),
			})
			return
		}
		src, oerr := fh.Open()
		if oerr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"code": "READ_ERROR", "message": "could not read uploaded file"})
			return
		}
		data, rerr := io.ReadAll(src)
		src.Close()
		if rerr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"code": "READ_ERROR", "message": "could not read uploaded file"})
			return
		}

		// Auto-detect content type from the bytes; never trust the client header.
		ct := http.DetectContentType(data)
		ct = strings.SplitN(ct, ";", 2)[0]
		if !allowedContentTypes[ct] {
			c.JSON(http.StatusUnsupportedMediaType, gin.H{
				"code": "UNSUPPORTED_TYPE",
				"message": fmt.Sprintf("file type %q is not allowed", ct),
			})
			return
		}

		fileName := sanitizeFileName(fh.Filename, ct)
		sum := sha256.Sum256(data)
		checksum := hex.EncodeToString(sum[:])
		fileToken := newToken()
		key := p.keyPrefix + bundle.Token + "/" + fileToken + extForType(ct, fileName)

		if perr := p.store.Put(ctx, key, ct, data); perr != nil {
			log.Error().Err(perr).Str("key", key).Msg("storage put failed")
			c.JSON(http.StatusBadGateway, gin.H{"code": "STORAGE_ERROR", "message": "could not store file"})
			return
		}

		f, ferr := p.repo.CreateFile(ctx, &models.File{
			BundleID:    bundle.ID,
			Token:       fileToken,
			DocName:     docNamePtr,
			FileName:    fileName,
			ContentType: ct,
			SizeBytes:   int64(len(data)),
			StorageKey:  key,
			Checksum:    &checksum,
		})
		if ferr != nil {
			log.Error().Err(ferr).Msg("create file row failed")
			c.JSON(http.StatusInternalServerError, gin.H{"code": "DB_ERROR", "message": "could not record file"})
			return
		}
		results = append(results, uploaded{
			Token:    f.Token,
			FileName: f.FileName,
			ViewURL:  p.link(c, "/f/"+f.Token),
		})
	}

	p.logAccess(c, &bundle.ID, nil, "upload", fmt.Sprintf("%d file(s)", len(results)))

	c.JSON(http.StatusCreated, gin.H{
		"token":      bundle.Token,
		"title":      bundle.Title,
		"accessMode": bundle.AccessMode,
		"bundleUrl":  p.link(c, "/b/"+bundle.Token),
		"files":      results,
	})
}

// ViewBundle handles GET /b/:token — the document page.
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
		label := f.FileName
		if f.DocName != nil && *f.DocName != "" {
			label = *f.DocName
		}
		views = append(views, fileView{
			Token:    f.Token,
			Label:    label,
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
		Title:     bundle.Title,
		Token:     bundle.Token,
		Note:      note,
		Files:     views,
		CreatedAt: bundle.CreatedAt.In(wib()).Format("02 Jan 2006 15:04 WIB"),
		Once:      bundle.AccessMode == models.AccessOnce,
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

	// once-mode: consume the bundle after the first successful download so every
	// subsequent access returns 403.
	if asAttachment && bundle.AccessMode == models.AccessOnce && bundle.Status != models.StatusRevoked {
		if rerr := p.repo.RevokeBundle(c.Request.Context(), bundle.ID); rerr != nil {
			log.Warn().Err(rerr).Int("bundle", bundle.ID).Msg("once-mode revoke failed")
		} else {
			p.logAccess(c, &bundle.ID, &file.ID, "confirm", "once_consumed")
		}
	}
}

// Confirm handles POST /b/:token/confirm — recipient confirms they've
// downloaded. This revokes the bundle so every subsequent access returns 403.
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
		"Title": bundle.Title,
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

// Forbidden is the public 403 handler for unknown delivery paths.
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

// link builds an absolute URL for a portal path using the configured base URL,
// falling back to the request's scheme+host.
func (p *Portal) link(c *gin.Context, p2 string) string {
	if p.baseURL != "" {
		return p.baseURL + p2
	}
	scheme := "https"
	if c.Request.TLS == nil && c.GetHeader("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	return scheme + "://" + c.Request.Host + p2
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

// sanitizeFileName keeps only the base name and ensures it has an extension
// matching the detected content type.
func sanitizeFileName(name, ct string) string {
	base := path.Base(strings.ReplaceAll(name, "\\", "/"))
	base = strings.TrimSpace(base)
	if base == "" || base == "." || base == "/" {
		base = "file"
	}
	if path.Ext(base) == "" {
		base += extForType(ct, "")
	}
	return base
}

// extForType returns a sensible extension for a content type, preferring the
// existing extension on the provided file name when present.
func extForType(ct, name string) string {
	if name != "" {
		if e := path.Ext(name); e != "" {
			return e
		}
	}
	switch ct {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/webp":
		return ".webp"
	case "image/gif":
		return ".gif"
	case "image/heic", "image/heif":
		return ".heic"
	case "application/pdf":
		return ".pdf"
	case "text/plain":
		return ".txt"
	case "text/csv":
		return ".csv"
	default:
		return ""
	}
}

// newToken returns a random UUIDv4 string without external dependencies.
func newToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is catastrophic; fall back to time-based entropy.
		t := time.Now().UnixNano()
		for i := range 8 {
			b[i] = byte(t >> (8 * i))
		}
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func wib() *time.Location {
	return time.FixedZone("WIB", 7*3600)
}
