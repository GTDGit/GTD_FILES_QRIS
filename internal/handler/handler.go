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
	"encoding/base64"
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

// uploadMeta is the bundle-level metadata parsed from an upload request.
type uploadMeta struct {
	title      string
	note       *string
	docName    *string
	accessMode models.AccessMode
}

// uploadFile is one decoded file ready to be validated and stored. fileName is
// a best-effort hint from the client (used only to preserve an extension); the
// content type is always re-detected from the bytes.
type uploadFile struct {
	fileName string
	data     []byte
}

// jsonUploadReq is the application/json (base64) upload shape.
type jsonUploadReq struct {
	Title      string `json:"title"`
	Note       string `json:"note"`
	DocName    string `json:"docName"`
	AccessMode string `json:"accessMode"`
	Files      []struct {
		FileName   string `json:"fileName"`
		DataBase64 string `json:"dataBase64"`
	} `json:"files"`
}

// Upload handles POST /api/upload — open, no auth. Accepts EITHER multipart
// form-data (field "files") OR application/json with base64-encoded files. In
// both cases bundle metadata is optional ("title", "note", "docName",
// "accessMode": open|once, default open). File name and content type are
// detected server-side, never trusted from the client.
func (p *Portal) Upload(c *gin.Context) {
	// Cap the whole request body to maxBytes * a small fanout for multi-file.
	// base64 inflates ~33%, so allow extra headroom for the JSON path.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, p.maxBytes*14+(1<<20))

	var (
		meta  uploadMeta
		files []uploadFile
		perr  *uploadError
	)
	switch {
	case strings.HasPrefix(c.ContentType(), "application/json"):
		meta, files, perr = p.parseJSONUpload(c)
	case strings.HasPrefix(c.ContentType(), "multipart/form-data"):
		meta, files, perr = p.parseMultipartUpload(c)
	default:
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"code": "UNSUPPORTED_MEDIA_TYPE", "message": "use multipart/form-data or application/json (base64)"})
		return
	}
	if perr != nil {
		c.JSON(perr.status, gin.H{"code": perr.code, "message": perr.message})
		return
	}
	if len(files) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"code": "NO_FILES", "message": "at least one file is required"})
		return
	}

	p.processUpload(c, meta, files)
}

// uploadError carries an HTTP status + API error code for the upload handler.
type uploadError struct {
	status  int
	code    string
	message string
}

func (p *Portal) parseMultipartUpload(c *gin.Context) (uploadMeta, []uploadFile, *uploadError) {
	if err := c.Request.ParseMultipartForm(p.maxBytes); err != nil {
		return uploadMeta{}, nil, &uploadError{http.StatusBadRequest, "INVALID_FORM", "could not parse upload form"}
	}
	form := c.Request.MultipartForm
	if form == nil {
		return uploadMeta{}, nil, &uploadError{http.StatusBadRequest, "INVALID_FORM", "could not parse upload form"}
	}
	meta := metaFrom(c.PostForm("title"), c.PostForm("note"), c.PostForm("docName"), c.PostForm("accessMode"))

	var files []uploadFile
	for _, fh := range form.File["files"] {
		if fh.Size > p.maxBytes {
			return meta, nil, &uploadError{http.StatusRequestEntityTooLarge, "FILE_TOO_LARGE",
				fmt.Sprintf("%s exceeds the %d MB limit", fh.Filename, p.maxBytes/(1024*1024))}
		}
		src, oerr := fh.Open()
		if oerr != nil {
			return meta, nil, &uploadError{http.StatusBadRequest, "READ_ERROR", "could not read uploaded file"}
		}
		data, rerr := io.ReadAll(src)
		src.Close()
		if rerr != nil {
			return meta, nil, &uploadError{http.StatusBadRequest, "READ_ERROR", "could not read uploaded file"}
		}
		files = append(files, uploadFile{fileName: fh.Filename, data: data})
	}
	return meta, files, nil
}

func (p *Portal) parseJSONUpload(c *gin.Context) (uploadMeta, []uploadFile, *uploadError) {
	var req jsonUploadReq
	if err := c.ShouldBindJSON(&req); err != nil {
		return uploadMeta{}, nil, &uploadError{http.StatusBadRequest, "INVALID_JSON", "invalid JSON body"}
	}
	meta := metaFrom(req.Title, req.Note, req.DocName, req.AccessMode)

	var files []uploadFile
	for _, f := range req.Files {
		data, derr := decodeBase64(f.DataBase64)
		if derr != nil {
			return meta, nil, &uploadError{http.StatusBadRequest, "INVALID_BASE64",
				fmt.Sprintf("invalid base64 for %q", f.FileName)}
		}
		if int64(len(data)) > p.maxBytes {
			return meta, nil, &uploadError{http.StatusRequestEntityTooLarge, "FILE_TOO_LARGE",
				fmt.Sprintf("%s exceeds the %d MB limit", f.FileName, p.maxBytes/(1024*1024))}
		}
		files = append(files, uploadFile{fileName: f.FileName, data: data})
	}
	return meta, files, nil
}

// processUpload validates each decoded file, stores it privately, records the
// rows, and writes the JSON response.
func (p *Portal) processUpload(c *gin.Context, meta uploadMeta, files []uploadFile) {
	ctx := c.Request.Context()

	bundle, err := p.repo.CreateBundle(ctx, &models.Bundle{
		Token:      newToken(),
		Title:      meta.title,
		Note:       meta.note,
		AccessMode: meta.accessMode,
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
	var storedKeys []string

	for _, uf := range files {
		if len(uf.data) == 0 {
			p.cleanup(ctx, storedKeys)
			c.JSON(http.StatusBadRequest, gin.H{"code": "EMPTY_FILE", "message": fmt.Sprintf("%q is empty", uf.fileName)})
			return
		}

		// Auto-detect content type from the bytes; never trust the client header.
		ct := http.DetectContentType(uf.data)
		ct = strings.SplitN(ct, ";", 2)[0]
		if !allowedContentTypes[ct] {
			p.cleanup(ctx, storedKeys)
			c.JSON(http.StatusUnsupportedMediaType, gin.H{
				"code":    "UNSUPPORTED_TYPE",
				"message": fmt.Sprintf("file type %q is not allowed", ct),
			})
			return
		}

		fileName := sanitizeFileName(uf.fileName, ct)
		sum := sha256.Sum256(uf.data)
		checksum := hex.EncodeToString(sum[:])
		fileToken := newToken()
		key := p.keyPrefix + bundle.Token + "/" + fileToken + extForType(ct, fileName)

		if perr := p.store.Put(ctx, key, ct, uf.data); perr != nil {
			log.Error().Err(perr).Str("key", key).Msg("storage put failed")
			p.cleanup(ctx, storedKeys)
			c.JSON(http.StatusBadGateway, gin.H{"code": "STORAGE_ERROR", "message": "could not store file"})
			return
		}
		storedKeys = append(storedKeys, key)

		f, ferr := p.repo.CreateFile(ctx, &models.File{
			BundleID:    bundle.ID,
			Token:       fileToken,
			DocName:     meta.docName,
			FileName:    fileName,
			ContentType: ct,
			SizeBytes:   int64(len(uf.data)),
			StorageKey:  key,
			Checksum:    &checksum,
		})
		if ferr != nil {
			log.Error().Err(ferr).Msg("create file row failed")
			p.cleanup(ctx, storedKeys)
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

// cleanup best-effort deletes objects stored before a mid-batch failure.
func (p *Portal) cleanup(ctx context.Context, keys []string) {
	for _, k := range keys {
		_ = p.store.Delete(ctx, k)
	}
}

// metaFrom normalizes bundle-level fields from any upload source.
func metaFrom(title, note, docName, accessMode string) uploadMeta {
	m := uploadMeta{accessMode: models.AccessOpen}
	if m.title = strings.TrimSpace(title); m.title == "" {
		m.title = "Untitled"
	}
	if strings.EqualFold(accessMode, string(models.AccessOnce)) {
		m.accessMode = models.AccessOnce
	}
	if n := strings.TrimSpace(note); n != "" {
		m.note = &n
	}
	if d := strings.TrimSpace(docName); d != "" {
		m.docName = &d
	}
	return m
}

// decodeBase64 accepts a raw base64 string or a data: URI
// (data:<ct>;base64,<payload>).
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ";base64,"); i != -1 {
		s = s[i+len(";base64,"):]
	} else if strings.HasPrefix(s, "data:") {
		if i := strings.Index(s, ","); i != -1 {
			s = s[i+1:]
		}
	}
	return base64.StdEncoding.DecodeString(s)
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
