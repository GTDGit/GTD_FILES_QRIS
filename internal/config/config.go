// Package config loads runtime configuration for the files-qris portal service.
package config

import (
	"errors"
	"os"
	"strconv"
)

// Config holds all runtime parameters for the file portal.
type Config struct {
	Port string
	Env  string

	// BaseURL is the public origin used to build shareable links, e.g.
	// "https://dev-files.gtd.co.id". When empty, links are built from the
	// incoming request host.
	BaseURL string

	// MaxUploadBytes caps a single uploaded file's size (default 15 MiB).
	MaxUploadBytes int64

	DB      DatabaseConfig
	Storage StorageConfig
}

// DatabaseConfig mirrors the gateway/api DB connection (same shared RDS).
type DatabaseConfig struct {
	Host        string
	Port        string
	User        string
	Password    string
	Name        string
	SSLMode     string
	SSLRootCert string
}

// StorageConfig points at the same private S3 bucket the gateway uploads to.
// The portal only reads (and the retention sweep deletes); it never writes new
// objects and never produces a public URL.
type StorageConfig struct {
	Region    string
	Bucket    string
	Endpoint  string
	AccessKey string
	SecretKey string
	// KeyPrefix namespaces all object keys this portal writes, e.g. "files/".
	KeyPrefix string
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{}

	cfg.Port = getEnv("PORT", "8090")
	cfg.Env = getEnv("ENV", "development")
	cfg.BaseURL = trimTrailingSlash(getEnv("FILES_BASE_URL", ""))
	cfg.MaxUploadBytes = int64(GetEnvInt("FILES_MAX_UPLOAD_MB", 15)) * 1024 * 1024

	cfg.DB = DatabaseConfig{
		Host:        getEnv("DB_HOST", ""),
		Port:        getEnv("DB_PORT", "5432"),
		User:        getEnv("DB_USER", ""),
		Password:    getEnv("DB_PASSWORD", ""),
		Name:        getEnv("DB_NAME", ""),
		SSLMode:     getEnv("DB_SSLMODE", "disable"),
		SSLRootCert: getEnv("DB_SSLROOTCERT", ""),
	}

	cfg.Storage = StorageConfig{
		Region:    getEnv("FILES_S3_REGION", "ap-southeast-3"),
		Bucket:    getEnv("FILES_S3_BUCKET", ""),
		Endpoint:  getEnv("FILES_S3_ENDPOINT", ""),
		AccessKey: getEnv("FILES_S3_ACCESS_KEY", ""),
		SecretKey: getEnv("FILES_S3_SECRET_KEY", ""),
		KeyPrefix: getEnv("FILES_S3_KEY_PREFIX", "files/"),
	}

	if cfg.DB.Host == "" || cfg.DB.User == "" || cfg.DB.Name == "" {
		return nil, errors.New("database configuration incomplete: ensure DB_HOST, DB_USER, and DB_NAME are set")
	}
	if cfg.Storage.Bucket == "" {
		return nil, errors.New("FILES_S3_BUCKET must be set for the document portal")
	}

	return cfg, nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// GetEnvInt returns an int env var or a default.
func GetEnvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return i
}
