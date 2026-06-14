// Package config loads runtime configuration for the files-qris portal service.
package config

import (
	"errors"
	"os"
	"strconv"
)

// Config holds all runtime parameters for the QRIS document portal.
type Config struct {
	Port string
	Env  string

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
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{}

	cfg.Port = getEnv("PORT", "8090")
	cfg.Env = getEnv("ENV", "development")

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
