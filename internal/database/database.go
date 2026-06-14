// Package database opens the shared PostgreSQL (RDS) connection for the portal.
package database

import (
	"fmt"
	"net/url"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	appconfig "github.com/GTDGit/gtd_files_qris/internal/config"
)

// Connect opens a pooled sqlx connection to the same RDS instance used by the
// api/gateway services, with TLS settings preserved.
func Connect(cfg *appconfig.DatabaseConfig) (*sqlx.DB, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		url.QueryEscape(cfg.User),
		url.QueryEscape(cfg.Password),
		cfg.Host,
		cfg.Port,
		cfg.Name,
		cfg.SSLMode,
	)
	if cfg.SSLRootCert != "" {
		dsn += "&sslrootcert=" + url.QueryEscape(cfg.SSLRootCert)
	}

	var db *sqlx.DB
	var err error
	delay := 500 * time.Millisecond
	for attempt := 1; attempt <= 5; attempt++ {
		db, err = sqlx.Open("postgres", dsn)
		if err == nil {
			if pingErr := db.Ping(); pingErr == nil {
				break
			} else {
				err = pingErr
			}
		}
		if attempt < 5 {
			time.Sleep(delay)
			delay *= 2
		}
	}
	if err != nil {
		return nil, fmt.Errorf("connect db: %w", err)
	}

	db.SetMaxOpenConns(15)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	return db, nil
}
