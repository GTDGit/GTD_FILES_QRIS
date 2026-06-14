package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/GTDGit/gtd_files_qris/internal/config"
	"github.com/GTDGit/gtd_files_qris/internal/database"
	"github.com/GTDGit/gtd_files_qris/internal/handler"
	"github.com/GTDGit/gtd_files_qris/internal/repository"
	"github.com/GTDGit/gtd_files_qris/internal/storage"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	setupLogger(cfg.Env)
	log.Info().Str("env", cfg.Env).Msg("starting files-qris portal")

	db, err := database.Connect(&cfg.DB)
	if err != nil {
		log.Error().Err(err).Msg("database connection failed")
		os.Exit(1)
	}
	defer db.Close()

	store, err := storage.NewS3Storage(context.Background(), cfg.Storage)
	if err != nil {
		log.Error().Err(err).Msg("storage init failed")
		os.Exit(1)
	}
	log.Info().Str("bucket", cfg.Storage.Bucket).Str("region", cfg.Storage.Region).Msg("storage ready")

	repo := repository.New(db)
	portal, err := handler.NewPortal(repo, store)
	if err != nil {
		log.Error().Err(err).Msg("portal init failed")
		os.Exit(1)
	}

	if cfg.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.New()
	router.Use(gin.Recovery())

	// Health check for nginx/load balancer.
	router.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	// Token-gated portal routes. No index, no listing — a bare visit to "/"
	// returns 403 just like any unknown token.
	router.GET("/", portal.Forbidden)
	router.GET("/b/:token", portal.ViewBundle)
	router.POST("/b/:token/confirm", portal.Confirm)
	router.GET("/f/:token", portal.ViewFile)
	router.GET("/f/:token/download", portal.DownloadFile)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Info().Str("port", cfg.Port).Msg("portal listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("server failed")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info().Msg("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("forced shutdown")
	}
	log.Info().Msg("server exited")
}

func setupLogger(env string) {
	if env == "production" {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
}
