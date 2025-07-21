package main

import (
	"authservice/internal/app"
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {

	ctx := context.Background()
	app, err := app.NewApp(ctx)
	if err != nil {
		slog.Error("Failed to create application", "error", err)
		os.Exit(1)
	}

	defer func() {
		if app.DBPool != nil {
			slog.Info("Closing database connection pool")
			app.DBPool.Close()
		}
		if app.Redis != nil {
			slog.Info("Closing Redis connection")
			app.Redis.Close()
		}
	}()

	port := os.Getenv("PORT")

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      app.Router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Received shutdown signal, starting graceful shutdown")

	ctxShut, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctxShut); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	} else {
		slog.Info("Server stopped gracefully")
	}
}
