package app

import (
	"authservice/internal/database"
	"authservice/internal/errors"
	"authservice/internal/handler"
	"authservice/internal/repository"
	"authservice/internal/router"
	"authservice/internal/service"
	"context"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type App struct {
	DBPool *pgxpool.Pool
	Router *chi.Mux
	Redis  *redis.Client
}

func NewApp(ctx context.Context) (*App, error) {

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return nil, errors.NewError(errors.ErrorTypeInternal, "DATABASE_URL environment variable is required", nil)
	}

	pool, err := database.NewPool(ctx, database.Config{
		URL:            dsn,
		MaxConns:       10,
		MaxConnIdle:    5 * time.Minute,
		ConnectTimeout: 3 * time.Second,
	})
	if err != nil {
		return nil, errors.NewError(errors.ErrorTypeDatabase, "failed to connect to database", err)
	}

	redisAddr := os.Getenv("REDIS_ADDR")
	redisPort := os.Getenv("REDIS_PORT")
	if redisAddr == "" || redisPort == "" {
		return nil, errors.NewError(errors.ErrorTypeInternal, "REDIS_ADDR and REDIS_PORT environment variables are required", nil)
	}

	redisClient, err := database.NewRedisClient(database.RedisConfig{
		Addr:     redisAddr + ":" + redisPort,
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})
	if err != nil {
		pool.Close()
		return nil, errors.NewError(errors.ErrorTypeRedis, "failed to connect to Redis", err)
	}

	blackList := service.NewBlacklistService(redisClient)

	tokenRepo := repository.NewRefTokenRepository(pool)
	authService := service.NewAuthService(tokenRepo, blackList)
	authHandler := handler.NewAuthHandler(authService)

	router := router.NewRouter(authHandler, blackList)

	app := &App{
		DBPool: pool,
		Router: router,
		Redis:  redisClient,
	}

	return app, nil
}
