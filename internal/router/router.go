package router

import (
	"authservice/internal/handler"
	"authservice/internal/middleware"
	"authservice/internal/service"

	_ "authservice/docs"

	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger"
)

func NewRouter(authHandler *handler.AuthHandler, blackList *service.BlacklistService) *chi.Mux {
	router := chi.NewRouter()

	router.Use(chiMiddleware.Logger)

	router.Get("/docs/*", httpSwagger.WrapHandler)

	router.Get("/new_session/{user_id}", authHandler.NewSession)
	router.Get("/refresh", authHandler.RefreshSession)
	router.Post("/refresh/revoke", authHandler.RevokeSession)

	router.Group(func(r chi.Router) {
		r.Use(middleware.AuthMiddleware(blackList))
		r.Get("/me", authHandler.GetAuthenticatedUserID)
	})

	return router
}
