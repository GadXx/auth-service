package middleware

import (
	"authservice/internal/errors"
	"authservice/internal/handler"
	"authservice/internal/service"
	"authservice/internal/utils"
	"log/slog"
	"net/http"
	"strings"
)

func AuthMiddleware(blackList *service.BlacklistService) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			header := r.Header.Get("Authorization")
			accessToken := strings.Split(header, " ")[1]
			if accessToken == "" {
				slog.Error("Missing access token header")
				handler.WriteTypeError(w, errors.ErrorTypeAuth, "Access token required")
				return
			}

			claims, err := utils.ParseToken(accessToken)
			if err != nil {
				slog.Error("Invalid token in middleware", "error", err)
				handler.WriteTypeError(w, errors.ErrorTypeAuth, "Invalid access token")
				return
			}

			sid, ok := claims["sid"].(string)
			if !ok {
				slog.Error("Invalid session ID in token claims")
				handler.WriteTypeError(w, errors.ErrorTypeAuth, "Invalid session ID in token")
				return
			}

			isBlacklisted, err := blackList.IsTokenBlacklist(sid)
			if err != nil {
				slog.Error("Error checking token blacklist", "error", err)
				handler.WriteTypeError(w, errors.ErrorTypeRedis, "Failed check token blacklist")
				return
			}
			if isBlacklisted {
				slog.Error("Token is blacklisted", "session_id", sid)
				handler.WriteTypeError(w, errors.ErrorTypeAuth, "Token is blacklisted")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
