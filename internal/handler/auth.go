package handler

import (
	"authservice/internal/errors"
	"authservice/internal/service"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"context"

	"authservice/internal/ctxkeys"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type AuthHandler struct {
	AuthService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{
		AuthService: authService,
	}
}

// NewSession godoc
// @Summary      Создать новую сессию
// @Description  Возвращает access token в заголовке и refresh token в cookie
// @Tags         auth
// @Param        user_id           path      string  true   "User ID"           default(0921ac27-5ec4-4031-a8f2-665e9c3c9eb3)
// @Param        User-Agent        header    string  false  "User-Agent"        default(Swagger-Test)
// @Param        X-Forwarded-For   header    string  false  "IP адрес клиента"  default(127.0.0.1)
// @Success      200  {object}  handler.SuccessResponse
// @Failure      400  {object}  handler.Response
// @Header       200  {string}  Access-Token  "Bearer <access_token>"
// @Set-Cookie   refresh_token=...; Path=/refresh; HttpOnly; Secure; SameSite=Strict
// @Router       /new_session/{user_id} [get]
func (h *AuthHandler) NewSession(w http.ResponseWriter, r *http.Request) {

	strID := chi.URLParam(r, "user_id")
	id, err := uuid.Parse(strID)
	if err != nil {
		slog.Error("Invalid user ID", "user_id", strID, "error", err)
		WriteTypeError(w, errors.ErrorTypeValidation, "Invalid user ID format")
		return
	}

	userAgent := r.Header.Get("User-Agent")
	ip := r.Header.Get("X-Forwarded-For")

	ctx := context.WithValue(r.Context(), ctxkeys.UserAgentKey, userAgent)
	ctx = context.WithValue(ctx, ctxkeys.IPAddressKey, ip)

	accessToken, refreshToken, err := h.AuthService.NewSession(ctx, id)
	if err != nil {
		slog.Error("Failed to create new session", "error", err)
		WriteError(w, err)
		return
	}

	w.Header().Set("Access-Token", "Bearer "+accessToken)

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/refresh",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
	})

	WriteSuccess(w, map[string]interface{}{
		"message": "Session created successfully",
	})
}

// GetAuthenticatedUserID godoc
// @Summary      Получить ID аутентифицированного пользователя
// @Description  Требует access token в заголовке Authorization
// @Tags         auth
// @Produce      json
// @Param        Authorization      header    string  true   "Bearer access_token"  default(Bearer <access_token>)
// @Param        User-Agent         header    string  false  "User-Agent"           default(Swagger-Test)
// @Param        X-Forwarded-For    header    string  false  "IP адрес клиента"     default(127.0.0.1)
// @Success      200  {object}  handler.SuccessResponse
// @Failure      401  {object}  handler.Response
// @Router       /me [get]
func (h *AuthHandler) GetAuthenticatedUserID(w http.ResponseWriter, r *http.Request) {

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		slog.Error("Missing access token header")
		WriteTypeError(w, errors.ErrorTypeAuth, "Access token required")
		return
	}

	accessToken := strings.Split(authHeader, " ")[1]
	if accessToken == "" {
		slog.Error("Missing access token header")
		WriteTypeError(w, errors.ErrorTypeAuth, "Access token required")
		return
	}

	userID, err := h.AuthService.GetUserID(r.Context(), accessToken)
	if err != nil {
		slog.Error("Failed to get user ID from token", "error", err)
		WriteError(w, err)
		return
	}

	WriteSuccess(w, map[string]interface{}{
		"user_id": userID,
	})
}

// RefreshSession godoc
// @Summary      Обновить access/refresh токены
// @Description  Требует access token в заголовке Authorization и cookie refresh_token.
// @Tags         auth
// @Produce      json
// @Param        Authorization      header    string  true   "Bearer access_token"  default(Bearer <access_token>)
// @Param        User-Agent         header    string  false  "User-Agent"           default(Swagger-Test)
// @Param        X-Forwarded-For    header    string  false  "IP адрес клиента"     default(127.0.0.1)
// @Success      200  {object}  handler.SuccessResponse
// @Failure      401  {object}  handler.Response
// @Header       200  {string}  Access-Token  "Bearer <new_access_token>"
// @Set-Cookie   refresh_token=...; Path=/refresh; HttpOnly; Secure; SameSite=Strict
// @Router       /refresh [get]
func (h *AuthHandler) RefreshSession(w http.ResponseWriter, r *http.Request) {

	accessToken := strings.Split(r.Header.Get("Authorization"), " ")[1]
	if accessToken == "" {
		slog.Error("Missing access token header")
		WriteTypeError(w, errors.ErrorTypeAuth, "Access token required")
		return
	}

	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		slog.Error("Missing refresh token cookie", "error", err)
		WriteTypeError(w, errors.ErrorTypeAuth, "Refresh token required")
		return
	}
	refreshToken := cookie.Value

	userAgent := r.Header.Get("User-Agent")
	ip := r.Header.Get("X-Forwarded-For")

	ctx := context.WithValue(r.Context(), ctxkeys.UserAgentKey, userAgent)
	ctx = context.WithValue(ctx, ctxkeys.IPAddressKey, ip)

	newAccessToken, newRefreshToken, err := h.AuthService.RefreshSession(ctx, accessToken, refreshToken)
	if err != nil {
		slog.Error("Failed to refresh session", "error", err)
		WriteError(w, err)
		return
	}

	w.Header().Set("Access-Token", "Bearer "+newAccessToken)

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    newRefreshToken,
		Path:     "/refresh",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
	})

	WriteSuccess(w, map[string]interface{}{
		"message": "Session refreshed successfully",
	})
}

// RevokeSession godoc
// @Summary      Отозвать сессию
// @Description  Требует access token в заголовке Authorization.
// @Tags         auth
// @Produce      json
// @Param        Authorization      header    string  true   "Bearer access_token"  default(Bearer <access_token>)
// @Param        User-Agent         header    string  false  "User-Agent"           default(Swagger-Test)
// @Param        X-Forwarded-For    header    string  false  "IP адрес клиента"     default(127.0.0.1)
// @Success      200  {object}  handler.SuccessResponse
// @Failure      401  {object}  handler.Response
// @Router       /refresh/revoke [post]
func (h *AuthHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		slog.Error("Missing access token header")
		WriteTypeError(w, errors.ErrorTypeAuth, "Access token required")
		return
	}

	accessToken := strings.Split(authHeader, " ")[1]
	if accessToken == "" {
		slog.Error("Missing access token header")
		WriteTypeError(w, errors.ErrorTypeAuth, "Access token required")
		return
	}

	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		slog.Error("Missing refresh token cookie", "error", err)
		WriteTypeError(w, errors.ErrorTypeAuth, "Refresh token required")
		return
	}
	refreshToken := cookie.Value

	err = h.AuthService.RevokeSession(r.Context(), accessToken, refreshToken)
	if err != nil {
		slog.Error("Failed to revoke session", "error", err)
		WriteError(w, err)
		return
	}

	WriteSuccess(w, map[string]interface{}{
		"message": "Session revoked successfully",
	})
}
