package service

import (
	"authservice/internal/ctxkeys"
	"authservice/internal/errors"
	"authservice/internal/model"
	"authservice/internal/repository"
	"authservice/internal/utils"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
)

type WebHookData struct {
	OldIP      string `json:"old_ip"`
	NewIP      string `json:"new_ip"`
	SesseionID string `json:"session_id"`
}

type AuthService struct {
	TokenRepo repository.IRefTokenRepository
	Blacklist *BlacklistService
}

func NewAuthService(repo repository.IRefTokenRepository, blacklist *BlacklistService) *AuthService {
	return &AuthService{
		TokenRepo: repo,
		Blacklist: blacklist,
	}
}

func (s *AuthService) NotifyWebHook(oldIP, newIP, sessionID string) error {

	data := WebHookData{
		OldIP:      oldIP,
		NewIP:      newIP,
		SesseionID: sessionID,
	}

	payload, err := json.Marshal(data)
	if err != nil {
		return errors.NewError(errors.ErrorTypeInternal, "failed marshal webhook data", err)
	} else {
		webhook := os.Getenv("WEBHOOK_URL")
		go func() {
			resp, err := http.Post(webhook, "application/json", bytes.NewBuffer(payload))
			if err != nil {
				slog.Error("Failed send webhook notification", "error", err)
			} else {
				resp.Body.Close()
			}
		}()
	}

	return nil
}

func (s *AuthService) NewSession(ctx context.Context, userID uuid.UUID) (string, string, error) {

	sessionID := uuid.New().String()
	strID := userID.String()

	accessToken, err := utils.GenerateJWT(strID, sessionID)
	if err != nil {
		return "", "", errors.NewError(errors.ErrorTypeInternal, "failed generate access token", err)
	}

	refreshToken, refreshTokenHash, err := utils.GenerateRefreshToken()
	if err != nil {
		return "", "", errors.NewError(errors.ErrorTypeInternal, "failed generate refresh token", err)
	}

	ua := ctx.Value(ctxkeys.UserAgentKey).(string)
	if ua == "" {
		return "", "", errors.NewError(errors.ErrorTypeAuth, "user agent not found in context", nil)
	}

	ip := ctx.Value(ctxkeys.IPAddressKey).(string)
	if ip == "" {
		return "", "", errors.NewError(errors.ErrorTypeAuth, "ip address not found in context", nil)
	}

	refSession := &model.RefreshSession{
		SessionID:        sessionID,
		RefreshTokenHash: refreshTokenHash,
		UserAgent:        ua,
		IPAddress:        ip,
		CreatedAt:        time.Now(),
		Revoked:          false,
	}
	if err := s.TokenRepo.Create(ctx, refSession); err != nil {
		return "", "", errors.NewError(errors.ErrorTypeDatabase, "failed create session in database", err)
	}

	return accessToken, refreshToken, nil
}

func (s *AuthService) GetUserID(ctx context.Context, accessToken string) (string, error) {

	claims, err := utils.ParseToken(accessToken)
	if err != nil {
		return "", errors.NewError(errors.ErrorTypeAuth, "failed parse access token", err)
	}

	userID, ok := claims["uid"].(string)
	if !ok {
		return "", errors.NewError(errors.ErrorTypeAuth, "invalid user ID in token claims", nil)
	}

	return userID, nil
}

func (s *AuthService) RefreshSession(ctx context.Context, Access_token, RefreshToken string) (string, string, error) {

	claims, err := utils.ParseToken(Access_token)
	if err != nil {
		return "", "", errors.NewError(errors.ErrorTypeAuth, "failed parse access token", err)
	}

	sessionID, ok := claims["sid"].(string)
	if !ok {
		return "", "", errors.NewError(errors.ErrorTypeAuth, "invalid session ID in token claims", nil)
	}

	refSession, err := s.TokenRepo.GetRefreshSession(ctx, sessionID)
	if err != nil {
		return "", "", errors.NewError(errors.ErrorTypeAuth, "failed get refresh session", err)
	}

	ua := ctx.Value(ctxkeys.UserAgentKey).(string)
	if refSession.UserAgent != ua {
		err = s.RevokeSession(ctx, Access_token, RefreshToken)
		if err != nil {
			return "", "", errors.NewError(errors.ErrorTypeAuth, "failed revoke old session", err)
		}
		return "", "", errors.NewError(errors.ErrorTypeAuth, "user agent mismatch", nil)
	}

	ip := ctx.Value(ctxkeys.IPAddressKey).(string)
	if refSession.IPAddress != ip {
		s.NotifyWebHook(refSession.IPAddress, ip, sessionID)
	}

	if !utils.CheckRefreshToken(RefreshToken, refSession.RefreshTokenHash) {
		return "", "", errors.NewError(errors.ErrorTypeAuth, "invalid refresh token", nil)
	}

	err = s.TokenRepo.RevokeRefreshSession(ctx, sessionID)
	if err != nil {
		return "", "", errors.NewError(errors.ErrorTypeDatabase, "failed revoke old session", err)
	}

	userIDStr, ok := claims["uid"].(string)
	if !ok {
		return "", "", errors.NewError(errors.ErrorTypeAuth, "invalid user ID in token claims", nil)
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return "", "", errors.NewError(errors.ErrorTypeAuth, "invalid user ID format", err)
	}

	access_token, refreshToken, err := s.NewSession(ctx, userID)
	if err != nil {
		return "", "", errors.NewError(errors.ErrorTypeInternal, "failed create new session", err)
	}

	return access_token, refreshToken, nil
}

func (s *AuthService) RevokeSession(ctx context.Context, access_token, refreshToken string) error {

	claims, err := utils.ParseToken(access_token)
	if err != nil {
		return errors.NewError(errors.ErrorTypeAuth, "failed parse access token", err)
	}

	sessionID, ok := claims["sid"].(string)
	if !ok {
		return errors.NewError(errors.ErrorTypeAuth, "invalid session ID in token claims", nil)
	}

	err = s.TokenRepo.RevokeRefreshSession(ctx, sessionID)
	if err != nil {
		return errors.NewError(errors.ErrorTypeDatabase, "failed revoke session", err)
	}

	ttlToken, err := utils.GetJWTTTL(access_token)
	if err != nil {
		return errors.NewError(errors.ErrorTypeAuth, "failed get token TTL", err)
	}

	err = s.Blacklist.AddToken(sessionID, ttlToken)
	if err != nil {
		return errors.NewError(errors.ErrorTypeRedis, "failed add token blacklist", err)
	}

	return nil
}
