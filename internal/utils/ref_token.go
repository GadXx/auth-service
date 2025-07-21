package utils

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

func GenerateRefreshToken() (string, string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", err
	}

	tokenStr := base64.StdEncoding.EncodeToString(tokenBytes)
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(tokenStr), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return tokenStr, string(tokenHash), nil
}

func CheckRefreshToken(refreshToken string, refreshTokenHash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(refreshTokenHash), []byte(refreshToken))
	return err == nil
}
