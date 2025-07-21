package utils

import (
	"authservice/internal/errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateJWT(userID, sessionID string) (string, error) {

	secret := os.Getenv("ACCESS_SECRET")
	if secret == "" {
		return "", errors.NewError(errors.ErrorTypeInternal, "ACCESS_SECRET not configured", nil)
	}

	claims := jwt.MapClaims{
		"uid": userID,
		"exp": time.Now().Add(30 * time.Minute).Unix(),
		"sid": sessionID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedToken, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", errors.NewError(errors.ErrorTypeInternal, "failed sign JWT token", err)
	}

	return signedToken, nil
}

func ParseToken(strToken string) (jwt.MapClaims, error) {

	secret := os.Getenv("ACCESS_SECRET")
	if secret == "" {
		return nil, errors.NewError(errors.ErrorTypeInternal, "ACCESS_SECRET not configured", nil)
	}

	token, err := jwt.Parse(strToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.NewError(errors.ErrorTypeAuth, "unexpected signing method", nil)
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, errors.NewError(errors.ErrorTypeAuth, "invalid token", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.NewError(errors.ErrorTypeAuth, "invalid token claims", nil)
	}

	return claims, nil
}

func GetJWTTTL(tokenString string) (time.Duration, error) {

	secret := os.Getenv("ACCESS_SECRET")
	if secret == "" {
		return 0, errors.NewError(errors.ErrorTypeInternal, "ACCESS_SECRET not configured", nil)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return 0, errors.NewError(errors.ErrorTypeAuth, "failed parse token for TTL calculation", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return 0, errors.NewError(errors.ErrorTypeAuth, "invalid token claims for TTL calculation", nil)
	}

	expFloat, ok := claims["exp"].(float64)
	if !ok {
		return 0, errors.NewError(errors.ErrorTypeAuth, "exp claim not found or not a float64", nil)
	}

	exp := int64(expFloat)
	now := time.Now().Unix()

	ttl := exp - now
	if ttl < 0 {
		return 0, errors.NewError(errors.ErrorTypeAuth, "token already expired", nil)
	}

	return time.Duration(ttl) * time.Second, nil
}
