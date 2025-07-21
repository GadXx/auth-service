package model

import (
	"time"
)

type RefreshSession struct {
	ID               int64     `db:"id"`
	SessionID        string    `db:"session_id"`
	RefreshTokenHash string    `db:"refresh_token_hash"`
	UserAgent        string    `db:"user_agent"`
	IPAddress        string    `db:"ip_address"`
	CreatedAt        time.Time `db:"created_at"`
	Revoked          bool      `db:"revoked"`
}
