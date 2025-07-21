package repository

import (
	"authservice/internal/errors"
	"authservice/internal/model"
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type IRefTokenRepository interface {
	Create(ctx context.Context, refSession *model.RefreshSession) error
	GetRefreshSession(ctx context.Context, sessionID string) (*model.RefreshSession, error)
	RevokeRefreshSession(ctx context.Context, sessionID string) error
}

type RefSessionRepository struct {
	DBPool *pgxpool.Pool
}

func NewRefTokenRepository(dbPool *pgxpool.Pool) *RefSessionRepository {
	return &RefSessionRepository{
		DBPool: dbPool,
	}
}

func (r *RefSessionRepository) Create(ctx context.Context, refSession *model.RefreshSession) error {
	query := `INSERT INTO refresh_sessions
	(session_id, refresh_token_hash, user_agent, ip_address, created_at, revoked)
	VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := r.DBPool.Exec(
		ctx,
		query,
		refSession.SessionID,
		refSession.RefreshTokenHash,
		refSession.UserAgent,
		refSession.IPAddress,
		refSession.CreatedAt,
		refSession.Revoked,
	)
	if err != nil {
		return errors.NewError(errors.ErrorTypeDatabase, "failed to create refresh session", err)
	}
	return nil
}

func (r *RefSessionRepository) GetRefreshSession(ctx context.Context, sessionID string) (*model.RefreshSession, error) {
	query := `SELECT * FROM refresh_sessions WHERE session_id = $1 AND revoked = false`
	var refSession model.RefreshSession
	err := r.DBPool.QueryRow(ctx, query, sessionID).Scan(
		&refSession.ID,
		&refSession.SessionID,
		&refSession.RefreshTokenHash,
		&refSession.UserAgent,
		&refSession.IPAddress,
		&refSession.CreatedAt,
		&refSession.Revoked,
	)
	if err != nil {
		return nil, errors.NewError(errors.ErrorTypeDatabase, "failed to get refresh session", err)
	}
	return &refSession, nil
}

func (r *RefSessionRepository) RevokeRefreshSession(ctx context.Context, sessionID string) error {
	query := `UPDATE refresh_sessions SET revoked = true WHERE session_id = $1 AND revoked = false`
	tag, err := r.DBPool.Exec(ctx, query, sessionID)
	if err != nil {
		return errors.NewError(errors.ErrorTypeDatabase, "failed to revoke refresh session", err)
	}
	rowsAffected := tag.RowsAffected()
	if rowsAffected == 0 {
		return errors.NewError(errors.ErrorTypeNotFound, "no active session found", nil)
	}
	return nil
}
