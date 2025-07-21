CREATE TABLE refresh_sessions (
    id BIGSERIAL PRIMARY KEY,
    session_id TEXT NOT NULL,
    refresh_token_hash TEXT NOT NULL UNIQUE,
    user_agent TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    revoked BOOLEAN NOT NULL DEFAULT FALSE
);