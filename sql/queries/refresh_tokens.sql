-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at)
VALUES (
    $1,
    now(),
    now(),
    $2,
    now() + INTERVAL '60 days'
)
RETURNING *;

-- name: ReadRefreshTokenByToken :one
SELECT
    *
FROM
    refresh_tokens
WHERE
    token = $1;

-- name: UpdateRevokeRefreshToken :one
UPDATE
    refresh_tokens
SET
    updated_at = now(),
    revoked_at = now()
WHERE token = $1
RETURNING *;
