-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, body, user_id)
VALUES (
    gen_random_uuid(),
    now(),
    now(),
    $1,
    $2
)
RETURNING *;

-- name: DeleteChirps :exec
DELETE FROM chirps;

-- name: ReadChirps :many
SELECT
    *
FROM
    chirps
ORDER BY
    created_at ASC;

-- name: ReadChirp :one
SELECT 
    *
FROM 
    chirps
WHERE 
    id = $1;

-- name: DeleteChirp :exec
DELETE FROM
    chirps
WHERE
    id = $1;