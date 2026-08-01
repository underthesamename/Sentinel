ALTER TABLE sessions
  ADD COLUMN token_fingerprint_key_id TEXT NOT NULL DEFAULT 'legacy',
  ADD COLUMN csrf_token_fingerprint BYTEA,
  ADD COLUMN csrf_token_key_id TEXT,
  ADD COLUMN csrf_expires_at TIMESTAMPTZ,
  ADD CONSTRAINT csrf_fields_are_complete CHECK (
    (csrf_token_fingerprint IS NULL AND csrf_token_key_id IS NULL AND csrf_expires_at IS NULL)
    OR
    (csrf_token_fingerprint IS NOT NULL AND csrf_token_key_id IS NOT NULL AND csrf_expires_at IS NOT NULL)
  );

ALTER TABLE sessions ALTER COLUMN token_fingerprint_key_id DROP DEFAULT;
CREATE UNIQUE INDEX sessions_token_fingerprint_with_key
  ON sessions(token_fingerprint_key_id, token_fingerprint);
