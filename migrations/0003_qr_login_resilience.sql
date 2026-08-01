ALTER TABLE qr_login_challenges
  ADD COLUMN qr_token_key_id TEXT,
  ADD COLUMN subscription_key_id TEXT,
  ADD COLUMN verification_code_key_id TEXT,
  ADD COLUMN verification_attempts SMALLINT NOT NULL DEFAULT 0,
  ADD COLUMN code_verified_at TIMESTAMPTZ,
  ADD CONSTRAINT qr_verification_attempts_range CHECK (
    verification_attempts BETWEEN 0 AND 5
  );

ALTER TABLE qr_scan_continuations
  ADD COLUMN token_fingerprint_key_id TEXT NOT NULL DEFAULT 'legacy';

ALTER TABLE qr_scan_continuations
  ALTER COLUMN token_fingerprint_key_id DROP DEFAULT;

CREATE UNIQUE INDEX qr_continuations_token_with_key
  ON qr_scan_continuations(token_fingerprint_key_id, token_fingerprint);

CREATE INDEX qr_continuations_retention
  ON qr_scan_continuations(expires_at, consumed_at);

CREATE INDEX qr_challenges_retention
  ON qr_login_challenges(terminal_at, created_at);
