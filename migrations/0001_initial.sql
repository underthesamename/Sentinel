CREATE TYPE account_status AS ENUM ('ACTIVE', 'LOCKED', 'DISABLED');
CREATE TYPE qr_challenge_status AS ENUM (
  'CREATED', 'SCANNED', 'APPROVED', 'EXCHANGED', 'REJECTED', 'EXPIRED', 'CANCELLED'
);

CREATE TABLE users (
  id UUID PRIMARY KEY,
  email_normalized TEXT NOT NULL UNIQUE,
  email_verified_at TIMESTAMPTZ,
  status account_status NOT NULL DEFAULT 'ACTIVE',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE password_credentials (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  password_hash TEXT NOT NULL,
  password_changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE qr_login_challenges (
  id UUID PRIMARY KEY,
  status qr_challenge_status NOT NULL DEFAULT 'CREATED',
  lock_version INTEGER NOT NULL DEFAULT 0,
  qr_token_fingerprint BYTEA UNIQUE,
  subscription_fingerprint BYTEA UNIQUE,
  verification_code_hash BYTEA,
  scanner_user_id UUID REFERENCES users(id),
  scanner_session_id UUID,
  requested_ua_summary TEXT,
  requested_ip INET,
  qr_expires_at TIMESTAMPTZ NOT NULL,
  approval_expires_at TIMESTAMPTZ,
  scanned_at TIMESTAMPTZ,
  approved_at TIMESTAMPTZ,
  terminal_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT approved_requires_scanner CHECK (
    status <> 'APPROVED' OR (scanner_user_id IS NOT NULL AND scanner_session_id IS NOT NULL)
  ),
  CONSTRAINT exchanged_requires_approval CHECK (status <> 'EXCHANGED' OR approved_at IS NOT NULL)
);

CREATE TABLE sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id),
  token_fingerprint BYTEA NOT NULL UNIQUE,
  auth_method TEXT NOT NULL,
  source_challenge_id UUID UNIQUE REFERENCES qr_login_challenges(id),
  user_agent_summary TEXT,
  ip_address INET,
  last_seen_at TIMESTAMPTZ NOT NULL,
  idle_expires_at TIMESTAMPTZ NOT NULL,
  absolute_expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  revocation_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE qr_login_challenges
  ADD CONSTRAINT qr_scanner_session_fk FOREIGN KEY (scanner_session_id) REFERENCES sessions(id);

CREATE TABLE qr_scan_continuations (
  id UUID PRIMARY KEY,
  challenge_id UUID NOT NULL REFERENCES qr_login_challenges(id),
  token_fingerprint BYTEA NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
  id UUID PRIMARY KEY,
  event_type TEXT NOT NULL,
  outcome TEXT NOT NULL,
  user_id UUID,
  session_id UUID,
  challenge_id UUID,
  correlation_id UUID NOT NULL,
  ip_prefix TEXT,
  ua_summary TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX sessions_active_by_user ON sessions(user_id) WHERE revoked_at IS NULL;
CREATE INDEX challenges_by_expiration ON qr_login_challenges(status, qr_expires_at, approval_expires_at);
CREATE INDEX challenges_by_scanner_session ON qr_login_challenges(scanner_session_id)
  WHERE scanner_session_id IS NOT NULL;
CREATE INDEX continuations_by_expiration ON qr_scan_continuations(expires_at);
CREATE INDEX audit_events_by_created_at ON audit_events(created_at);

