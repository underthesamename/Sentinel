use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};

use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{
        PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString, rand_core::OsRng,
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sentinel_application::auth::{
    AccountStatus, AuthRepository, AuthRepositoryError, Credentials, FingerprintCandidate,
    NewSession, PasswordHashError, PasswordHasher, SessionIdentity,
};
use sentinel_domain::auth::NormalizedEmail;
use sqlx::{PgPool, Postgres, QueryBuilder, Row};
use uuid::Uuid;

#[derive(Clone)]
pub struct Argon2idPasswordHasher {
    argon2: Argon2<'static>,
    dummy_hash: Arc<str>,
}

impl Argon2idPasswordHasher {
    pub fn new() -> Result<Self, PasswordHashError> {
        let params = Params::new(19 * 1024, 2, 1, None).map_err(|_| PasswordHashError)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        let dummy_hash = argon2
            .hash_password(b"sentinel dummy password verification", &salt)
            .map_err(|_| PasswordHashError)?
            .to_string()
            .into();
        Ok(Self { argon2, dummy_hash })
    }
}

#[async_trait]
impl PasswordHasher for Argon2idPasswordHasher {
    async fn hash(&self, password: &str) -> Result<String, PasswordHashError> {
        let password = password.as_bytes().to_vec();
        let argon2 = self.argon2.clone();
        tokio::task::spawn_blocking(move || {
            let salt = SaltString::generate(&mut OsRng);
            argon2
                .hash_password(&password, &salt)
                .map(|hash| hash.to_string())
                .map_err(|_| PasswordHashError)
        })
        .await
        .map_err(|_| PasswordHashError)?
    }

    async fn verify(&self, password: &str, password_hash: &str) -> Result<bool, PasswordHashError> {
        let password = password.as_bytes().to_vec();
        let password_hash = password_hash.to_owned();
        let argon2 = self.argon2.clone();
        tokio::task::spawn_blocking(move || {
            let parsed = PasswordHash::new(&password_hash).map_err(|_| PasswordHashError)?;
            Ok(argon2.verify_password(&password, &parsed).is_ok())
        })
        .await
        .map_err(|_| PasswordHashError)?
    }

    fn dummy_hash(&self) -> &str {
        &self.dummy_hash
    }
}

#[derive(Clone)]
pub struct PostgresAuthRepository {
    pool: PgPool,
}

impl PostgresAuthRepository {
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuthRepository for PostgresAuthRepository {
    async fn create_user_with_password(
        &self,
        user_id: Uuid,
        email: &NormalizedEmail,
        password_hash: &str,
        now: SystemTime,
    ) -> Result<(), AuthRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        let timestamp = timestamp(now);
        let insert_user = sqlx::query(
            "INSERT INTO users (id, email_normalized, created_at, updated_at) VALUES ($1, $2, $3, $3)",
        )
        .bind(user_id)
        .bind(email.as_str())
        .bind(timestamp)
        .execute(&mut *transaction)
        .await;
        if let Err(error) = insert_user {
            return Err(if is_unique_violation(&error) {
                AuthRepositoryError::DuplicateEmail
            } else {
                AuthRepositoryError::Unavailable
            });
        }
        sqlx::query(
            "INSERT INTO password_credentials (user_id, password_hash, password_changed_at) VALUES ($1, $2, $3)",
        )
        .bind(user_id)
        .bind(password_hash)
        .bind(timestamp)
        .execute(&mut *transaction)
        .await
        .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)
    }

    async fn find_credentials(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<Credentials>, AuthRepositoryError> {
        let row = sqlx::query(
            "SELECT u.id, u.status::text AS status, p.password_hash FROM users u JOIN password_credentials p ON p.user_id = u.id WHERE u.email_normalized = $1",
        )
        .bind(email.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?;
        row.map(|row| {
            let status: String = row.try_get("status").map_err(unavailable)?;
            Ok(Credentials {
                user_id: row.try_get("id").map_err(unavailable)?,
                password_hash: row.try_get("password_hash").map_err(unavailable)?,
                status: parse_status(&status)?,
            })
        })
        .transpose()
    }

    async fn create_session(&self, session: &NewSession) -> Result<(), AuthRepositoryError> {
        sqlx::query(
            "INSERT INTO sessions (id, user_id, token_fingerprint, token_fingerprint_key_id, auth_method, last_seen_at, idle_expires_at, absolute_expires_at, created_at) VALUES ($1, $2, $3, $4, 'password', $5, $6, $7, $5)",
        )
        .bind(session.id)
        .bind(session.user_id)
        .bind(&session.token_fingerprint)
        .bind(&session.token_key_id)
        .bind(timestamp(session.last_seen_at))
        .bind(timestamp(session.idle_expires_at))
        .bind(timestamp(session.absolute_expires_at))
        .execute(&self.pool)
        .await
        .map_err(unavailable)?;
        Ok(())
    }

    async fn find_active_session(
        &self,
        candidates: &[FingerprintCandidate],
        now: SystemTime,
        idle_ttl: Duration,
        touch_interval: Duration,
    ) -> Result<Option<SessionIdentity>, AuthRepositoryError> {
        if candidates.is_empty() {
            return Ok(None);
        }
        let now_timestamp = timestamp(now);
        let mut query = QueryBuilder::<Postgres>::new(
            "SELECT s.id, s.user_id, u.email_normalized, s.last_seen_at, s.idle_expires_at, s.absolute_expires_at, s.csrf_token_fingerprint, s.csrf_token_key_id, s.csrf_expires_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.revoked_at IS NULL AND s.idle_expires_at > ",
        );
        query.push_bind(now_timestamp);
        query
            .push(" AND s.absolute_expires_at > ")
            .push_bind(now_timestamp);
        query.push(" AND u.status = 'ACTIVE' AND (");
        push_fingerprint_conditions(&mut query, candidates);
        query.push(") LIMIT 1");
        let row = query
            .build()
            .fetch_optional(&self.pool)
            .await
            .map_err(unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut identity = session_from_row(&row)?;
        if now
            .duration_since(identity.last_seen_at)
            .unwrap_or_default()
            >= touch_interval
        {
            let proposed_idle = now + idle_ttl;
            let new_idle = proposed_idle.min(identity.absolute_expires_at);
            sqlx::query("UPDATE sessions SET last_seen_at = $2, idle_expires_at = $3 WHERE id = $1 AND revoked_at IS NULL")
                .bind(identity.session_id)
                .bind(now_timestamp)
                .bind(timestamp(new_idle))
                .execute(&self.pool)
                .await
                .map_err(unavailable)?;
            identity.last_seen_at = now;
            identity.idle_expires_at = new_idle;
        }
        Ok(Some(identity))
    }

    async fn store_csrf(
        &self,
        session_id: Uuid,
        fingerprint: &[u8],
        key_id: &str,
        expires_at: SystemTime,
    ) -> Result<(), AuthRepositoryError> {
        sqlx::query("UPDATE sessions SET csrf_token_fingerprint = $2, csrf_token_key_id = $3, csrf_expires_at = $4 WHERE id = $1 AND revoked_at IS NULL")
            .bind(session_id)
            .bind(fingerprint)
            .bind(key_id)
            .bind(timestamp(expires_at))
            .execute(&self.pool)
            .await
            .map_err(unavailable)?;
        Ok(())
    }

    async fn revoke_session(
        &self,
        session_id: Uuid,
        now: SystemTime,
    ) -> Result<(), AuthRepositoryError> {
        let mut transaction = self.pool.begin().await.map_err(unavailable)?;
        sqlx::query("UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2), revocation_reason = COALESCE(revocation_reason, 'logout'), csrf_token_fingerprint = NULL, csrf_token_key_id = NULL, csrf_expires_at = NULL WHERE id = $1")
            .bind(session_id)
            .bind(timestamp(now))
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        sqlx::query("UPDATE qr_login_challenges SET status = 'CANCELLED', terminal_at = $2, lock_version = lock_version + 1 WHERE scanner_session_id = $1 AND status IN ('SCANNED', 'APPROVED')")
            .bind(session_id)
            .bind(timestamp(now))
            .execute(&mut *transaction)
            .await
            .map_err(unavailable)?;
        transaction.commit().await.map_err(unavailable)
    }
}

fn push_fingerprint_conditions<'a>(
    query: &mut QueryBuilder<'a, Postgres>,
    candidates: &'a [FingerprintCandidate],
) {
    for (index, candidate) in candidates.iter().enumerate() {
        if index > 0 {
            query.push(" OR ");
        }
        query
            .push("(s.token_fingerprint_key_id = ")
            .push_bind(&candidate.key_id)
            .push(" AND s.token_fingerprint = ")
            .push_bind(&candidate.digest)
            .push(")");
    }
}

fn session_from_row(row: &sqlx::postgres::PgRow) -> Result<SessionIdentity, AuthRepositoryError> {
    Ok(SessionIdentity {
        session_id: row.try_get("id").map_err(unavailable)?,
        user_id: row.try_get("user_id").map_err(unavailable)?,
        email_normalized: row.try_get("email_normalized").map_err(unavailable)?,
        last_seen_at: system_time(row.try_get("last_seen_at").map_err(unavailable)?),
        idle_expires_at: system_time(row.try_get("idle_expires_at").map_err(unavailable)?),
        absolute_expires_at: system_time(row.try_get("absolute_expires_at").map_err(unavailable)?),
        csrf_fingerprint: row.try_get("csrf_token_fingerprint").map_err(unavailable)?,
        csrf_key_id: row.try_get("csrf_token_key_id").map_err(unavailable)?,
        csrf_expires_at: row
            .try_get::<Option<DateTime<Utc>>, _>("csrf_expires_at")
            .map_err(unavailable)?
            .map(system_time),
    })
}

fn parse_status(value: &str) -> Result<AccountStatus, AuthRepositoryError> {
    match value {
        "ACTIVE" => Ok(AccountStatus::Active),
        "LOCKED" => Ok(AccountStatus::Locked),
        "DISABLED" => Ok(AccountStatus::Disabled),
        _ => Err(AuthRepositoryError::Unavailable),
    }
}

fn timestamp(value: SystemTime) -> DateTime<Utc> {
    value.into()
}

fn system_time(value: DateTime<Utc>) -> SystemTime {
    value.into()
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|error| error.code())
        .as_deref()
        == Some("23505")
}

fn unavailable<T>(_: T) -> AuthRepositoryError {
    AuthRepositoryError::Unavailable
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use sqlx::Execute;

    use super::*;

    #[tokio::test]
    async fn argon2id_hash_uses_documented_parameters_and_verifies() {
        let hasher = Argon2idPasswordHasher::new().unwrap();
        let hash = hasher.hash("uma senha longa e exclusiva").await.unwrap();
        assert!(hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(
            hasher
                .verify("uma senha longa e exclusiva", &hash)
                .await
                .unwrap()
        );
        assert!(
            !hasher
                .verify("senha incorreta mas longa", &hash)
                .await
                .unwrap()
        );
    }

    #[test]
    fn fingerprint_lookup_keeps_each_key_and_digest_in_one_predicate() {
        let candidates = vec![
            FingerprintCandidate {
                key_id: "current".to_owned(),
                digest: vec![1; 32],
            },
            FingerprintCandidate {
                key_id: "previous".to_owned(),
                digest: vec![2; 32],
            },
        ];
        let mut builder = QueryBuilder::<Postgres>::new("(");
        push_fingerprint_conditions(&mut builder, &candidates);
        builder.push(")");
        assert_eq!(
            builder.build().sql(),
            "((s.token_fingerprint_key_id = $1 AND s.token_fingerprint = $2) OR (s.token_fingerprint_key_id = $3 AND s.token_fingerprint = $4))"
        );
    }

    #[tokio::test]
    #[ignore = "benchmark manual dependente do hardware"]
    async fn benchmark_argon2id_hash() {
        let hasher = Argon2idPasswordHasher::new().unwrap();
        let mut samples = Vec::with_capacity(5);
        for _ in 0..5 {
            let started_at = Instant::now();
            hasher
                .hash("uma senha longa usada somente no benchmark")
                .await
                .unwrap();
            samples.push(started_at.elapsed());
        }
        samples.sort_unstable();
        println!("Argon2id median over 5 hashes: {:?}", samples[2]);
    }
}
