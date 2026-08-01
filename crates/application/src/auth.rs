use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use sentinel_domain::auth::NormalizedEmail;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    Active,
    Locked,
    Disabled,
}

#[derive(Debug, Clone)]
pub struct Credentials {
    pub user_id: Uuid,
    pub password_hash: String,
    pub status: AccountStatus,
}

#[derive(Debug, Clone)]
pub struct NewSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_fingerprint: Vec<u8>,
    pub token_key_id: String,
    pub last_seen_at: SystemTime,
    pub idle_expires_at: SystemTime,
    pub absolute_expires_at: SystemTime,
}

#[derive(Debug, Clone)]
pub struct SessionIdentity {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub email_normalized: String,
    pub last_seen_at: SystemTime,
    pub idle_expires_at: SystemTime,
    pub absolute_expires_at: SystemTime,
    pub csrf_fingerprint: Option<Vec<u8>>,
    pub csrf_key_id: Option<String>,
    pub csrf_expires_at: Option<SystemTime>,
}

#[derive(Debug, Clone)]
pub struct FingerprintCandidate {
    pub key_id: String,
    pub digest: Vec<u8>,
}

#[async_trait]
pub trait AuthRepository: Send + Sync {
    async fn create_user_with_password(
        &self,
        user_id: Uuid,
        email: &NormalizedEmail,
        password_hash: &str,
        now: SystemTime,
    ) -> Result<(), AuthRepositoryError>;

    async fn find_credentials(
        &self,
        email: &NormalizedEmail,
    ) -> Result<Option<Credentials>, AuthRepositoryError>;

    async fn create_session(&self, session: &NewSession) -> Result<(), AuthRepositoryError>;

    async fn find_active_session(
        &self,
        candidates: &[FingerprintCandidate],
        now: SystemTime,
        idle_ttl: Duration,
        touch_interval: Duration,
    ) -> Result<Option<SessionIdentity>, AuthRepositoryError>;

    async fn store_csrf(
        &self,
        session_id: Uuid,
        fingerprint: &[u8],
        key_id: &str,
        expires_at: SystemTime,
    ) -> Result<(), AuthRepositoryError>;

    async fn revoke_session(
        &self,
        session_id: Uuid,
        now: SystemTime,
    ) -> Result<(), AuthRepositoryError>;
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthRepositoryError {
    #[error("e-mail já cadastrado")]
    DuplicateEmail,
    #[error("repositório de autenticação indisponível")]
    Unavailable,
}

#[async_trait]
pub trait PasswordHasher: Send + Sync {
    async fn hash(&self, password: &str) -> Result<String, PasswordHashError>;
    async fn verify(&self, password: &str, password_hash: &str) -> Result<bool, PasswordHashError>;
    fn dummy_hash(&self) -> &str;
}

#[derive(Debug, Error)]
#[error("operação de senha indisponível")]
pub struct PasswordHashError;
