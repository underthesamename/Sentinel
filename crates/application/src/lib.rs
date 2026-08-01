//! Casos de uso e portas do Sentinel.
//!
//! Esta camada orquestra o domínio sem depender de Axum, SQLx ou detalhes de transporte.

use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use sentinel_domain::qr_login::QrLoginChallenge;
use uuid::Uuid;

#[async_trait]
pub trait ChallengeRepository: Send + Sync {
    async fn find(&self, id: Uuid) -> Result<Option<QrLoginChallenge>, RepositoryError>;
    async fn save(&self, challenge: &QrLoginChallenge) -> Result<(), RepositoryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("repositório indisponível")]
    Unavailable,
    #[error("conflito de concorrência")]
    Conflict,
}

/// Porta substituível para limitação de taxa por operação e chave composta.
#[async_trait]
pub trait RateLimiter: Send + Sync {
    async fn check(
        &self,
        operation: RateLimitOperation,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
        now: SystemTime,
    ) -> RateLimitDecision;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitOperation {
    Register,
    Login,
    CreateQrChallenge,
    BootstrapQr,
    VerifyQrCode,
    ApproveQr,
    PollQr,
    ExchangeQr,
    WebSocket,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RateLimitKey(String);

impl RateLimitKey {
    pub fn composite(parts: &[&str]) -> Self {
        let mut value = String::new();
        for part in parts {
            value.push_str(&part.len().to_string());
            value.push(':');
            value.push_str(part);
            value.push('|');
        }
        Self(value)
    }
}

impl std::fmt::Debug for RateLimitKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RateLimitKey([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimitPolicy {
    pub limit: u32,
    pub window: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub remaining: u32,
    pub retry_after: Option<Duration>,
}
