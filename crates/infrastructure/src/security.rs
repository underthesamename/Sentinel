use std::{
    collections::HashMap,
    fmt,
    sync::Mutex,
    time::{Duration, SystemTime},
};

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sentinel_application::{
    RateLimitDecision, RateLimitKey, RateLimitOperation, RateLimitPolicy, RateLimiter,
};
use sha2::Sha256;
use thiserror::Error;

const TOKEN_BYTES: usize = 32;
const MINIMUM_HMAC_KEY_BYTES: usize = 32;

/// Segredo opaco. `Debug` nunca revela o valor e a exposição exige uma chamada explícita.
pub struct SecretToken(String);

impl SecretToken {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretToken([REDACTED])")
    }
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("fonte de aleatoriedade do sistema indisponível")]
    RandomSource,
    #[error("chave de fingerprint deve possuir ao menos 32 bytes")]
    WeakFingerprintKey,
    #[error("key id de fingerprint vazio ou duplicado")]
    InvalidKeyId,
    #[error("keyring de fingerprint vazio")]
    EmptyKeyring,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTokenGenerator;

impl SystemTokenGenerator {
    pub fn generate(&self) -> Result<SecretToken, TokenError> {
        let mut bytes = [0_u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| TokenError::RandomSource)?;
        Ok(SecretToken(URL_SAFE_NO_PAD.encode(bytes)))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TokenFingerprint {
    key_id: String,
    digest: [u8; 32],
}

impl TokenFingerprint {
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl fmt::Debug for TokenFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenFingerprint")
            .field("key_id", &self.key_id)
            .field("digest", &"[32 BYTES]")
            .finish()
    }
}

#[derive(Clone)]
struct FingerprintKey {
    id: String,
    bytes: Vec<u8>,
}

/// O primeiro item é a chave ativa; chaves seguintes permanecem válidas durante rotação.
#[derive(Clone)]
pub struct FingerprintKeyRing {
    keys: Vec<FingerprintKey>,
}

impl fmt::Debug for FingerprintKeyRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ids = self
            .keys
            .iter()
            .map(|key| key.id.as_str())
            .collect::<Vec<_>>();
        formatter
            .debug_struct("FingerprintKeyRing")
            .field("key_ids", &ids)
            .finish()
    }
}

impl FingerprintKeyRing {
    pub fn new(keys: impl IntoIterator<Item = (String, Vec<u8>)>) -> Result<Self, TokenError> {
        let mut result = Vec::new();
        for (id, bytes) in keys {
            if id.trim().is_empty() || result.iter().any(|key: &FingerprintKey| key.id == id) {
                return Err(TokenError::InvalidKeyId);
            }
            if bytes.len() < MINIMUM_HMAC_KEY_BYTES {
                return Err(TokenError::WeakFingerprintKey);
            }
            result.push(FingerprintKey { id, bytes });
        }
        if result.is_empty() {
            return Err(TokenError::EmptyKeyring);
        }
        Ok(Self { keys: result })
    }

    pub fn fingerprint(&self, context: &[u8], token: &str) -> TokenFingerprint {
        let active = &self.keys[0];
        TokenFingerprint {
            key_id: active.id.clone(),
            digest: digest(&active.bytes, context, token),
        }
    }

    pub fn verify(&self, context: &[u8], token: &str, expected: &TokenFingerprint) -> bool {
        let Some(key) = self.keys.iter().find(|key| key.id == expected.key_id) else {
            return false;
        };
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&key.bytes).expect("HMAC accepts any key size");
        update_mac(&mut mac, context, token);
        mac.verify_slice(&expected.digest).is_ok()
    }
}

fn digest(key: &[u8], context: &[u8], token: &str) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
    update_mac(&mut mac, context, token);
    mac.finalize().into_bytes().into()
}

fn update_mac(mac: &mut Hmac<Sha256>, context: &[u8], token: &str) {
    mac.update(b"sentinel-token-v1\0");
    mac.update(&(context.len() as u64).to_be_bytes());
    mac.update(context);
    mac.update(token.as_bytes());
}

#[derive(Debug, Clone)]
pub struct CsrfTokenRecord {
    pub fingerprint: TokenFingerprint,
    pub expires_at: SystemTime,
}

#[derive(Debug)]
pub struct IssuedCsrfToken {
    pub token: SecretToken,
    pub record: CsrfTokenRecord,
}

#[derive(Clone)]
pub struct CsrfProtector {
    generator: SystemTokenGenerator,
    fingerprints: FingerprintKeyRing,
}

impl CsrfProtector {
    pub const fn new(generator: SystemTokenGenerator, fingerprints: FingerprintKeyRing) -> Self {
        Self {
            generator,
            fingerprints,
        }
    }

    pub fn issue(
        &self,
        session_id: &str,
        now: SystemTime,
        ttl: Duration,
    ) -> Result<IssuedCsrfToken, TokenError> {
        let token = self.generator.generate()?;
        let fingerprint = self
            .fingerprints
            .fingerprint(csrf_context(session_id).as_bytes(), token.expose());
        Ok(IssuedCsrfToken {
            token,
            record: CsrfTokenRecord {
                fingerprint,
                expires_at: now + ttl,
            },
        })
    }

    pub fn verify(
        &self,
        session_id: &str,
        supplied_token: Option<&str>,
        record: &CsrfTokenRecord,
        now: SystemTime,
    ) -> CsrfVerification {
        if now >= record.expires_at {
            return CsrfVerification::Expired;
        }
        let Some(token) = supplied_token.filter(|value| !value.is_empty()) else {
            return CsrfVerification::Missing;
        };
        if self.fingerprints.verify(
            csrf_context(session_id).as_bytes(),
            token,
            &record.fingerprint,
        ) {
            CsrfVerification::Valid
        } else {
            CsrfVerification::Invalid
        }
    }
}

fn csrf_context(session_id: &str) -> String {
    format!("csrf-session:{session_id}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsrfVerification {
    Missing,
    Invalid,
    Expired,
    Valid,
}

#[derive(Default)]
pub struct InMemoryRateLimiter {
    entries: Mutex<HashMap<(RateLimitOperation, RateLimitKey), WindowCounter>>,
}

#[derive(Debug, Clone, Copy)]
struct WindowCounter {
    started_at: SystemTime,
    count: u32,
}

#[async_trait]
impl RateLimiter for InMemoryRateLimiter {
    async fn check(
        &self,
        operation: RateLimitOperation,
        key: &RateLimitKey,
        policy: RateLimitPolicy,
        now: SystemTime,
    ) -> RateLimitDecision {
        if policy.limit == 0 || policy.window.is_zero() {
            return RateLimitDecision {
                allowed: false,
                remaining: 0,
                retry_after: None,
            };
        }
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = entries
            .entry((operation, key.clone()))
            .or_insert(WindowCounter {
                started_at: now,
                count: 0,
            });
        if now.duration_since(entry.started_at).unwrap_or_default() >= policy.window {
            *entry = WindowCounter {
                started_at: now,
                count: 0,
            };
        }
        if entry.count >= policy.limit {
            let elapsed = now.duration_since(entry.started_at).unwrap_or_default();
            return RateLimitDecision {
                allowed: false,
                remaining: 0,
                retry_after: Some(policy.window.saturating_sub(elapsed)),
            };
        }
        entry.count += 1;
        RateLimitDecision {
            allowed: true,
            remaining: policy.limit - entry.count,
            retry_after: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keyring(id: &str, byte: u8) -> FingerprintKeyRing {
        FingerprintKeyRing::new([(id.to_owned(), vec![byte; 32])]).unwrap()
    }

    #[test]
    fn tokens_are_distinct_and_exactly_256_bits_before_encoding() {
        let generator = SystemTokenGenerator;
        let first = generator.generate().unwrap();
        let second = generator.generate().unwrap();
        assert_ne!(first.expose(), second.expose());
        assert_eq!(URL_SAFE_NO_PAD.decode(first.expose()).unwrap().len(), 32);
        assert!(!format!("{first:?}").contains(first.expose()));
    }

    #[test]
    fn fingerprints_are_deterministic_only_for_same_key_and_context() {
        let first = keyring("current", 7);
        let second = keyring("other", 8);
        let fingerprint = first.fingerprint(b"session", "raw-secret");
        assert_eq!(fingerprint, first.fingerprint(b"session", "raw-secret"));
        assert_ne!(
            fingerprint.digest(),
            second.fingerprint(b"session", "raw-secret").digest()
        );
        assert_ne!(
            fingerprint.digest(),
            first.fingerprint(b"challenge", "raw-secret").digest()
        );
        assert!(first.verify(b"session", "raw-secret", &fingerprint));
        assert!(!first.verify(b"session", "wrong", &fingerprint));
    }

    #[test]
    fn old_key_remains_verifiable_during_rotation() {
        let old = keyring("old", 1);
        let fingerprint = old.fingerprint(b"session", "token");
        let rotated = FingerprintKeyRing::new([
            ("new".to_owned(), vec![2; 32]),
            ("old".to_owned(), vec![1; 32]),
        ])
        .unwrap();
        assert!(rotated.verify(b"session", "token", &fingerprint));
        assert_eq!(rotated.fingerprint(b"session", "token").key_id(), "new");
    }

    #[test]
    fn csrf_is_bound_to_session_and_expiration() {
        let protector = CsrfProtector::new(SystemTokenGenerator, keyring("v1", 3));
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let issued = protector
            .issue("session-a", now, Duration::from_secs(60))
            .unwrap();
        assert_eq!(
            protector.verify("session-a", None, &issued.record, now),
            CsrfVerification::Missing
        );
        assert_eq!(
            protector.verify("session-a", Some("bad"), &issued.record, now),
            CsrfVerification::Invalid
        );
        assert_eq!(
            protector.verify(
                "session-b",
                Some(issued.token.expose()),
                &issued.record,
                now
            ),
            CsrfVerification::Invalid
        );
        assert_eq!(
            protector.verify(
                "session-a",
                Some(issued.token.expose()),
                &issued.record,
                now + Duration::from_secs(60)
            ),
            CsrfVerification::Expired
        );
        assert_eq!(
            protector.verify(
                "session-a",
                Some(issued.token.expose()),
                &issued.record,
                now + Duration::from_secs(59)
            ),
            CsrfVerification::Valid
        );
    }

    #[tokio::test]
    async fn rate_limit_recovers_and_isolates_operations_and_keys() {
        let limiter = InMemoryRateLimiter::default();
        let now = SystemTime::UNIX_EPOCH;
        let policy = RateLimitPolicy {
            limit: 2,
            window: Duration::from_secs(10),
        };
        let a = RateLimitKey::composite(&["account", "network"]);
        let b = RateLimitKey::composite(&["other", "network"]);
        assert!(
            limiter
                .check(RateLimitOperation::Login, &a, policy, now)
                .await
                .allowed
        );
        assert!(
            limiter
                .check(RateLimitOperation::Login, &a, policy, now)
                .await
                .allowed
        );
        assert!(
            !limiter
                .check(RateLimitOperation::Login, &a, policy, now)
                .await
                .allowed
        );
        assert!(
            limiter
                .check(RateLimitOperation::Register, &a, policy, now)
                .await
                .allowed
        );
        assert!(
            limiter
                .check(RateLimitOperation::Login, &b, policy, now)
                .await
                .allowed
        );
        assert!(
            limiter
                .check(
                    RateLimitOperation::Login,
                    &a,
                    policy,
                    now + Duration::from_secs(10)
                )
                .await
                .allowed
        );
    }
}
