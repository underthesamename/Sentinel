use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum::{
    Json,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use sentinel_api_contract::{
    CredentialsRequest, CsrfResponse, SessionDetails, SessionResponse, UserResponse,
};
use sentinel_application::{
    RateLimitKey, RateLimitOperation, RateLimitPolicy, RateLimiter,
    auth::{
        AccountStatus, AuthRepository, AuthRepositoryError, FingerprintCandidate, NewSession,
        PasswordHasher, SessionIdentity,
    },
};
use sentinel_domain::auth::{NormalizedEmail, PasswordPolicy, PasswordPolicyError};
use sentinel_infrastructure::security::{
    CsrfProtector, CsrfTokenRecord, CsrfVerification, FingerprintKeyRing, SystemTokenGenerator,
    TokenFingerprint,
};
use uuid::Uuid;

use crate::{
    AppState, CorrelationId,
    config::PublicConfig,
    error::ApiError,
    security::{AuditCategory, AuditEvent, AuditOutcome, HostCookieBuilder, OriginPolicy},
};

const SESSION_CONTEXT: &[u8] = b"session";

pub struct AuthService {
    repository: Arc<dyn AuthRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    rate_limiter: Arc<dyn RateLimiter>,
    fingerprints: FingerprintKeyRing,
    csrf: CsrfProtector,
    token_generator: SystemTokenGenerator,
    origin_policy: OriginPolicy,
    cookies: HostCookieBuilder,
    config: Arc<PublicConfig>,
}

impl AuthService {
    pub fn new(
        repository: Arc<dyn AuthRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        rate_limiter: Arc<dyn RateLimiter>,
        fingerprints: FingerprintKeyRing,
        config: Arc<PublicConfig>,
    ) -> Result<Self, crate::security::OriginError> {
        let csrf = CsrfProtector::new(SystemTokenGenerator, fingerprints.clone());
        let origin_policy = OriginPolicy::new([config.app_origin.clone()])?;
        let cookies = HostCookieBuilder::new(config.environment);
        Ok(Self {
            repository,
            password_hasher,
            rate_limiter,
            fingerprints,
            csrf,
            token_generator: SystemTokenGenerator,
            origin_policy,
            cookies,
            config,
        })
    }

    pub(crate) async fn authenticate(
        &self,
        headers: &HeaderMap,
        now: SystemTime,
    ) -> Result<SessionIdentity, AuthenticationFailure> {
        let token = session_cookie(headers).ok_or(AuthenticationFailure::InvalidSession)?;
        let candidates = self
            .fingerprints
            .candidates(SESSION_CONTEXT, token)
            .into_iter()
            .map(|candidate| FingerprintCandidate {
                key_id: candidate.key_id().to_owned(),
                digest: candidate.digest().to_vec(),
            })
            .collect::<Vec<_>>();
        self.repository
            .find_active_session(
                &candidates,
                now,
                self.config.session_idle_ttl,
                self.config.session_touch_interval,
            )
            .await
            .map_err(|_| AuthenticationFailure::RepositoryUnavailable)?
            .ok_or(AuthenticationFailure::InvalidSession)
    }

    pub(crate) async fn allow(
        &self,
        operation: RateLimitOperation,
        key: RateLimitKey,
        policy: RateLimitPolicy,
        now: SystemTime,
    ) -> bool {
        self.rate_limiter
            .check(operation, &key, policy, now)
            .await
            .allowed
    }
}

impl AuthService {
    pub(crate) fn validate_mutation(
        &self,
        headers: &HeaderMap,
        correlation_id: CorrelationId,
    ) -> Result<(), ApiError> {
        self.origin_policy
            .validate_http_mutation(headers)
            .map_err(|_| ApiError::csrf_rejected(correlation_id))
    }

    pub(crate) fn validate_websocket(&self, headers: &HeaderMap) -> bool {
        self.origin_policy.validate_websocket(headers).is_ok()
    }

    pub(crate) fn verify_session_csrf(
        &self,
        identity: &SessionIdentity,
        headers: &HeaderMap,
        now: SystemTime,
    ) -> bool {
        let Some(record) = csrf_record(identity) else {
            return false;
        };
        let supplied = headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok());
        self.csrf
            .verify(&identity.session_id.to_string(), supplied, &record, now)
            == CsrfVerification::Valid
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum AuthenticationFailure {
    InvalidSession,
    RepositoryUnavailable,
}

#[axum::debug_handler]
pub async fn register(
    State(state): State<AppState>,
    correlation_id: axum::Extension<CorrelationId>,
    client: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<CredentialsRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let correlation_id = correlation_id.0;
    state
        .auth
        .origin_policy
        .validate_http_mutation(&headers)
        .map_err(|_| ApiError::bad_request("INVALID_ORIGIN", "Origem inválida", correlation_id))?;
    let email = NormalizedEmail::parse(&request.email).map_err(|_| {
        ApiError::bad_request(
            "INVALID_REGISTRATION",
            "Dados de cadastro inválidos",
            correlation_id,
        )
    })?;
    PasswordPolicy
        .validate(&request.password)
        .map_err(|error| password_policy_error(error, correlation_id))?;
    let now = SystemTime::now();
    let network = client_network(client);
    if !state
        .auth
        .allow(
            RateLimitOperation::Register,
            RateLimitKey::composite(&[email.as_str(), &network]),
            RateLimitPolicy {
                limit: 3,
                window: Duration::from_secs(3600),
            },
            now,
        )
        .await
    {
        audit(
            AuditOutcome::Denied,
            "auth.register.rate_limited",
            correlation_id,
        )
        .write_log();
        return Err(ApiError::too_many_requests(correlation_id));
    }
    let password_hash = state
        .auth
        .password_hasher
        .hash(&request.password)
        .await
        .map_err(|_| ApiError::internal(correlation_id))?;
    let user_id = Uuid::now_v7();
    match state
        .auth
        .repository
        .create_user_with_password(user_id, &email, &password_hash, now)
        .await
    {
        Ok(()) => {
            audit(AuditOutcome::Succeeded, "auth.registered", correlation_id)
                .user(user_id)
                .write_log();
            Ok((
                StatusCode::CREATED,
                Json(UserResponse {
                    id: user_id,
                    email: email.as_str().to_owned(),
                }),
            ))
        }
        Err(AuthRepositoryError::DuplicateEmail) => Err(ApiError::conflict(
            "EMAIL_ALREADY_REGISTERED",
            "Conta já cadastrada",
            correlation_id,
        )),
        Err(AuthRepositoryError::Unavailable) => Err(ApiError::internal(correlation_id)),
    }
}

#[axum::debug_handler]
pub async fn login(
    State(state): State<AppState>,
    correlation_id: axum::Extension<CorrelationId>,
    client: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<CredentialsRequest>,
) -> Result<Response, ApiError> {
    let correlation_id = correlation_id.0;
    state
        .auth
        .origin_policy
        .validate_http_mutation(&headers)
        .map_err(|_| ApiError::bad_request("INVALID_ORIGIN", "Origem inválida", correlation_id))?;
    let email = NormalizedEmail::parse(&request.email)
        .map_err(|_| ApiError::invalid_credentials(correlation_id))?;
    let now = SystemTime::now();
    let network = client_network(client);
    if !state
        .auth
        .allow(
            RateLimitOperation::Login,
            RateLimitKey::composite(&[email.as_str(), &network]),
            RateLimitPolicy {
                limit: 5,
                window: Duration::from_secs(15 * 60),
            },
            now,
        )
        .await
    {
        audit(
            AuditOutcome::Denied,
            "auth.login.rate_limited",
            correlation_id,
        )
        .write_log();
        return Err(ApiError::too_many_requests(correlation_id));
    }
    let credentials = state
        .auth
        .repository
        .find_credentials(&email)
        .await
        .map_err(|_| ApiError::internal(correlation_id))?;
    let password_hash = credentials.as_ref().map_or_else(
        || state.auth.password_hasher.dummy_hash(),
        |value| &value.password_hash,
    );
    let password_matches = state
        .auth
        .password_hasher
        .verify(&request.password, password_hash)
        .await
        .map_err(|_| ApiError::internal(correlation_id))?;
    let Some(credentials) = credentials
        .filter(|credentials| password_matches && credentials.status == AccountStatus::Active)
    else {
        audit(AuditOutcome::Failed, "auth.login.failed", correlation_id)
            .reason_category("invalid_credentials")
            .write_log();
        return Err(ApiError::invalid_credentials(correlation_id));
    };
    let previous_session = match state.auth.authenticate(&headers, now).await {
        Ok(session) => Some(session),
        Err(AuthenticationFailure::InvalidSession) => None,
        Err(AuthenticationFailure::RepositoryUnavailable) => {
            return Err(ApiError::internal(correlation_id));
        }
    };

    let session_id = Uuid::now_v7();
    let token = state
        .auth
        .token_generator
        .generate()
        .map_err(|_| ApiError::internal(correlation_id))?;
    let fingerprint = state
        .auth
        .fingerprints
        .fingerprint(SESSION_CONTEXT, token.expose());
    let session = NewSession {
        id: session_id,
        user_id: credentials.user_id,
        token_fingerprint: fingerprint.digest().to_vec(),
        token_key_id: fingerprint.key_id().to_owned(),
        last_seen_at: now,
        idle_expires_at: now + state.auth.config.session_idle_ttl,
        absolute_expires_at: now + state.auth.config.session_absolute_ttl,
    };
    state
        .auth
        .repository
        .create_session(&session)
        .await
        .map_err(|_| ApiError::internal(correlation_id))?;
    if let Some(previous) = previous_session.filter(|previous| previous.session_id != session_id) {
        state
            .auth
            .repository
            .revoke_session(previous.session_id, now)
            .await
            .map_err(|_| ApiError::internal(correlation_id))?;
    }
    let cookie = state
        .auth
        .cookies
        .session(token.expose(), state.auth.config.session_absolute_ttl)
        .map_err(|_| ApiError::internal(correlation_id))?;
    audit(
        AuditOutcome::Succeeded,
        "auth.login.succeeded",
        correlation_id,
    )
    .user(credentials.user_id)
    .session(session_id)
    .write_log();
    let body = SessionResponse {
        user: UserResponse {
            id: credentials.user_id,
            email: email.as_str().to_owned(),
        },
        session: SessionDetails {
            id: session_id,
            idle_expires_at: timestamp(session.idle_expires_at),
            absolute_expires_at: timestamp(session.absolute_expires_at),
        },
    };
    let mut response = (StatusCode::OK, Json(body)).into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(response)
}

pub async fn me(
    State(state): State<AppState>,
    correlation_id: axum::Extension<CorrelationId>,
    headers: HeaderMap,
) -> Result<Json<SessionResponse>, ApiError> {
    let identity = state
        .auth
        .authenticate(&headers, SystemTime::now())
        .await
        .map_err(|error| authentication_error(error, correlation_id.0))?;
    Ok(Json(session_response(identity)))
}

pub async fn csrf(
    State(state): State<AppState>,
    correlation_id: axum::Extension<CorrelationId>,
    headers: HeaderMap,
) -> Result<Json<CsrfResponse>, ApiError> {
    let correlation_id = correlation_id.0;
    let identity = state
        .auth
        .authenticate(&headers, SystemTime::now())
        .await
        .map_err(|error| authentication_error(error, correlation_id))?;
    let now = SystemTime::now();
    let issued = state
        .auth
        .csrf
        .issue(
            &identity.session_id.to_string(),
            now,
            state.auth.config.csrf_ttl,
        )
        .map_err(|_| ApiError::internal(correlation_id))?;
    state
        .auth
        .repository
        .store_csrf(
            identity.session_id,
            issued.record.fingerprint.digest(),
            issued.record.fingerprint.key_id(),
            issued.record.expires_at,
        )
        .await
        .map_err(|_| ApiError::internal(correlation_id))?;
    Ok(Json(CsrfResponse {
        csrf_token: issued.token.expose().to_owned(),
        expires_at: timestamp(issued.record.expires_at),
    }))
}

pub async fn logout(
    State(state): State<AppState>,
    correlation_id: axum::Extension<CorrelationId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let correlation_id = correlation_id.0;
    state
        .auth
        .origin_policy
        .validate_http_mutation(&headers)
        .map_err(|_| ApiError::csrf_rejected(correlation_id))?;
    let now = SystemTime::now();
    let identity = state
        .auth
        .authenticate(&headers, now)
        .await
        .map_err(|error| authentication_error(error, correlation_id))?;
    let csrf_record =
        csrf_record(&identity).ok_or_else(|| ApiError::csrf_rejected(correlation_id))?;
    let supplied = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok());
    if state.auth.csrf.verify(
        &identity.session_id.to_string(),
        supplied,
        &csrf_record,
        now,
    ) != CsrfVerification::Valid
    {
        return Err(ApiError::csrf_rejected(correlation_id));
    }
    state
        .auth
        .repository
        .revoke_session(identity.session_id, now)
        .await
        .map_err(|_| ApiError::internal(correlation_id))?;
    audit(AuditOutcome::Succeeded, "session.revoked", correlation_id)
        .user(identity.user_id)
        .session(identity.session_id)
        .reason_category("logout")
        .write_log();
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, state.auth.cookies.clear_session());
    Ok(response)
}

pub async fn revoke_all_sessions(
    State(state): State<AppState>,
    correlation_id: axum::Extension<CorrelationId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let correlation_id = correlation_id.0;
    state
        .auth
        .origin_policy
        .validate_http_mutation(&headers)
        .map_err(|_| ApiError::csrf_rejected(correlation_id))?;
    let now = SystemTime::now();
    let identity = state
        .auth
        .authenticate(&headers, now)
        .await
        .map_err(|error| authentication_error(error, correlation_id))?;
    let csrf_record =
        csrf_record(&identity).ok_or_else(|| ApiError::csrf_rejected(correlation_id))?;
    let supplied = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok());
    if state.auth.csrf.verify(
        &identity.session_id.to_string(),
        supplied,
        &csrf_record,
        now,
    ) != CsrfVerification::Valid
    {
        return Err(ApiError::csrf_rejected(correlation_id));
    }

    let revoked_at: DateTime<Utc> = now.into();
    let mut transaction = state
        .pool
        .begin()
        .await
        .map_err(|_| ApiError::internal(correlation_id))?;
    sqlx::query("UPDATE sessions SET revoked_at = $2, revocation_reason = 'revoke_all', csrf_token_fingerprint = NULL, csrf_token_key_id = NULL, csrf_expires_at = NULL WHERE user_id = $1 AND revoked_at IS NULL")
        .bind(identity.user_id)
        .bind(revoked_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal(correlation_id))?;
    sqlx::query("UPDATE qr_login_challenges SET status = 'CANCELLED', terminal_at = $2, lock_version = lock_version + 1, qr_token_fingerprint = NULL, verification_code_hash = NULL WHERE scanner_user_id = $1 AND status IN ('SCANNED', 'APPROVED')")
        .bind(identity.user_id)
        .bind(revoked_at)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ApiError::internal(correlation_id))?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal(correlation_id))?;

    audit(
        AuditOutcome::Succeeded,
        "session.revoked_all",
        correlation_id,
    )
    .user(identity.user_id)
    .session(identity.session_id)
    .reason_category("user_requested")
    .write_log();
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, state.auth.cookies.clear_session());
    Ok(response)
}

fn csrf_record(identity: &SessionIdentity) -> Option<CsrfTokenRecord> {
    let digest: [u8; 32] = identity.csrf_fingerprint.as_deref()?.try_into().ok()?;
    Some(CsrfTokenRecord {
        fingerprint: TokenFingerprint::from_parts(identity.csrf_key_id.clone()?, digest),
        expires_at: identity.csrf_expires_at?,
    })
}

fn session_response(identity: SessionIdentity) -> SessionResponse {
    SessionResponse {
        user: UserResponse {
            id: identity.user_id,
            email: identity.email_normalized,
        },
        session: SessionDetails {
            id: identity.session_id,
            idle_expires_at: timestamp(identity.idle_expires_at),
            absolute_expires_at: timestamp(identity.absolute_expires_at),
        },
    }
}

fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .map(str::trim)
        .find_map(|cookie| cookie.strip_prefix("__Host-session="))
        .filter(|value| !value.is_empty())
}

fn client_network(client: ConnectInfo<SocketAddr>) -> String {
    client.0.ip().to_string()
}

fn password_policy_error(error: PasswordPolicyError, correlation_id: CorrelationId) -> ApiError {
    match error {
        PasswordPolicyError::Blocked => {
            ApiError::bad_request("PASSWORD_BLOCKED", "Senha não permitida", correlation_id)
        }
        PasswordPolicyError::TooShort | PasswordPolicyError::TooLong => ApiError::bad_request(
            "PASSWORD_POLICY_REJECTED",
            "Senha não atende à política",
            correlation_id,
        ),
    }
}

fn authentication_error(error: AuthenticationFailure, correlation_id: CorrelationId) -> ApiError {
    match error {
        AuthenticationFailure::InvalidSession => ApiError::unauthorized(correlation_id),
        AuthenticationFailure::RepositoryUnavailable => ApiError::internal(correlation_id),
    }
}

fn timestamp(value: SystemTime) -> DateTime<Utc> {
    value.into()
}

fn audit(
    outcome: AuditOutcome,
    event_type: &'static str,
    correlation_id: CorrelationId,
) -> AuditEvent {
    AuditEvent::new(
        AuditCategory::Authentication,
        event_type,
        outcome,
        correlation_id.0,
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use async_trait::async_trait;
    use axum::{
        Router,
        body::Body,
        http::{HeaderValue, Request},
    };
    use http_body_util::BodyExt;
    use sentinel_application::auth::{Credentials, PasswordHashError};
    use sentinel_infrastructure::security::InMemoryRateLimiter;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;
    use crate::{HealthProbe, build_router, config::AppEnvironment};

    #[derive(Default)]
    struct MemoryRepository {
        state: Mutex<MemoryState>,
    }

    #[derive(Default)]
    struct MemoryState {
        users: HashMap<String, Credentials>,
        sessions: HashMap<Uuid, MemorySession>,
    }

    struct MemorySession {
        session: NewSession,
        email: String,
        csrf: Option<(Vec<u8>, String, SystemTime)>,
        revoked: bool,
    }

    #[async_trait]
    impl AuthRepository for MemoryRepository {
        async fn create_user_with_password(
            &self,
            user_id: Uuid,
            email: &NormalizedEmail,
            password_hash: &str,
            _now: SystemTime,
        ) -> Result<(), AuthRepositoryError> {
            let mut state = self.state.lock().unwrap();
            if state.users.contains_key(email.as_str()) {
                return Err(AuthRepositoryError::DuplicateEmail);
            }
            state.users.insert(
                email.as_str().to_owned(),
                Credentials {
                    user_id,
                    password_hash: password_hash.to_owned(),
                    status: AccountStatus::Active,
                },
            );
            Ok(())
        }

        async fn find_credentials(
            &self,
            email: &NormalizedEmail,
        ) -> Result<Option<Credentials>, AuthRepositoryError> {
            Ok(self
                .state
                .lock()
                .unwrap()
                .users
                .get(email.as_str())
                .cloned())
        }

        async fn create_session(&self, session: &NewSession) -> Result<(), AuthRepositoryError> {
            let mut state = self.state.lock().unwrap();
            let email = state
                .users
                .iter()
                .find_map(|(email, credentials)| {
                    (credentials.user_id == session.user_id).then(|| email.clone())
                })
                .ok_or(AuthRepositoryError::Unavailable)?;
            state.sessions.insert(
                session.id,
                MemorySession {
                    session: session.clone(),
                    email,
                    csrf: None,
                    revoked: false,
                },
            );
            Ok(())
        }

        async fn find_active_session(
            &self,
            candidates: &[FingerprintCandidate],
            now: SystemTime,
            idle_ttl: Duration,
            touch_interval: Duration,
        ) -> Result<Option<SessionIdentity>, AuthRepositoryError> {
            let mut state = self.state.lock().unwrap();
            let found = state.sessions.values_mut().find(|stored| {
                !stored.revoked
                    && stored.session.idle_expires_at > now
                    && stored.session.absolute_expires_at > now
                    && candidates.iter().any(|candidate| {
                        candidate.key_id == stored.session.token_key_id
                            && candidate.digest == stored.session.token_fingerprint
                    })
            });
            let Some(stored) = found else {
                return Ok(None);
            };
            if now
                .duration_since(stored.session.last_seen_at)
                .unwrap_or_default()
                >= touch_interval
            {
                stored.session.last_seen_at = now;
                stored.session.idle_expires_at =
                    (now + idle_ttl).min(stored.session.absolute_expires_at);
            }
            let (csrf_fingerprint, csrf_key_id, csrf_expires_at) = stored
                .csrf
                .clone()
                .map_or((None, None, None), |(digest, key, expires)| {
                    (Some(digest), Some(key), Some(expires))
                });
            Ok(Some(SessionIdentity {
                session_id: stored.session.id,
                user_id: stored.session.user_id,
                email_normalized: stored.email.clone(),
                last_seen_at: stored.session.last_seen_at,
                idle_expires_at: stored.session.idle_expires_at,
                absolute_expires_at: stored.session.absolute_expires_at,
                csrf_fingerprint,
                csrf_key_id,
                csrf_expires_at,
            }))
        }

        async fn store_csrf(
            &self,
            session_id: Uuid,
            fingerprint: &[u8],
            key_id: &str,
            expires_at: SystemTime,
        ) -> Result<(), AuthRepositoryError> {
            let mut state = self.state.lock().unwrap();
            let session = state
                .sessions
                .get_mut(&session_id)
                .ok_or(AuthRepositoryError::Unavailable)?;
            session.csrf = Some((fingerprint.to_vec(), key_id.to_owned(), expires_at));
            Ok(())
        }

        async fn revoke_session(
            &self,
            session_id: Uuid,
            _now: SystemTime,
        ) -> Result<(), AuthRepositoryError> {
            if let Some(session) = self.state.lock().unwrap().sessions.get_mut(&session_id) {
                session.revoked = true;
                session.csrf = None;
            }
            Ok(())
        }
    }

    struct TestPasswordHasher;

    #[async_trait]
    impl PasswordHasher for TestPasswordHasher {
        async fn hash(&self, password: &str) -> Result<String, PasswordHashError> {
            Ok(format!("test-hash:{password}"))
        }

        async fn verify(
            &self,
            password: &str,
            password_hash: &str,
        ) -> Result<bool, PasswordHashError> {
            Ok(password_hash == format!("test-hash:{password}"))
        }

        fn dummy_hash(&self) -> &str {
            "test-hash:dummy-password-value"
        }
    }

    struct ReadyProbe;

    #[async_trait]
    impl HealthProbe for ReadyProbe {
        async fn is_ready(&self) -> bool {
            true
        }
    }

    fn test_app() -> (Router, Arc<MemoryRepository>) {
        let repository = Arc::new(MemoryRepository::default());
        let config = Arc::new(PublicConfig {
            service_name: "sentinel-api",
            environment: AppEnvironment::Ci,
            app_origin: "https://sentinel.example".to_owned(),
            websocket_origins: vec!["https://sentinel.example".to_owned()],
            session_idle_ttl: Duration::from_secs(1800),
            session_absolute_ttl: Duration::from_secs(720 * 3600),
            csrf_ttl: Duration::from_secs(1800),
            session_touch_interval: Duration::from_secs(300),
            qr_challenge_ttl: Duration::from_secs(90),
            qr_approval_ttl: Duration::from_secs(90),
            qr_continuation_ttl: Duration::from_secs(300),
        });
        let fingerprints = FingerprintKeyRing::new([("test".to_owned(), vec![4; 32])]).unwrap();
        let auth = Arc::new(
            AuthService::new(
                repository.clone(),
                Arc::new(TestPasswordHasher),
                Arc::new(InMemoryRateLimiter::default()),
                fingerprints.clone(),
                config.clone(),
            )
            .unwrap(),
        );
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://sentinel:secret@127.0.0.1:1/sentinel")
            .unwrap();
        (
            build_router(AppState::new(
                pool.clone(),
                config.clone(),
                Arc::new(ReadyProbe),
                auth,
                Arc::new(crate::qr::QrService::new(
                    pool,
                    fingerprints,
                    Arc::new(InMemoryRateLimiter::default()),
                    config.environment,
                )),
            )),
            repository,
        )
    }

    fn auth_request(method: &str, uri: &str, body: &str) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::ORIGIN, "https://sentinel.example")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap();
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
        ));
        request
    }

    async fn response_body(response: Response) -> String {
        String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn registration_normalizes_email_rejects_duplicate_and_blocked_password() {
        let (app, _) = test_app();
        let valid = r#"{"email":" Person@Example.COM ","password":"uma frase longa e exclusiva"}"#;
        let response = app
            .clone()
            .oneshot(auth_request("POST", "/v1/auth/register", valid))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert!(response_body(response).await.contains("person@example.com"));

        let duplicate = app
            .clone()
            .oneshot(auth_request("POST", "/v1/auth/register", valid))
            .await
            .unwrap();
        assert_eq!(duplicate.status(), StatusCode::CONFLICT);

        let blocked = r#"{"email":"other@example.com","password":"passwordpassword"}"#;
        let response = app
            .oneshot(auth_request("POST", "/v1/auth/register", blocked))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response_body(response).await.contains("PASSWORD_BLOCKED"));
    }

    #[tokio::test]
    async fn wrong_password_and_unknown_account_have_equivalent_external_response() {
        let (app, _) = test_app();
        let registration =
            r#"{"email":"person@example.com","password":"uma frase longa e exclusiva"}"#;
        app.clone()
            .oneshot(auth_request("POST", "/v1/auth/register", registration))
            .await
            .unwrap();

        let wrong = r#"{"email":"person@example.com","password":"senha incorreta longa"}"#;
        let unknown = r#"{"email":"unknown@example.com","password":"senha incorreta longa"}"#;
        let wrong_response = app
            .clone()
            .oneshot(auth_request("POST", "/v1/auth/login", wrong))
            .await
            .unwrap();
        let unknown_response = app
            .oneshot(auth_request("POST", "/v1/auth/login", unknown))
            .await
            .unwrap();
        assert_eq!(wrong_response.status(), unknown_response.status());
        let wrong_body: serde_json::Value =
            serde_json::from_str(&response_body(wrong_response).await).unwrap();
        let unknown_body: serde_json::Value =
            serde_json::from_str(&response_body(unknown_response).await).unwrap();
        for field in ["status", "code", "title"] {
            assert_eq!(wrong_body[field], unknown_body[field]);
        }
    }

    #[tokio::test]
    async fn login_me_csrf_and_logout_enforce_server_side_session() {
        let (app, _) = test_app();
        let credentials =
            r#"{"email":"person@example.com","password":"uma frase longa e exclusiva"}"#;
        app.clone()
            .oneshot(auth_request("POST", "/v1/auth/register", credentials))
            .await
            .unwrap();
        let login = app
            .clone()
            .oneshot(auth_request("POST", "/v1/auth/login", credentials))
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let set_cookie = login.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .to_owned();
        assert!(set_cookie.contains("Secure; HttpOnly; SameSite=Lax"));
        let cookie = set_cookie.split(';').next().unwrap();

        let me_request = Request::builder()
            .uri("/v1/auth/me")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap();
        let me = app.clone().oneshot(me_request).await.unwrap();
        assert_eq!(me.status(), StatusCode::OK);

        let csrf_request = Request::builder()
            .uri("/v1/auth/csrf")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap();
        let csrf_response = app.clone().oneshot(csrf_request).await.unwrap();
        let csrf_json: serde_json::Value =
            serde_json::from_str(&response_body(csrf_response).await).unwrap();
        let csrf_token = csrf_json["csrf_token"].as_str().unwrap();

        let missing_csrf = auth_request("POST", "/v1/auth/logout", "");
        let mut missing_csrf = missing_csrf;
        missing_csrf
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
        assert_eq!(
            app.clone().oneshot(missing_csrf).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        let mut logout = auth_request("POST", "/v1/auth/logout", "");
        logout
            .headers_mut()
            .insert(header::COOKIE, HeaderValue::from_str(cookie).unwrap());
        logout
            .headers_mut()
            .insert("x-csrf-token", HeaderValue::from_str(csrf_token).unwrap());
        let logout_response = app.clone().oneshot(logout).await.unwrap();
        assert_eq!(logout_response.status(), StatusCode::NO_CONTENT);
        assert!(
            logout_response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Max-Age=0")
        );

        let me_request = Request::builder()
            .uri("/v1/auth/me")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(me_request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn login_rate_limit_blocks_sixth_attempt_and_registration_is_atomic() {
        let (app, repository) = test_app();
        for attempt in 0..6 {
            let body = r#"{"email":"unknown@example.com","password":"senha incorreta longa"}"#;
            let response = app
                .clone()
                .oneshot(auth_request("POST", "/v1/auth/login", body))
                .await
                .unwrap();
            let expected = if attempt < 5 {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::TOO_MANY_REQUESTS
            };
            assert_eq!(response.status(), expected);
        }

        let email = NormalizedEmail::parse("race@example.com").unwrap();
        let first =
            repository.create_user_with_password(Uuid::now_v7(), &email, "hash", SystemTime::now());
        let second =
            repository.create_user_with_password(Uuid::now_v7(), &email, "hash", SystemTime::now());
        let (first, second) = tokio::join!(first, second);
        assert_eq!(
            [first.is_ok(), second.is_ok()]
                .into_iter()
                .filter(|ok| *ok)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn registration_rate_limit_blocks_fourth_attempt_for_same_account_and_network() {
        let (app, _) = test_app();
        let body = r#"{"email":"limited@example.com","password":"uma frase longa e exclusiva"}"#;
        for attempt in 0..4 {
            let response = app
                .clone()
                .oneshot(auth_request("POST", "/v1/auth/register", body))
                .await
                .unwrap();
            let expected = match attempt {
                0 => StatusCode::CREATED,
                1 | 2 => StatusCode::CONFLICT,
                _ => StatusCode::TOO_MANY_REQUESTS,
            };
            assert_eq!(response.status(), expected);
        }
    }

    #[tokio::test]
    async fn login_rotates_existing_session_and_invalidates_old_cookie() {
        let (app, _) = test_app();
        let credentials =
            r#"{"email":"person@example.com","password":"uma frase longa e exclusiva"}"#;
        app.clone()
            .oneshot(auth_request("POST", "/v1/auth/register", credentials))
            .await
            .unwrap();
        let first = app
            .clone()
            .oneshot(auth_request("POST", "/v1/auth/login", credentials))
            .await
            .unwrap();
        let first_cookie = first.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        let mut second_request = auth_request("POST", "/v1/auth/login", credentials);
        second_request.headers_mut().insert(
            header::COOKIE,
            HeaderValue::from_str(&first_cookie).unwrap(),
        );
        let second = app.clone().oneshot(second_request).await.unwrap();
        let second_cookie = second.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        assert_ne!(first_cookie, second_cookie);

        let old_me = Request::builder()
            .uri("/v1/auth/me")
            .header(header::COOKIE, first_cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(old_me).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        let new_me = Request::builder()
            .uri("/v1/auth/me")
            .header(header::COOKIE, second_cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.oneshot(new_me).await.unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn idle_and_absolute_expiration_fail_closed() {
        let (app, repository) = test_app();
        let credentials =
            r#"{"email":"person@example.com","password":"uma frase longa e exclusiva"}"#;
        app.clone()
            .oneshot(auth_request("POST", "/v1/auth/register", credentials))
            .await
            .unwrap();
        let login = app
            .clone()
            .oneshot(auth_request("POST", "/v1/auth/login", credentials))
            .await
            .unwrap();
        let cookie = login.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();

        {
            let mut state = repository.state.lock().unwrap();
            let session = state.sessions.values_mut().next().unwrap();
            session.session.idle_expires_at = SystemTime::UNIX_EPOCH;
        }
        let request = Request::builder()
            .uri("/v1/auth/me")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );

        {
            let mut state = repository.state.lock().unwrap();
            let session = state.sessions.values_mut().next().unwrap();
            session.session.idle_expires_at = SystemTime::now() + Duration::from_secs(60);
            session.session.absolute_expires_at = SystemTime::UNIX_EPOCH;
        }
        let request = Request::builder()
            .uri("/v1/auth/me")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
