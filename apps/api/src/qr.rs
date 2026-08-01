use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum::{
    Json,
    extract::{
        ConnectInfo, Path, State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use sentinel_api_contract::{
    ExchangeRequest, QrBootstrapRequest, QrChallengeCreated, QrChallengeDetails, QrCodeRequest,
    QrScanResponse, QrStatusResponse, QrTransitionRequest, SubscriptionRequest,
};
use sentinel_application::auth::{NewSession, SessionIdentity};
use sentinel_application::{RateLimitKey, RateLimitOperation, RateLimitPolicy, RateLimiter};
use sentinel_infrastructure::security::{FingerprintKeyRing, SystemTokenGenerator};
use serde::Deserialize;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{
    AppState, CorrelationId,
    error::ApiError,
    security::{AuditCategory, AuditEvent, AuditOutcome, HostCookieBuilder},
};

const QR_CONTEXT: &[u8] = b"qr-token";
const SUBSCRIPTION_CONTEXT: &[u8] = b"qr-subscription";
const CONTINUATION_CONTEXT: &[u8] = b"qr-continuation";
const SESSION_CONTEXT: &[u8] = b"session";
const CODE_ATTEMPT_LIMIT: i16 = 5;

pub struct QrService {
    pool: PgPool,
    fingerprints: FingerprintKeyRing,
    rate_limiter: Arc<dyn RateLimiter>,
    tokens: SystemTokenGenerator,
    cookies: HostCookieBuilder,
}

impl QrService {
    pub fn new(
        pool: PgPool,
        fingerprints: FingerprintKeyRing,
        rate_limiter: Arc<dyn RateLimiter>,
        environment: crate::config::AppEnvironment,
    ) -> Self {
        Self {
            pool,
            fingerprints,
            rate_limiter,
            tokens: SystemTokenGenerator,
            cookies: HostCookieBuilder::new(environment),
        }
    }

    async fn allow(
        &self,
        operation: RateLimitOperation,
        key: RateLimitKey,
        limit: u32,
        window: Duration,
    ) -> bool {
        self.rate_limiter
            .check(
                operation,
                &key,
                RateLimitPolicy { limit, window },
                SystemTime::now(),
            )
            .await
            .allowed
    }

    async fn authorize_subscription(
        &self,
        challenge_id: Uuid,
        token: &str,
    ) -> Result<QrStatusResponse, QrFailure> {
        for candidate in self.fingerprints.candidates(SUBSCRIPTION_CONTEXT, token) {
            let row = sqlx::query("SELECT status::text AS status, lock_version, qr_expires_at, approval_expires_at FROM qr_login_challenges WHERE id = $1 AND subscription_key_id = $2 AND subscription_fingerprint = $3")
                .bind(challenge_id)
                .bind(candidate.key_id())
                .bind(candidate.digest().as_slice())
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| QrFailure::Unavailable)?;
            if let Some(row) = row {
                return Ok(status_from_row(challenge_id, &row));
            }
        }
        Err(QrFailure::NotFound)
    }

    async fn expire_if_needed(
        &self,
        challenge_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(), QrFailure> {
        sqlx::query("UPDATE qr_login_challenges SET status = 'EXPIRED', terminal_at = $2, lock_version = lock_version + 1, qr_token_fingerprint = NULL, verification_code_hash = NULL WHERE id = $1 AND ((status IN ('CREATED', 'SCANNED') AND qr_expires_at <= $2) OR (status = 'APPROVED' AND approval_expires_at <= $2))")
            .bind(challenge_id)
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(|_| QrFailure::Unavailable)?;
        Ok(())
    }

    pub async fn cleanup_retained(
        &self,
        continuation_before: DateTime<Utc>,
        challenge_before: DateTime<Utc>,
    ) -> Result<(u64, u64), sqlx::Error> {
        let continuations = sqlx::query(
            "DELETE FROM qr_scan_continuations WHERE expires_at < $1 OR consumed_at < $1",
        )
        .bind(continuation_before)
        .execute(&self.pool)
        .await?
        .rows_affected();
        let challenges = sqlx::query("DELETE FROM qr_login_challenges WHERE terminal_at < $1 AND NOT EXISTS (SELECT 1 FROM sessions WHERE source_challenge_id = qr_login_challenges.id)")
            .bind(challenge_before).execute(&self.pool).await?.rows_affected();
        Ok((continuations, challenges))
    }
}

#[derive(Debug, Clone, Copy)]
enum QrFailure {
    NotFound,
    Gone,
    Conflict,
    Forbidden,
    RateLimited,
    Unavailable,
}

fn api_error(failure: QrFailure, correlation_id: CorrelationId) -> ApiError {
    match failure {
        QrFailure::NotFound => ApiError::not_found(correlation_id),
        QrFailure::Gone => {
            ApiError::gone("QR_CHALLENGE_EXPIRED", "Challenge expirado", correlation_id)
        }
        QrFailure::Conflict => ApiError::conflict(
            "QR_CHALLENGE_STATE_CONFLICT",
            "Estado incompatível",
            correlation_id,
        ),
        QrFailure::Forbidden => ApiError::csrf_rejected(correlation_id),
        QrFailure::RateLimited => ApiError::too_many_requests(correlation_id),
        QrFailure::Unavailable => ApiError::internal(correlation_id),
    }
}

pub async fn create_challenge(
    State(state): State<AppState>,
    correlation: axum::Extension<CorrelationId>,
    ConnectInfo(client): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<QrChallengeCreated>), ApiError> {
    if !state
        .qr
        .allow(
            RateLimitOperation::CreateQrChallenge,
            RateLimitKey::composite(&[&client.ip().to_string()]),
            10,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(api_error(QrFailure::RateLimited, correlation.0));
    }
    let id = Uuid::now_v7();
    let qr_token = state
        .qr
        .tokens
        .generate()
        .map_err(|_| ApiError::internal(correlation.0))?;
    let subscription = state
        .qr
        .tokens
        .generate()
        .map_err(|_| ApiError::internal(correlation.0))?;
    let verification_code = random_code().map_err(|_| ApiError::internal(correlation.0))?;
    let qr_fingerprint = state
        .qr
        .fingerprints
        .fingerprint(QR_CONTEXT, qr_token.expose());
    let subscription_fingerprint = state
        .qr
        .fingerprints
        .fingerprint(SUBSCRIPTION_CONTEXT, subscription.expose());
    let code_context = code_context(id);
    let code_fingerprint = state
        .qr
        .fingerprints
        .fingerprint(code_context.as_bytes(), &verification_code);
    let now = Utc::now();
    let expires_at = now + chrono::Duration::from_std(state.config.qr_challenge_ttl).unwrap();
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(summarize_user_agent);
    sqlx::query("INSERT INTO qr_login_challenges (id, qr_token_fingerprint, qr_token_key_id, subscription_fingerprint, subscription_key_id, verification_code_hash, verification_code_key_id, requested_ua_summary, requested_ip, qr_expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::inet,$10,$11)")
        .bind(id).bind(qr_fingerprint.digest().as_slice()).bind(qr_fingerprint.key_id())
        .bind(subscription_fingerprint.digest().as_slice()).bind(subscription_fingerprint.key_id())
        .bind(code_fingerprint.digest().as_slice()).bind(code_fingerprint.key_id())
        .bind(user_agent).bind(client.ip().to_string()).bind(expires_at).bind(now)
        .execute(&state.pool).await.map_err(|_| ApiError::internal(correlation.0))?;
    audit("qr.created", AuditOutcome::Succeeded, correlation.0, id).write_log();
    Ok((
        StatusCode::CREATED,
        Json(QrChallengeCreated {
            challenge_id: id,
            qr_payload: format!(
                "{}/qr/scan#token={}",
                state.config.app_origin,
                qr_token.expose()
            ),
            subscription_token: subscription.expose().to_owned(),
            verification_code,
            qr_expires_at: expires_at,
            poll_after_ms: 1500,
        }),
    ))
}

pub async fn bootstrap(
    State(state): State<AppState>,
    correlation: axum::Extension<CorrelationId>,
    ConnectInfo(client): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<QrBootstrapRequest>,
) -> Result<Response, ApiError> {
    state.auth.validate_mutation(&headers, correlation.0)?;
    if !state
        .qr
        .allow(
            RateLimitOperation::BootstrapQr,
            RateLimitKey::composite(&[&client.ip().to_string()]),
            20,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(api_error(QrFailure::RateLimited, correlation.0));
    }
    let now = Utc::now();
    let mut challenge_id = None;
    for candidate in state
        .qr
        .fingerprints
        .candidates(QR_CONTEXT, &request.qr_token)
    {
        challenge_id = sqlx::query_scalar::<_, Uuid>("SELECT id FROM qr_login_challenges WHERE status = 'CREATED' AND qr_expires_at > $1 AND qr_token_key_id = $2 AND qr_token_fingerprint = $3")
            .bind(now).bind(candidate.key_id()).bind(candidate.digest().as_slice())
            .fetch_optional(&state.pool).await.map_err(|_| ApiError::internal(correlation.0))?;
        if challenge_id.is_some() {
            break;
        }
    }
    let challenge_id = challenge_id.ok_or_else(|| api_error(QrFailure::Gone, correlation.0))?;
    let token = state
        .qr
        .tokens
        .generate()
        .map_err(|_| ApiError::internal(correlation.0))?;
    let fingerprint = state
        .qr
        .fingerprints
        .fingerprint(CONTINUATION_CONTEXT, token.expose());
    let expires_at = now + chrono::Duration::from_std(state.config.qr_continuation_ttl).unwrap();
    sqlx::query("INSERT INTO qr_scan_continuations (id, challenge_id, token_fingerprint, token_fingerprint_key_id, expires_at, created_at) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(Uuid::now_v7()).bind(challenge_id).bind(fingerprint.digest().as_slice()).bind(fingerprint.key_id()).bind(expires_at).bind(now)
        .execute(&state.pool).await.map_err(|_| ApiError::internal(correlation.0))?;
    let cookie = state
        .qr
        .cookies
        .qr_continuation(token.expose(), state.config.qr_continuation_ttl)
        .map_err(|_| ApiError::internal(correlation.0))?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    audit(
        "qr.bootstrapped",
        AuditOutcome::Succeeded,
        correlation.0,
        challenge_id,
    )
    .write_log();
    Ok(response)
}

pub async fn scan(
    State(state): State<AppState>,
    correlation: axum::Extension<CorrelationId>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let now_system = SystemTime::now();
    state.auth.validate_mutation(&headers, correlation.0)?;
    let identity = state
        .auth
        .authenticate(&headers, now_system)
        .await
        .map_err(|_| ApiError::unauthorized(correlation.0))?;
    if !state
        .qr
        .allow(
            RateLimitOperation::BootstrapQr,
            RateLimitKey::composite(&[&identity.session_id.to_string()]),
            20,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(api_error(QrFailure::RateLimited, correlation.0));
    }
    if !state
        .auth
        .verify_session_csrf(&identity, &headers, now_system)
    {
        return Err(api_error(QrFailure::Forbidden, correlation.0));
    }
    let continuation = cookie(&headers, "__Host-qr-cont")
        .ok_or_else(|| api_error(QrFailure::Gone, correlation.0))?;
    let now = Utc::now();
    let mut transaction = state
        .pool
        .begin()
        .await
        .map_err(|_| ApiError::internal(correlation.0))?;
    let mut challenge_id = None;
    for candidate in state
        .qr
        .fingerprints
        .candidates(CONTINUATION_CONTEXT, continuation)
    {
        challenge_id = sqlx::query_scalar::<_, Uuid>("SELECT challenge_id FROM qr_scan_continuations WHERE consumed_at IS NULL AND expires_at > $1 AND token_fingerprint_key_id = $2 AND token_fingerprint = $3 FOR UPDATE")
            .bind(now).bind(candidate.key_id()).bind(candidate.digest().as_slice()).fetch_optional(&mut *transaction).await.map_err(|_| ApiError::internal(correlation.0))?;
        if challenge_id.is_some() {
            break;
        }
    }
    let challenge_id = challenge_id.ok_or_else(|| api_error(QrFailure::Gone, correlation.0))?;
    let row = sqlx::query("UPDATE qr_login_challenges SET status='SCANNED', scanner_user_id=$2, scanner_session_id=$3, scanned_at=$4, lock_version=lock_version+1, qr_token_fingerprint=NULL WHERE id=$1 AND status='CREATED' AND qr_expires_at>$4 RETURNING lock_version")
        .bind(challenge_id).bind(identity.user_id).bind(identity.session_id).bind(now)
        .fetch_optional(&mut *transaction).await.map_err(|_| ApiError::internal(correlation.0))?
        .ok_or_else(|| api_error(QrFailure::Conflict, correlation.0))?;
    sqlx::query("UPDATE qr_scan_continuations SET consumed_at=$2 WHERE challenge_id=$1 AND consumed_at IS NULL")
        .bind(challenge_id).bind(now).execute(&mut *transaction).await.map_err(|_| ApiError::internal(correlation.0))?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal(correlation.0))?;
    let mut response = (
        StatusCode::OK,
        Json(QrScanResponse {
            challenge_id,
            lock_version: row.get("lock_version"),
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, state.qr.cookies.clear_qr_continuation());
    audit(
        "qr.scanned",
        AuditOutcome::Succeeded,
        correlation.0,
        challenge_id,
    )
    .user(identity.user_id)
    .session(identity.session_id)
    .write_log();
    Ok(response)
}

pub async fn details(
    State(state): State<AppState>,
    correlation: axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<QrChallengeDetails>, ApiError> {
    let identity = state
        .auth
        .authenticate(&headers, SystemTime::now())
        .await
        .map_err(|_| ApiError::not_found(correlation.0))?;
    state
        .qr
        .expire_if_needed(id, Utc::now())
        .await
        .map_err(|e| api_error(e, correlation.0))?;
    let row = sqlx::query("SELECT status::text AS status, lock_version, requested_ua_summary, host(requested_ip) AS requested_ip, created_at, qr_expires_at, code_verified_at IS NOT NULL AS code_verified FROM qr_login_challenges WHERE id=$1 AND scanner_user_id=$2 AND scanner_session_id=$3 AND status IN ('SCANNED','APPROVED') AND qr_expires_at>now()")
        .bind(id).bind(identity.user_id).bind(identity.session_id).fetch_optional(&state.pool).await.map_err(|_| ApiError::internal(correlation.0))?
        .ok_or_else(|| ApiError::not_found(correlation.0))?;
    Ok(Json(QrChallengeDetails {
        challenge_id: id,
        status: row.get("status"),
        lock_version: row.get("lock_version"),
        requested_ua_summary: row.get("requested_ua_summary"),
        requested_ip: row.get("requested_ip"),
        created_at: row.get("created_at"),
        qr_expires_at: row.get("qr_expires_at"),
        code_verified: row.get("code_verified"),
    }))
}

pub async fn verify_code(
    State(state): State<AppState>,
    correlation: axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<QrCodeRequest>,
) -> Result<Json<QrScanResponse>, ApiError> {
    let identity = scanner_mutation(&state, &headers, correlation.0).await?;
    if !state
        .qr
        .allow(
            RateLimitOperation::VerifyQrCode,
            RateLimitKey::composite(&[&id.to_string()]),
            5,
            Duration::from_secs(300),
        )
        .await
    {
        return Err(api_error(QrFailure::RateLimited, correlation.0));
    }
    let mut transaction = state
        .pool
        .begin()
        .await
        .map_err(|_| ApiError::internal(correlation.0))?;
    let row = sqlx::query("SELECT verification_code_hash, verification_code_key_id, verification_attempts, lock_version, qr_expires_at FROM qr_login_challenges WHERE id=$1 AND status='SCANNED' AND scanner_user_id=$2 AND scanner_session_id=$3 FOR UPDATE")
        .bind(id).bind(identity.user_id).bind(identity.session_id).fetch_optional(&mut *transaction).await.map_err(|_| ApiError::internal(correlation.0))?.ok_or_else(|| ApiError::not_found(correlation.0))?;
    if row.get::<DateTime<Utc>, _>("qr_expires_at") <= Utc::now() {
        return Err(api_error(QrFailure::Gone, correlation.0));
    }
    if row.get::<i32, _>("lock_version") != request.lock_version {
        return Err(api_error(QrFailure::Conflict, correlation.0));
    }
    let expected: Vec<u8> = row.get("verification_code_hash");
    let key_id: String = row.get("verification_code_key_id");
    let supplied = state
        .qr
        .fingerprints
        .candidates(code_context(id).as_bytes(), &request.verification_code)
        .into_iter()
        .find(|candidate| candidate.key_id() == key_id)
        .is_some_and(|candidate| candidate.digest().as_slice() == expected);
    let attempts: i16 = row.get("verification_attempts");
    let next_attempt = attempts + 1;
    if !supplied {
        let cancelled = next_attempt >= CODE_ATTEMPT_LIMIT;
        sqlx::query("UPDATE qr_login_challenges SET verification_attempts=$2, status=CASE WHEN $3 THEN 'CANCELLED'::qr_challenge_status ELSE status END, terminal_at=CASE WHEN $3 THEN now() ELSE terminal_at END, lock_version=lock_version+1 WHERE id=$1")
            .bind(id).bind(next_attempt).bind(cancelled).execute(&mut *transaction).await.map_err(|_| ApiError::internal(correlation.0))?;
        transaction
            .commit()
            .await
            .map_err(|_| ApiError::internal(correlation.0))?;
        audit("qr.code.failed", AuditOutcome::Failed, correlation.0, id)
            .attempt_count(next_attempt as u32)
            .write_log();
        return Err(if cancelled {
            api_error(QrFailure::RateLimited, correlation.0)
        } else {
            api_error(QrFailure::Forbidden, correlation.0)
        });
    }
    let new_version: i32 = sqlx::query_scalar("UPDATE qr_login_challenges SET code_verified_at=now(), lock_version=lock_version+1 WHERE id=$1 RETURNING lock_version")
        .bind(id).fetch_one(&mut *transaction).await.map_err(|_| ApiError::internal(correlation.0))?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal(correlation.0))?;
    Ok(Json(QrScanResponse {
        challenge_id: id,
        lock_version: new_version,
    }))
}

pub async fn approve(
    State(state): State<AppState>,
    correlation: axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<QrTransitionRequest>,
) -> Result<Json<QrStatusResponse>, ApiError> {
    let identity = scanner_mutation(&state, &headers, correlation.0).await?;
    transition_scanner(
        &state,
        correlation.0,
        id,
        identity,
        request.lock_version,
        "APPROVED",
    )
    .await
}

pub async fn reject(
    State(state): State<AppState>,
    correlation: axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<QrTransitionRequest>,
) -> Result<Json<QrStatusResponse>, ApiError> {
    let identity = scanner_mutation(&state, &headers, correlation.0).await?;
    transition_scanner(
        &state,
        correlation.0,
        id,
        identity,
        request.lock_version,
        "REJECTED",
    )
    .await
}

async fn transition_scanner(
    state: &AppState,
    correlation: CorrelationId,
    id: Uuid,
    identity: SessionIdentity,
    version: i32,
    target: &str,
) -> Result<Json<QrStatusResponse>, ApiError> {
    let now = Utc::now();
    let approval_expires = now + chrono::Duration::from_std(state.config.qr_approval_ttl).unwrap();
    let row = if target == "APPROVED" {
        sqlx::query("UPDATE qr_login_challenges SET status='APPROVED', approved_at=$5, approval_expires_at=$6, lock_version=lock_version+1 WHERE id=$1 AND status='SCANNED' AND lock_version=$2 AND scanner_user_id=$3 AND scanner_session_id=$4 AND code_verified_at IS NOT NULL AND qr_expires_at>$5 RETURNING status::text AS status,lock_version,qr_expires_at,approval_expires_at")
            .bind(id).bind(version).bind(identity.user_id).bind(identity.session_id).bind(now).bind(approval_expires).fetch_optional(&state.pool).await
    } else {
        sqlx::query("UPDATE qr_login_challenges SET status='REJECTED', terminal_at=$5, lock_version=lock_version+1,qr_token_fingerprint=NULL,verification_code_hash=NULL WHERE id=$1 AND status='SCANNED' AND lock_version=$2 AND scanner_user_id=$3 AND scanner_session_id=$4 AND qr_expires_at>$5 RETURNING status::text AS status,lock_version,qr_expires_at,approval_expires_at")
            .bind(id).bind(version).bind(identity.user_id).bind(identity.session_id).bind(now).fetch_optional(&state.pool).await
    }.map_err(|_| ApiError::internal(correlation))?.ok_or_else(|| api_error(QrFailure::Conflict, correlation))?;
    audit(
        if target == "APPROVED" {
            "qr.approved"
        } else {
            "qr.rejected"
        },
        AuditOutcome::Succeeded,
        correlation,
        id,
    )
    .user(identity.user_id)
    .session(identity.session_id)
    .write_log();
    Ok(Json(status_from_row(id, &row)))
}

pub async fn status(
    State(state): State<AppState>,
    correlation: axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<QrStatusResponse>, ApiError> {
    let token = bearer(&headers).ok_or_else(|| ApiError::not_found(correlation.0))?;
    if !state
        .qr
        .allow(
            RateLimitOperation::PollQr,
            RateLimitKey::composite(&[&id.to_string()]),
            1,
            Duration::from_secs(1),
        )
        .await
    {
        return Err(api_error(QrFailure::RateLimited, correlation.0));
    }
    state
        .qr
        .expire_if_needed(id, Utc::now())
        .await
        .map_err(|e| api_error(e, correlation.0))?;
    state
        .qr
        .authorize_subscription(id, token)
        .await
        .map(Json)
        .map_err(|e| api_error(e, correlation.0))
}

pub async fn cancel(
    State(state): State<AppState>,
    correlation: axum::Extension<CorrelationId>,
    Path(id): Path<Uuid>,
    Json(request): Json<SubscriptionRequest>,
) -> Result<StatusCode, ApiError> {
    state
        .qr
        .authorize_subscription(id, &request.subscription_token)
        .await
        .map_err(|e| api_error(e, correlation.0))?;
    let changed = sqlx::query("UPDATE qr_login_challenges SET status='CANCELLED',terminal_at=now(),lock_version=lock_version+1,qr_token_fingerprint=NULL,verification_code_hash=NULL WHERE id=$1 AND status IN ('CREATED','SCANNED','APPROVED')")
        .bind(id).execute(&state.pool).await.map_err(|_| ApiError::internal(correlation.0))?.rows_affected();
    if changed == 0 {
        return Err(api_error(QrFailure::Conflict, correlation.0));
    }
    Ok(StatusCode::NO_CONTENT)
}

pub async fn exchange(
    State(state): State<AppState>,
    correlation: axum::Extension<CorrelationId>,
    ConnectInfo(client): ConnectInfo<SocketAddr>,
    Json(request): Json<ExchangeRequest>,
) -> Result<Response, ApiError> {
    if !state
        .qr
        .allow(
            RateLimitOperation::ExchangeQr,
            RateLimitKey::composite(&[&request.challenge_id.to_string(), &client.ip().to_string()]),
            10,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(api_error(QrFailure::RateLimited, correlation.0));
    }
    let token = state
        .qr
        .tokens
        .generate()
        .map_err(|_| ApiError::internal(correlation.0))?;
    let session_fingerprint = state
        .qr
        .fingerprints
        .fingerprint(SESSION_CONTEXT, token.expose());
    let now = Utc::now();
    let mut transaction = state
        .pool
        .begin()
        .await
        .map_err(|_| ApiError::internal(correlation.0))?;
    let row = sqlx::query("SELECT status::text AS status,scanner_user_id,approval_expires_at,subscription_key_id,subscription_fingerprint FROM qr_login_challenges WHERE id=$1 FOR UPDATE")
        .bind(request.challenge_id).fetch_optional(&mut *transaction).await.map_err(|_| ApiError::internal(correlation.0))?.ok_or_else(|| ApiError::not_found(correlation.0))?;
    let valid_token = row
        .get::<Option<String>, _>("subscription_key_id")
        .zip(row.get::<Option<Vec<u8>>, _>("subscription_fingerprint"))
        .is_some_and(|(key, expected)| {
            state
                .qr
                .fingerprints
                .candidates(SUBSCRIPTION_CONTEXT, &request.subscription_token)
                .into_iter()
                .any(|candidate| {
                    candidate.key_id() == key && candidate.digest().as_slice() == expected
                })
        });
    if !valid_token {
        return Err(ApiError::not_found(correlation.0));
    }
    if row.get::<String, _>("status") != "APPROVED" {
        return Err(api_error(QrFailure::Conflict, correlation.0));
    }
    if row
        .get::<Option<DateTime<Utc>>, _>("approval_expires_at")
        .is_none_or(|expiry| expiry <= now)
    {
        return Err(api_error(QrFailure::Gone, correlation.0));
    }
    let user_id: Uuid = row
        .get::<Option<Uuid>, _>("scanner_user_id")
        .ok_or_else(|| ApiError::internal(correlation.0))?;
    let session_id = Uuid::now_v7();
    let session = NewSession {
        id: session_id,
        user_id,
        token_fingerprint: session_fingerprint.digest().to_vec(),
        token_key_id: session_fingerprint.key_id().to_owned(),
        last_seen_at: SystemTime::now(),
        idle_expires_at: SystemTime::now() + state.config.session_idle_ttl,
        absolute_expires_at: SystemTime::now() + state.config.session_absolute_ttl,
    };
    sqlx::query("INSERT INTO sessions (id,user_id,token_fingerprint,token_fingerprint_key_id,auth_method,source_challenge_id,last_seen_at,idle_expires_at,absolute_expires_at,created_at,ip_address) VALUES ($1,$2,$3,$4,'qr',$5,$6,$7,$8,$6,$9::inet)")
        .bind(session.id).bind(session.user_id).bind(&session.token_fingerprint).bind(&session.token_key_id).bind(request.challenge_id).bind(DateTime::<Utc>::from(session.last_seen_at)).bind(DateTime::<Utc>::from(session.idle_expires_at)).bind(DateTime::<Utc>::from(session.absolute_expires_at)).bind(client.ip().to_string())
        .execute(&mut *transaction).await.map_err(|_| api_error(QrFailure::Conflict, correlation.0))?;
    sqlx::query("UPDATE qr_login_challenges SET status='EXCHANGED',terminal_at=$2,lock_version=lock_version+1,qr_token_fingerprint=NULL,verification_code_hash=NULL WHERE id=$1 AND status='APPROVED'")
        .bind(request.challenge_id).bind(now).execute(&mut *transaction).await.map_err(|_| ApiError::internal(correlation.0))?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::internal(correlation.0))?;
    let cookie = state
        .qr
        .cookies
        .session(token.expose(), state.config.session_absolute_ttl)
        .map_err(|_| ApiError::internal(correlation.0))?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    audit(
        "qr.exchanged",
        AuditOutcome::Succeeded,
        correlation.0,
        request.challenge_id,
    )
    .user(user_id)
    .session(session_id)
    .write_log();
    Ok(response)
}

#[derive(Deserialize)]
struct SubscribeMessage {
    #[serde(rename = "type")]
    message_type: String,
    challenge_id: Uuid,
    subscription_token: String,
    #[allow(dead_code)]
    last_seen_version: Option<i32>,
}

pub async fn websocket(
    State(state): State<AppState>,
    correlation: axum::Extension<CorrelationId>,
    ConnectInfo(client): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    if !state.auth.validate_websocket(&headers) {
        return Err(ApiError::bad_request(
            "INVALID_ORIGIN",
            "Origem inválida",
            correlation.0,
        ));
    }
    if !state
        .qr
        .allow(
            RateLimitOperation::WebSocket,
            RateLimitKey::composite(&[&client.ip().to_string()]),
            5,
            Duration::from_secs(60),
        )
        .await
    {
        return Err(api_error(QrFailure::RateLimited, correlation.0));
    }
    Ok(upgrade
        .max_message_size(4096)
        .on_upgrade(move |socket| websocket_session(socket, state))
        .into_response())
}

async fn websocket_session(mut socket: WebSocket, state: AppState) {
    let subscribe = tokio::time::timeout(Duration::from_secs(5), socket.recv())
        .await
        .ok()
        .flatten()
        .and_then(Result::ok)
        .and_then(|message| match message {
            Message::Text(text) => serde_json::from_str::<SubscribeMessage>(&text).ok(),
            _ => None,
        });
    let Some(subscribe) = subscribe.filter(|message| message.message_type == "subscribe") else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    let Ok(mut snapshot) = state
        .qr
        .authorize_subscription(subscribe.challenge_id, &subscribe.subscription_token)
        .await
    else {
        let _ = socket.send(Message::Close(None)).await;
        return;
    };
    if send_snapshot(&mut socket, &snapshot).await.is_err() {
        return;
    }
    let mut interval = tokio::time::interval(Duration::from_millis(750));
    loop {
        interval.tick().await;
        if state
            .qr
            .expire_if_needed(subscribe.challenge_id, Utc::now())
            .await
            .is_err()
        {
            break;
        }
        let Ok(current) = state
            .qr
            .authorize_subscription(subscribe.challenge_id, &subscribe.subscription_token)
            .await
        else {
            break;
        };
        if current.lock_version != snapshot.lock_version {
            if send_snapshot(&mut socket, &current).await.is_err() {
                break;
            }
            snapshot = current;
        }
        if matches!(
            snapshot.status.as_str(),
            "EXCHANGED" | "REJECTED" | "EXPIRED" | "CANCELLED"
        ) {
            break;
        }
    }
    let _ = socket.send(Message::Close(None)).await;
}

async fn send_snapshot(
    socket: &mut WebSocket,
    snapshot: &QrStatusResponse,
) -> Result<(), axum::Error> {
    let value = serde_json::json!({"type":"qr.snapshot","challenge_id":snapshot.challenge_id,"status":snapshot.status,"version":snapshot.lock_version,"qr_expires_at":snapshot.qr_expires_at,"approval_expires_at":snapshot.approval_expires_at});
    socket.send(Message::Text(value.to_string().into())).await
}

async fn scanner_mutation(
    state: &AppState,
    headers: &HeaderMap,
    correlation: CorrelationId,
) -> Result<SessionIdentity, ApiError> {
    let now = SystemTime::now();
    state.auth.validate_mutation(headers, correlation)?;
    let identity = state
        .auth
        .authenticate(headers, now)
        .await
        .map_err(|_| ApiError::not_found(correlation))?;
    if !state.auth.verify_session_csrf(&identity, headers, now) {
        return Err(ApiError::csrf_rejected(correlation));
    }
    Ok(identity)
}
fn status_from_row(id: Uuid, row: &sqlx::postgres::PgRow) -> QrStatusResponse {
    QrStatusResponse {
        challenge_id: id,
        status: row.get("status"),
        lock_version: row.get("lock_version"),
        qr_expires_at: row.get("qr_expires_at"),
        approval_expires_at: row.get("approval_expires_at"),
    }
}
fn random_code() -> Result<String, getrandom::Error> {
    loop {
        let mut bytes = [0u8; 2];
        getrandom::fill(&mut bytes)?;
        let sample = u16::from_le_bytes(bytes);
        if sample < 60_000 {
            return Ok(format!("{:04}", sample % 10_000));
        }
    }
}
fn code_context(id: Uuid) -> String {
    format!("qr-code:{id}")
}
fn summarize_user_agent(value: &str) -> String {
    value.chars().take(120).collect()
}
fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .map(str::trim)
        .find_map(|item| item.strip_prefix(&format!("{name}=")))
        .filter(|v| !v.is_empty())
}
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|v| !v.is_empty())
}
fn audit(
    event: &'static str,
    outcome: AuditOutcome,
    correlation: CorrelationId,
    challenge: Uuid,
) -> AuditEvent {
    AuditEvent::new(AuditCategory::QrLogin, event, outcome, correlation.0).challenge(challenge)
}
