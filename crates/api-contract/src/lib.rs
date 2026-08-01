use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub code: String,
    pub correlation_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct CredentialsRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub user: UserResponse,
    pub session: SessionDetails,
}

#[derive(Debug, Serialize)]
pub struct SessionDetails {
    pub id: Uuid,
    pub idle_expires_at: DateTime<Utc>,
    pub absolute_expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct CsrfResponse {
    pub csrf_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ExchangeRequest {
    pub challenge_id: Uuid,
    pub subscription_token: String,
}

#[derive(Debug, Deserialize)]
pub struct QrBootstrapRequest {
    pub qr_token: String,
}

#[derive(Debug, Deserialize)]
pub struct QrCodeRequest {
    pub verification_code: String,
    pub lock_version: i32,
}

#[derive(Debug, Deserialize)]
pub struct QrTransitionRequest {
    pub lock_version: i32,
}

#[derive(Debug, Deserialize)]
pub struct SubscriptionRequest {
    pub subscription_token: String,
}

#[derive(Debug, Serialize)]
pub struct QrChallengeCreated {
    pub challenge_id: Uuid,
    pub qr_payload: String,
    pub subscription_token: String,
    pub verification_code: String,
    pub qr_expires_at: DateTime<Utc>,
    pub poll_after_ms: u32,
}

#[derive(Debug, Serialize)]
pub struct QrScanResponse {
    pub challenge_id: Uuid,
    pub lock_version: i32,
}

#[derive(Debug, Serialize)]
pub struct QrChallengeDetails {
    pub challenge_id: Uuid,
    pub status: String,
    pub lock_version: i32,
    pub requested_ua_summary: Option<String>,
    pub requested_ip: Option<String>,
    pub created_at: DateTime<Utc>,
    pub qr_expires_at: DateTime<Utc>,
    pub code_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct QrStatusResponse {
    pub challenge_id: Uuid,
    pub status: String,
    pub lock_version: i32,
    pub qr_expires_at: DateTime<Utc>,
    pub approval_expires_at: Option<DateTime<Utc>>,
}
