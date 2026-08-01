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
