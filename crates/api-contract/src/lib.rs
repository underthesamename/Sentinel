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
pub struct ExchangeRequest {
    pub challenge_id: Uuid,
    pub subscription_token: String,
}
