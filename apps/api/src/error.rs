use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use sentinel_api_contract::ProblemDetails;

use crate::CorrelationId;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    title: &'static str,
    correlation_id: CorrelationId,
}

impl ApiError {
    pub fn service_unavailable(correlation_id: CorrelationId) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "SERVICE_NOT_READY",
            title: "Serviço temporariamente indisponível",
            correlation_id,
        }
    }

    pub fn not_found(correlation_id: CorrelationId) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "ROUTE_NOT_FOUND",
            title: "Rota não encontrada",
            correlation_id,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let problem = ProblemDetails {
            problem_type: format!(
                "https://docs.sentinel.local/errors/{}",
                self.code.to_ascii_lowercase()
            ),
            title: self.title.to_owned(),
            status: self.status.as_u16(),
            code: self.code.to_owned(),
            correlation_id: self.correlation_id.0,
        };
        let mut response = (self.status, Json(problem)).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}
