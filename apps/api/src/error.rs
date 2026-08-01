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
    pub fn bad_request(
        code: &'static str,
        title: &'static str,
        correlation_id: CorrelationId,
    ) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            title,
            correlation_id,
        }
    }

    pub fn conflict(
        code: &'static str,
        title: &'static str,
        correlation_id: CorrelationId,
    ) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code,
            title,
            correlation_id,
        }
    }

    pub fn unauthorized(correlation_id: CorrelationId) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "AUTHENTICATION_REQUIRED",
            title: "Autenticação necessária",
            correlation_id,
        }
    }

    pub fn invalid_credentials(correlation_id: CorrelationId) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "INVALID_CREDENTIALS",
            title: "Credenciais inválidas",
            correlation_id,
        }
    }

    pub fn csrf_rejected(correlation_id: CorrelationId) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "CSRF_REJECTED",
            title: "Requisição não autorizada",
            correlation_id,
        }
    }

    pub fn too_many_requests(correlation_id: CorrelationId) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "RATE_LIMITED",
            title: "Muitas tentativas",
            correlation_id,
        }
    }

    pub fn internal(correlation_id: CorrelationId) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "INTERNAL_ERROR",
            title: "Erro interno",
            correlation_id,
        }
    }

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
