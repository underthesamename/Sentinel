pub mod config;
mod error;
pub mod security;

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use axum::{
    Extension, Json, Router,
    extract::{Request, State},
    http::{HeaderName, HeaderValue},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use config::PublicConfig;
use error::ApiError;
use serde::Serialize;
use sqlx::PgPool;
use tower_http::trace::TraceLayer;
use tracing::{Level, Span};
use uuid::Uuid;

const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

#[derive(Debug, Clone, Copy)]
pub struct CorrelationId(pub Uuid);

#[async_trait]
pub trait HealthProbe: Send + Sync {
    async fn is_ready(&self) -> bool;
}

pub struct DatabaseHealthProbe {
    pool: PgPool,
}

impl DatabaseHealthProbe {
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl HealthProbe for DatabaseHealthProbe {
    async fn is_ready(&self) -> bool {
        tokio::time::timeout(
            Duration::from_secs(2),
            sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(&self.pool),
        )
        .await
        .is_ok_and(|result| matches!(result, Ok(1)))
    }
}

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: Arc<PublicConfig>,
    health_probe: Arc<dyn HealthProbe>,
}

impl AppState {
    pub fn new(
        pool: PgPool,
        config: Arc<PublicConfig>,
        health_probe: Arc<dyn HealthProbe>,
    ) -> Self {
        Self {
            pool,
            config,
            health_probe,
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .fallback(not_found)
        .with_state(state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &Request| {
                    let correlation_id = request
                        .extensions()
                        .get::<CorrelationId>()
                        .map_or_else(|| "missing".to_owned(), |id| id.0.to_string());
                    tracing::span!(
                        Level::INFO,
                        "http.request",
                        method = %request.method(),
                        path = %request.uri().path(),
                        correlation_id = %correlation_id,
                        status = tracing::field::Empty,
                        latency_ms = tracing::field::Empty,
                    )
                })
                .on_response(|response: &Response, latency: Duration, span: &Span| {
                    span.record("status", response.status().as_u16());
                    span.record("latency_ms", latency.as_millis() as u64);
                    tracing::info!(parent: span, event = "http.response", "requisição concluída");
                }),
        )
        .layer(middleware::from_fn(security::security_headers))
        .layer(middleware::from_fn(correlation_middleware))
}

pub fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sentinel_api=info,tower_http=info".into()),
        )
        .json()
        .with_current_span(true)
        .with_span_list(false)
        .init();
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

async fn live(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: state.config.service_name,
    })
}

async fn ready(
    State(state): State<AppState>,
    Extension(correlation_id): Extension<CorrelationId>,
) -> Result<Json<HealthResponse>, ApiError> {
    if !state.health_probe.is_ready().await {
        return Err(ApiError::service_unavailable(correlation_id));
    }
    Ok(Json(HealthResponse {
        status: "ok",
        service: state.config.service_name,
    }))
}

async fn not_found(Extension(correlation_id): Extension<CorrelationId>) -> Response {
    let mut response = ApiError::not_found(correlation_id).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
}

async fn correlation_middleware(mut request: Request, next: Next) -> Response {
    let correlation_id = request
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Uuid::parse_str(value).ok())
        .unwrap_or_else(Uuid::now_v7);
    request
        .extensions_mut()
        .insert(CorrelationId(correlation_id));

    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&correlation_id.to_string()) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use super::*;
    use crate::config::AppEnvironment;

    struct FixedProbe(bool);

    #[async_trait]
    impl HealthProbe for FixedProbe {
        async fn is_ready(&self) -> bool {
            self.0
        }
    }

    fn app(ready: bool) -> Router {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://sentinel:secret@127.0.0.1:1/sentinel")
            .unwrap();
        let config = Arc::new(PublicConfig {
            service_name: "sentinel-api",
            environment: AppEnvironment::Ci,
            app_origin: "https://sentinel.example".to_owned(),
            websocket_origins: vec!["https://sentinel.example".to_owned()],
        });
        build_router(AppState::new(pool, config, Arc::new(FixedProbe(ready))))
    }

    #[tokio::test]
    async fn liveness_does_not_depend_on_database() {
        let response = app(false)
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readiness_succeeds_when_database_probe_succeeds() {
        let response = app(true)
            .oneshot(
                Request::builder()
                    .uri("/health/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(&REQUEST_ID_HEADER));
    }

    #[tokio::test]
    async fn readiness_returns_problem_details_without_secrets() {
        let response = app(false)
            .oneshot(
                Request::builder()
                    .uri("/health/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/problem+json"
        );

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("SERVICE_NOT_READY"));
        assert!(!body.contains("secret"));
        assert!(!body.contains("postgres://"));
    }

    #[tokio::test]
    async fn valid_request_id_is_propagated() {
        let request_id = Uuid::now_v7();
        let response = app(true)
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .header(&REQUEST_ID_HEADER, request_id.to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.headers().get(&REQUEST_ID_HEADER).unwrap(),
            request_id.to_string().as_str()
        );
    }
}
