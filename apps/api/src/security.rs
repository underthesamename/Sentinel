use std::{collections::BTreeMap, fmt, time::Duration};

use axum::{
    extract::Request,
    http::{HeaderMap, HeaderValue, header},
    middleware::Next,
    response::Response,
};
use serde::Serialize;
use url::Url;
use uuid::Uuid;

use crate::config::AppEnvironment;

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedOrigin(String);

impl NormalizedOrigin {
    fn parse_origin(value: &str) -> Result<Self, OriginError> {
        let url = Url::parse(value).map_err(|_| OriginError::Malformed)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
        {
            return Err(OriginError::Malformed);
        }
        Ok(Self(url.origin().ascii_serialization()))
    }

    fn parse_referer(value: &str) -> Result<Self, OriginError> {
        let url = Url::parse(value).map_err(|_| OriginError::Malformed)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
        {
            return Err(OriginError::Malformed);
        }
        Ok(Self(url.origin().ascii_serialization()))
    }
}

#[derive(Debug, Clone)]
pub struct OriginPolicy {
    allowed: Vec<NormalizedOrigin>,
}

impl OriginPolicy {
    pub fn new(origins: impl IntoIterator<Item = String>) -> Result<Self, OriginError> {
        let allowed = origins
            .into_iter()
            .map(|origin| NormalizedOrigin::parse_origin(&origin))
            .collect::<Result<Vec<_>, _>>()?;
        if allowed.is_empty() {
            return Err(OriginError::EmptyAllowlist);
        }
        Ok(Self { allowed })
    }

    /// `Referer` is accepted only as a fallback for ordinary authenticated HTTP mutations.
    pub fn validate_http_mutation(&self, headers: &HeaderMap) -> Result<(), OriginError> {
        let candidate = if let Some(origin) = headers.get(header::ORIGIN) {
            NormalizedOrigin::parse_origin(origin.to_str().map_err(|_| OriginError::Malformed)?)?
        } else if let Some(referer) = headers.get(header::REFERER) {
            NormalizedOrigin::parse_referer(referer.to_str().map_err(|_| OriginError::Malformed)?)?
        } else {
            return Err(OriginError::Missing);
        };

        if self.allowed.contains(&candidate) {
            Ok(())
        } else {
            Err(OriginError::NotAllowed)
        }
    }

    /// WebSocket handshakes require `Origin`; `Referer` is never a substitute.
    pub fn validate_websocket(&self, headers: &HeaderMap) -> Result<(), OriginError> {
        let origin = headers.get(header::ORIGIN).ok_or(OriginError::Missing)?;
        let candidate =
            NormalizedOrigin::parse_origin(origin.to_str().map_err(|_| OriginError::Malformed)?)?;
        if self.allowed.contains(&candidate) {
            Ok(())
        } else {
            Err(OriginError::NotAllowed)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OriginError {
    #[error("allowlist de origens vazia")]
    EmptyAllowlist,
    #[error("origem ausente")]
    Missing,
    #[error("origem malformada")]
    Malformed,
    #[error("origem não permitida")]
    NotAllowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSitePolicy {
    Lax,
    Strict,
}

impl fmt::Display for SameSitePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Lax => "Lax",
            Self::Strict => "Strict",
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HostCookieBuilder {
    environment: AppEnvironment,
}

impl HostCookieBuilder {
    pub const fn new(environment: AppEnvironment) -> Self {
        Self { environment }
    }

    pub fn session(&self, value: &str, max_age: Duration) -> Result<HeaderValue, CookieError> {
        self.build("__Host-session", value, max_age, SameSitePolicy::Lax)
    }

    pub fn qr_continuation(
        &self,
        value: &str,
        max_age: Duration,
    ) -> Result<HeaderValue, CookieError> {
        self.build("__Host-qr-cont", value, max_age, SameSitePolicy::Lax)
    }

    pub fn clear_session(&self) -> HeaderValue {
        HeaderValue::from_static(
            "__Host-session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
        )
    }

    pub fn clear_qr_continuation(&self) -> HeaderValue {
        HeaderValue::from_static(
            "__Host-qr-cont=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
        )
    }

    fn build(
        &self,
        name: &str,
        value: &str,
        max_age: Duration,
        same_site: SameSitePolicy,
    ) -> Result<HeaderValue, CookieError> {
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CookieError::UnsafeValue);
        }
        if max_age.is_zero() || max_age.as_secs() > i64::MAX as u64 {
            return Err(CookieError::InvalidMaxAge);
        }
        // `Secure` is unconditional: the __Host- prefix is invalid without it, including locally.
        let value = format!(
            "{name}={value}; Path=/; Max-Age={}; Secure; HttpOnly; SameSite={same_site}",
            max_age.as_secs()
        );
        let _ = self.environment;
        HeaderValue::from_str(&value).map_err(|_| CookieError::UnsafeValue)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CookieError {
    #[error("valor de cookie inseguro")]
    UnsafeValue,
    #[error("Max-Age de cookie inválido")]
    InvalidMaxAge,
}

pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Succeeded,
    Failed,
    Denied,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditCategory {
    Authentication,
    Session,
    QrLogin,
    SecurityControl,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub category: AuditCategory,
    pub event_type: &'static str,
    pub outcome: AuditOutcome,
    pub correlation_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<Uuid>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<&'static str, AuditValue>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum AuditValue {
    Count(u32),
    Category(&'static str),
    Fingerprint(String),
}

impl AuditEvent {
    pub fn new(
        category: AuditCategory,
        event_type: &'static str,
        outcome: AuditOutcome,
        correlation_id: Uuid,
    ) -> Self {
        Self {
            category,
            event_type,
            outcome,
            correlation_id,
            user_id: None,
            session_id: None,
            challenge_id: None,
            metadata: BTreeMap::new(),
        }
    }

    pub fn reason_category(mut self, reason: &'static str) -> Self {
        self.metadata
            .insert("reason_category", AuditValue::Category(reason));
        self
    }

    pub fn user(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn session(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }

    pub fn challenge(mut self, challenge_id: Uuid) -> Self {
        self.challenge_id = Some(challenge_id);
        self
    }

    pub fn attempt_count(mut self, count: u32) -> Self {
        self.metadata
            .insert("attempt_count", AuditValue::Count(count));
        self
    }

    pub fn key_fingerprint(mut self, fingerprint: String) -> Self {
        self.metadata
            .insert("key_fingerprint", AuditValue::Fingerprint(fingerprint));
        self
    }

    pub fn write_log(&self) {
        if let Ok(record) = serde_json::to_string(self) {
            tracing::info!(event = "security.audit", audit = %record, "evento de auditoria");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };

    use axum::{Router, body::Body, http::Request, routing::get};
    use tower::ServiceExt;
    use tracing_subscriber::fmt::MakeWriter;

    use super::*;

    fn policy() -> OriginPolicy {
        OriginPolicy::new(["https://Example.COM:443".to_owned()]).unwrap()
    }

    #[test]
    fn origin_accepts_normalized_allowed_origin_and_referer_fallback() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://example.com"),
        );
        assert_eq!(policy().validate_http_mutation(&headers), Ok(()));

        headers.remove(header::ORIGIN);
        headers.insert(
            header::REFERER,
            HeaderValue::from_static("https://example.com/account/settings?tab=security"),
        );
        assert_eq!(policy().validate_http_mutation(&headers), Ok(()));
    }

    #[test]
    fn origin_rejects_absent_invalid_and_malformed_values() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            policy().validate_http_mutation(&headers),
            Err(OriginError::Missing)
        );
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert_eq!(
            policy().validate_http_mutation(&headers),
            Err(OriginError::NotAllowed)
        );
        headers.insert(header::ORIGIN, HeaderValue::from_static("null"));
        assert_eq!(
            policy().validate_http_mutation(&headers),
            Err(OriginError::Malformed)
        );
        headers.remove(header::ORIGIN);
        headers.insert(header::REFERER, HeaderValue::from_static("not a URL"));
        assert_eq!(
            policy().validate_http_mutation(&headers),
            Err(OriginError::Malformed)
        );
    }

    #[test]
    fn websocket_never_falls_back_to_referer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::REFERER,
            HeaderValue::from_static("https://example.com/app"),
        );
        assert_eq!(
            policy().validate_websocket(&headers),
            Err(OriginError::Missing)
        );
    }

    #[test]
    fn cookies_have_exact_host_attributes_in_local_and_production() {
        for environment in [AppEnvironment::Local, AppEnvironment::Production] {
            let builder = HostCookieBuilder::new(environment);
            assert_eq!(
                builder
                    .session("abc_DEF-123", Duration::from_secs(1800))
                    .unwrap(),
                "__Host-session=abc_DEF-123; Path=/; Max-Age=1800; Secure; HttpOnly; SameSite=Lax"
            );
            assert_eq!(
                builder
                    .qr_continuation("abc_DEF-123", Duration::from_secs(300))
                    .unwrap(),
                "__Host-qr-cont=abc_DEF-123; Path=/; Max-Age=300; Secure; HttpOnly; SameSite=Lax"
            );
        }
    }

    #[tokio::test]
    async fn private_security_headers_are_applied() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(security_headers));
        let response = app.oneshot(Request::new(Body::empty())).await.unwrap();
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "no-store, private"
        );
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert!(
            response.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("frame-ancestors 'none'")
        );
    }

    #[test]
    fn captured_audit_log_only_contains_allowlisted_fields_and_no_secrets() {
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(capture.clone())
            .finish();
        let event = AuditEvent::new(
            AuditCategory::SecurityControl,
            "security.rate_limited",
            AuditOutcome::Denied,
            Uuid::nil(),
        )
        .reason_category("limit_exceeded")
        .attempt_count(6)
        .key_fingerprint("sha256:public-fingerprint".to_owned());
        tracing::subscriber::with_default(subscriber, || event.write_log());
        let captured_log = capture.contents();
        for secret in [
            "person@example.com",
            "correct horse battery staple",
            "raw-session-token",
            "Cookie: __Host-session=raw-session-token",
            "raw-csrf-token",
        ] {
            assert!(!captured_log.contains(secret));
        }
        assert!(captured_log.contains("key_fingerprint"));
    }

    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    impl LogCapture {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    struct LogWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for LogWriter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> MakeWriter<'writer> for LogCapture {
        type Writer = LogWriter;

        fn make_writer(&'writer self) -> Self::Writer {
            LogWriter(self.0.clone())
        }
    }
}
