use std::{
    env,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use axum::{
    Router,
    body::Body,
    extract::ConnectInfo,
    http::{HeaderValue, Request, StatusCode, header},
    response::Response,
};
use http_body_util::BodyExt;
use sentinel_api::{
    AppState, DatabaseHealthProbe, build_router,
    config::{AppEnvironment, PublicConfig},
};
use sentinel_application::auth::{
    AuthRepository, AuthRepositoryError, FingerprintCandidate, NewSession,
};
use sentinel_domain::auth::NormalizedEmail;
use sentinel_infrastructure::{
    auth::{Argon2idPasswordHasher, PostgresAuthRepository},
    security::{FingerprintKeyRing, InMemoryRateLimiter},
};
use serde_json::Value;
use sqlx::{Executor, PgPool, Row, postgres::PgPoolOptions};
use tower::ServiceExt;
use uuid::Uuid;

const APP_ORIGIN: &str = "https://sentinel.example";
const TEST_PASSWORD: &str = "uma senha sintética longa e exclusiva";
const SESSION_CONTEXT: &[u8] = b"session";

struct TestDatabase {
    admin_pool: PgPool,
    pool: PgPool,
    schema: String,
}

impl TestDatabase {
    async fn create() -> Self {
        let database_url = env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL é obrigatório para os testes PostgreSQL");
        let admin_pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .expect("PostgreSQL de teste indisponível");
        let schema = format!("auth_{}", Uuid::new_v4().simple());
        admin_pool
            .execute(format!("CREATE SCHEMA {schema}").as_str())
            .await
            .expect("não foi possível criar schema isolado");

        let search_path = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(12)
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {search_path}");
                Box::pin(async move {
                    connection.execute(statement.as_str()).await?;
                    Ok(())
                })
            })
            .connect(&database_url)
            .await
            .expect("não foi possível conectar ao schema isolado");
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrações falharam em banco vazio");

        Self {
            admin_pool,
            pool,
            schema,
        }
    }

    async fn cleanup(self) {
        self.pool.close().await;
        self.admin_pool
            .execute(format!("DROP SCHEMA {} CASCADE", self.schema).as_str())
            .await
            .expect("não foi possível remover dados sintéticos");
        self.admin_pool.close().await;
    }
}

fn public_config() -> Arc<PublicConfig> {
    Arc::new(PublicConfig {
        service_name: "sentinel-api",
        environment: AppEnvironment::Ci,
        app_origin: APP_ORIGIN.to_owned(),
        websocket_origins: vec![APP_ORIGIN.to_owned()],
        session_idle_ttl: Duration::from_secs(30 * 60),
        session_absolute_ttl: Duration::from_secs(30 * 24 * 60 * 60),
        csrf_ttl: Duration::from_secs(30 * 60),
        session_touch_interval: Duration::from_secs(5 * 60),
        qr_challenge_ttl: Duration::from_secs(90),
        qr_approval_ttl: Duration::from_secs(90),
        qr_continuation_ttl: Duration::from_secs(300),
    })
}

fn app(pool: PgPool) -> Router {
    let config = public_config();
    let fingerprints = FingerprintKeyRing::new([("test".to_owned(), vec![9; 32])])
        .expect("keyring de teste inválido");
    let auth = Arc::new(
        sentinel_api::auth::AuthService::new(
            Arc::new(PostgresAuthRepository::new(pool.clone())),
            Arc::new(Argon2idPasswordHasher::new().expect("Argon2id indisponível")),
            Arc::new(InMemoryRateLimiter::default()),
            fingerprints.clone(),
            config.clone(),
        )
        .expect("serviço de autenticação inválido"),
    );
    build_router(AppState::new(
        pool.clone(),
        config.clone(),
        Arc::new(DatabaseHealthProbe::new(pool.clone())),
        auth,
        Arc::new(sentinel_api::qr::QrService::new(
            pool.clone(),
            fingerprints,
            Arc::new(InMemoryRateLimiter::default()),
            config.environment,
        )),
    ))
}

fn mutation_request(uri: &str, body: &str) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::ORIGIN, APP_ORIGIN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .expect("requisição inválida");
    request.extensions_mut().insert(ConnectInfo(
        "192.0.2.10:4242"
            .parse::<SocketAddr>()
            .expect("endereço sintético inválido"),
    ));
    request
}

fn session_request(uri: &str, cookie: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(header::COOKIE, cookie)
        .body(Body::empty())
        .expect("requisição inválida")
}

async fn body_json(response: Response) -> Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("corpo HTTP inválido")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("resposta não contém JSON válido")
}

async fn register_and_login(app: &Router, email: &str) -> String {
    let credentials = format!(r#"{{"email":"{email}","password":"{TEST_PASSWORD}"}}"#);
    assert_eq!(
        app.clone()
            .oneshot(mutation_request("/v1/auth/register", &credentials))
            .await
            .unwrap()
            .status(),
        StatusCode::CREATED
    );
    let login = app
        .clone()
        .oneshot(mutation_request("/v1/auth/login", &credentials))
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    cookie_from(&login)
}

async fn csrf_token(app: &Router, cookie: &str) -> String {
    let response = app
        .clone()
        .oneshot(session_request("/v1/auth/csrf", cookie))
        .await
        .unwrap();
    body_json(response).await["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn authenticated_mutation(uri: &str, body: &str, cookies: &str, csrf: &str) -> Request<Body> {
    let mut request = mutation_request(uri, body);
    request
        .headers_mut()
        .insert(header::COOKIE, HeaderValue::from_str(cookies).unwrap());
    request
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(csrf).unwrap());
    request
}

struct ScannedQr {
    id: Uuid,
    subscription_token: String,
    verification_code: String,
    lock_version: i64,
}

async fn create_and_scan_qr(app: &Router, session_cookie: &str, csrf: &str) -> ScannedQr {
    let created = body_json(
        app.clone()
            .oneshot(mutation_request("/v1/qr-login/challenges", ""))
            .await
            .unwrap(),
    )
    .await;
    let id = Uuid::parse_str(created["challenge_id"].as_str().unwrap()).unwrap();
    let qr_token = created["qr_payload"]
        .as_str()
        .unwrap()
        .split("#token=")
        .nth(1)
        .unwrap();
    let bootstrap = app
        .clone()
        .oneshot(mutation_request(
            "/v1/qr-login/bootstrap",
            &format!(r#"{{"qr_token":"{qr_token}"}}"#),
        ))
        .await
        .unwrap();
    let continuation_cookie = cookie_from(&bootstrap);
    let scan = app
        .clone()
        .oneshot(authenticated_mutation(
            "/v1/qr-login/scan",
            "",
            &format!("{session_cookie}; {continuation_cookie}"),
            csrf,
        ))
        .await
        .unwrap();
    assert_eq!(scan.status(), StatusCode::OK);
    let scan = body_json(scan).await;
    ScannedQr {
        id,
        subscription_token: created["subscription_token"].as_str().unwrap().to_owned(),
        verification_code: created["verification_code"].as_str().unwrap().to_owned(),
        lock_version: scan["lock_version"].as_i64().unwrap(),
    }
}

fn cookie_from(response: &Response) -> String {
    response.headers()[header::SET_COOKIE]
        .to_str()
        .expect("Set-Cookie inválido")
        .split(';')
        .next()
        .expect("cookie ausente")
        .to_owned()
}

#[tokio::test]
async fn migrations_apply_from_zero_and_http_contract_survives_abuse() {
    let database = TestDatabase::create().await;
    let app = app(database.pool.clone());
    let credentials = format!(r#"{{"email":"auth@example.test","password":"{TEST_PASSWORD}"}}"#);

    let request_id = Uuid::now_v7();
    let mut registration = mutation_request("/v1/auth/register", &credentials);
    registration.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.to_string()).expect("request id inválido"),
    );
    let registered = app.clone().oneshot(registration).await.expect("falha HTTP");
    assert_eq!(registered.status(), StatusCode::CREATED);
    assert_eq!(registered.headers()["x-request-id"], request_id.to_string());

    let injection =
        r#"{"email":"' OR 1=1;--@example.test","password":"uma senha sintética diferente"}"#;
    let rejected = app
        .clone()
        .oneshot(mutation_request("/v1/auth/login", injection))
        .await
        .expect("falha HTTP");
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        rejected.headers()[header::CONTENT_TYPE],
        "application/problem+json"
    );
    let problem = body_json(rejected).await;
    assert_eq!(problem["code"], "INVALID_CREDENTIALS");
    assert_eq!(problem["status"], 401);
    assert!(Uuid::parse_str(problem["correlation_id"].as_str().unwrap()).is_ok());

    let login = app
        .clone()
        .oneshot(mutation_request("/v1/auth/login", &credentials))
        .await
        .expect("falha HTTP");
    assert_eq!(login.status(), StatusCode::OK);
    let set_cookie = login.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(set_cookie.starts_with("__Host-session="));
    for attribute in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
        assert!(
            set_cookie.contains(attribute),
            "atributo ausente: {attribute}"
        );
    }
    let cookie = cookie_from(&login);

    let csrf = app
        .clone()
        .oneshot(session_request("/v1/auth/csrf", &cookie))
        .await
        .expect("falha HTTP");
    assert_eq!(csrf.status(), StatusCode::OK);
    let csrf_token = body_json(csrf).await["csrf_token"]
        .as_str()
        .unwrap()
        .to_owned();

    let mut logout = mutation_request("/v1/auth/logout", "");
    logout
        .headers_mut()
        .insert(header::COOKIE, HeaderValue::from_str(&cookie).unwrap());
    logout
        .headers_mut()
        .insert("x-csrf-token", HeaderValue::from_str(&csrf_token).unwrap());
    let logged_out = app.clone().oneshot(logout).await.expect("falha HTTP");
    assert_eq!(logged_out.status(), StatusCode::NO_CONTENT);
    assert!(
        logged_out.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(
        app.oneshot(session_request("/v1/auth/me", &cookie))
            .await
            .expect("falha HTTP")
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let stored_users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&database.pool)
        .await
        .unwrap();
    assert_eq!(stored_users, 1, "payload de SQL injection alterou dados");
    database.cleanup().await;
}

#[tokio::test]
async fn postgres_enforces_duplicate_registration_under_concurrency() {
    let database = TestDatabase::create().await;
    let repository = PostgresAuthRepository::new(database.pool.clone());
    let email = NormalizedEmail::parse("concurrent@example.test").unwrap();
    let now = SystemTime::now();
    let first = repository.create_user_with_password(Uuid::now_v7(), &email, "hash-a", now);
    let second = repository.create_user_with_password(Uuid::now_v7(), &email, "hash-b", now);
    let (first, second) = tokio::join!(first, second);
    let results = [first, second];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(AuthRepositoryError::DuplicateEmail)))
            .count(),
        1
    );
    let credentials: i64 = sqlx::query_scalar("SELECT count(*) FROM password_credentials")
        .fetch_one(&database.pool)
        .await
        .unwrap();
    assert_eq!(
        credentials, 1,
        "transação deixou credencial órfã ou duplicada"
    );
    database.cleanup().await;
}

#[tokio::test]
async fn concurrent_session_touch_and_logout_converge_to_revoked() {
    let database = TestDatabase::create().await;
    let repository = PostgresAuthRepository::new(database.pool.clone());
    let email = NormalizedEmail::parse("session-race@example.test").unwrap();
    let user_id = Uuid::now_v7();
    let session_id = Uuid::now_v7();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
    repository
        .create_user_with_password(user_id, &email, "hash", now)
        .await
        .unwrap();
    let keyring = FingerprintKeyRing::new([("test".to_owned(), vec![9; 32])]).unwrap();
    let fingerprint = keyring.fingerprint(SESSION_CONTEXT, "synthetic-session-token");
    repository
        .create_session(&NewSession {
            id: session_id,
            user_id,
            token_fingerprint: fingerprint.digest().to_vec(),
            token_key_id: fingerprint.key_id().to_owned(),
            last_seen_at: now,
            idle_expires_at: now + Duration::from_secs(3600),
            absolute_expires_at: now + Duration::from_secs(7200),
        })
        .await
        .unwrap();
    let candidates = [FingerprintCandidate {
        key_id: fingerprint.key_id().to_owned(),
        digest: fingerprint.digest().to_vec(),
    }];
    let touch_now = now + Duration::from_secs(600);
    let touch = repository.find_active_session(
        &candidates,
        touch_now,
        Duration::from_secs(3600),
        Duration::from_secs(300),
    );
    let first_logout = repository.revoke_session(session_id, touch_now);
    let second_logout = repository.revoke_session(session_id, touch_now);
    let (_, first_logout_result, second_logout_result) =
        tokio::join!(touch, first_logout, second_logout);
    first_logout_result.unwrap();
    second_logout_result.unwrap();

    let after_race = repository
        .find_active_session(
            &candidates,
            touch_now,
            Duration::from_secs(3600),
            Duration::ZERO,
        )
        .await
        .unwrap();
    assert!(after_race.is_none());
    let row = sqlx::query("SELECT revoked_at, csrf_token_fingerprint FROM sessions WHERE id = $1")
        .bind(session_id)
        .fetch_one(&database.pool)
        .await
        .unwrap();
    assert!(
        row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("revoked_at")
            .unwrap()
            .is_some()
    );
    assert!(
        row.try_get::<Option<Vec<u8>>, _>("csrf_token_fingerprint")
            .unwrap()
            .is_none()
    );
    database.cleanup().await;
}

#[tokio::test]
async fn readiness_reports_database_outage_and_recovers_with_a_healthy_pool() {
    let unavailable_pool = PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgres://sentinel:sentinel@127.0.0.1:1/sentinel")
        .unwrap();
    let unavailable = app(unavailable_pool)
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(unavailable).await["code"], "SERVICE_NOT_READY");

    let database = TestDatabase::create().await;
    let recovered = app(database.pool.clone())
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(recovered.status(), StatusCode::OK);
    database.cleanup().await;
}

#[test]
fn openapi_paths_match_the_real_routes() {
    let document: serde_yaml::Value =
        serde_yaml::from_str(include_str!("../../../docs/openapi.yaml")).unwrap();
    let paths = document["paths"].as_mapping().unwrap();
    let documented = paths
        .keys()
        .map(|path| path.as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    let real = [
        "/health/live",
        "/health/ready",
        "/v1/auth/register",
        "/v1/auth/login",
        "/v1/auth/me",
        "/v1/auth/csrf",
        "/v1/auth/logout",
        "/v1/sessions/revoke-all",
        "/v1/qr-login/challenges",
        "/v1/qr-login/bootstrap",
        "/v1/qr-login/scan",
        "/v1/qr-login/challenges/{id}",
        "/v1/qr-login/challenges/{id}/verify-code",
        "/v1/qr-login/challenges/{id}/approve",
        "/v1/qr-login/challenges/{id}/reject",
        "/v1/qr-login/challenges/{id}/status",
        "/v1/qr-login/challenges/{id}/cancel",
        "/v1/qr-login/exchange",
        "/v1/qr-login/ws",
    ]
    .into_iter()
    .collect();
    assert_eq!(documented, real);
}

#[tokio::test]
async fn qr_happy_path_and_twenty_parallel_exchanges_create_one_session() {
    let database = TestDatabase::create().await;
    let app = app(database.pool.clone());
    let scanner_cookie = register_and_login(&app, "qr-scanner@example.test").await;
    let scanner_csrf = csrf_token(&app, &scanner_cookie).await;

    let created = app
        .clone()
        .oneshot(mutation_request("/v1/qr-login/challenges", ""))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let created = body_json(created).await;
    let challenge_id = created["challenge_id"].as_str().unwrap();
    let qr_token = created["qr_payload"]
        .as_str()
        .unwrap()
        .split("#token=")
        .nth(1)
        .unwrap();
    assert!(!created["qr_payload"].as_str().unwrap().contains('?'));
    let subscription_token = created["subscription_token"].as_str().unwrap();
    let verification_code = created["verification_code"].as_str().unwrap();

    let bootstrap = app
        .clone()
        .oneshot(mutation_request(
            "/v1/qr-login/bootstrap",
            &format!(r#"{{"qr_token":"{qr_token}"}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(bootstrap.status(), StatusCode::NO_CONTENT);
    let continuation_cookie = cookie_from(&bootstrap);
    assert!(
        bootstrap.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Secure; HttpOnly; SameSite=Lax")
    );
    let scan_cookies = format!("{scanner_cookie}; {continuation_cookie}");
    let scan = app
        .clone()
        .oneshot(authenticated_mutation(
            "/v1/qr-login/scan",
            "",
            &scan_cookies,
            &scanner_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(scan.status(), StatusCode::OK);
    let scanned = body_json(scan).await;
    let scanned_version = scanned["lock_version"].as_i64().unwrap();

    let verified = app
        .clone()
        .oneshot(authenticated_mutation(
            &format!("/v1/qr-login/challenges/{challenge_id}/verify-code"),
            &format!(
                r#"{{"verification_code":"{verification_code}","lock_version":{scanned_version}}}"#
            ),
            &scanner_cookie,
            &scanner_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(verified.status(), StatusCode::OK);
    let verified_version = body_json(verified).await["lock_version"].as_i64().unwrap();
    let approved = app
        .clone()
        .oneshot(authenticated_mutation(
            &format!("/v1/qr-login/challenges/{challenge_id}/approve"),
            &format!(r#"{{"lock_version":{verified_version}}}"#),
            &scanner_cookie,
            &scanner_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(approved.status(), StatusCode::OK);

    let status_request = Request::builder()
        .uri(format!("/v1/qr-login/challenges/{challenge_id}/status"))
        .header(
            header::AUTHORIZATION,
            format!("Bearer {subscription_token}"),
        )
        .body(Body::empty())
        .unwrap();
    let status = app.clone().oneshot(status_request).await.unwrap();
    assert_eq!(body_json(status).await["status"], "APPROVED");

    let mut exchanges = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let app = app.clone();
        let body = format!(
            r#"{{"challenge_id":"{challenge_id}","subscription_token":"{subscription_token}"}}"#
        );
        exchanges.spawn(async move {
            app.oneshot(mutation_request("/v1/qr-login/exchange", &body))
                .await
                .unwrap()
                .status()
        });
    }
    let mut statuses = Vec::new();
    while let Some(result) = exchanges.join_next().await {
        statuses.push(result.unwrap());
    }
    assert_eq!(
        statuses
            .iter()
            .filter(|status| **status == StatusCode::NO_CONTENT)
            .count(),
        1
    );
    assert!(statuses.iter().all(|status| matches!(
        *status,
        StatusCode::NO_CONTENT | StatusCode::CONFLICT | StatusCode::TOO_MANY_REQUESTS
    )));
    let sessions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM sessions WHERE source_challenge_id = $1")
            .bind(Uuid::parse_str(challenge_id).unwrap())
            .fetch_one(&database.pool)
            .await
            .unwrap();
    assert_eq!(sessions, 1);
    let stored_secrets = sqlx::query(
        "SELECT qr_token_fingerprint, verification_code_hash FROM qr_login_challenges WHERE id=$1",
    )
    .bind(Uuid::parse_str(challenge_id).unwrap())
    .fetch_one(&database.pool)
    .await
    .unwrap();
    assert!(
        stored_secrets
            .try_get::<Option<Vec<u8>>, _>("qr_token_fingerprint")
            .unwrap()
            .is_none()
    );
    assert!(
        stored_secrets
            .try_get::<Option<Vec<u8>>, _>("verification_code_hash")
            .unwrap()
            .is_none()
    );
    database.cleanup().await;
}

#[tokio::test]
async fn qr_expiration_exact_session_code_limit_revocation_and_retention_fail_closed() {
    let database = TestDatabase::create().await;
    let app = app(database.pool.clone());
    let scanner_cookie = register_and_login(&app, "qr-guards@example.test").await;
    let scanner_csrf = csrf_token(&app, &scanner_cookie).await;
    let created = body_json(
        app.clone()
            .oneshot(mutation_request("/v1/qr-login/challenges", ""))
            .await
            .unwrap(),
    )
    .await;
    let challenge_id = Uuid::parse_str(created["challenge_id"].as_str().unwrap()).unwrap();
    let subscription_token = created["subscription_token"].as_str().unwrap().to_owned();
    let qr_token = created["qr_payload"]
        .as_str()
        .unwrap()
        .split("#token=")
        .nth(1)
        .unwrap();
    let bootstrap = app
        .clone()
        .oneshot(mutation_request(
            "/v1/qr-login/bootstrap",
            &format!(r#"{{"qr_token":"{qr_token}"}}"#),
        ))
        .await
        .unwrap();
    let continuation_cookie = cookie_from(&bootstrap);
    sqlx::query("UPDATE qr_scan_continuations SET expires_at=now()-interval '1 second' WHERE challenge_id=$1")
        .bind(challenge_id).execute(&database.pool).await.unwrap();
    let expired_continuation = app
        .clone()
        .oneshot(authenticated_mutation(
            "/v1/qr-login/scan",
            "",
            &format!("{scanner_cookie}; {continuation_cookie}"),
            &scanner_csrf,
        ))
        .await
        .unwrap();
    assert_eq!(expired_continuation.status(), StatusCode::GONE);

    sqlx::query(
        "UPDATE qr_login_challenges SET qr_expires_at=now()-interval '1 second' WHERE id=$1",
    )
    .bind(challenge_id)
    .execute(&database.pool)
    .await
    .unwrap();
    let expired_qr = app
        .clone()
        .oneshot(mutation_request(
            "/v1/qr-login/bootstrap",
            &format!(r#"{{"qr_token":"{qr_token}"}}"#),
        ))
        .await
        .unwrap();
    assert_eq!(expired_qr.status(), StatusCode::GONE);

    let status_request = Request::builder()
        .uri(format!("/v1/qr-login/challenges/{challenge_id}/status"))
        .header(
            header::AUTHORIZATION,
            format!("Bearer {subscription_token}"),
        )
        .body(Body::empty())
        .unwrap();
    let expired_status = app.clone().oneshot(status_request).await.unwrap();
    assert_eq!(body_json(expired_status).await["status"], "EXPIRED");

    let other_cookie = register_and_login(&app, "other-user@example.test").await;
    let hidden = app
        .clone()
        .oneshot(session_request(
            &format!("/v1/qr-login/challenges/{challenge_id}"),
            &other_cookie,
        ))
        .await
        .unwrap();
    assert_eq!(hidden.status(), StatusCode::NOT_FOUND);

    sqlx::query("UPDATE qr_scan_continuations SET expires_at=now()-interval '1 day', consumed_at=now()-interval '1 day'")
        .execute(&database.pool).await.unwrap();
    sqlx::query("UPDATE qr_login_challenges SET terminal_at=now()-interval '1 day' WHERE id=$1")
        .bind(challenge_id)
        .execute(&database.pool)
        .await
        .unwrap();
    let qr = sentinel_api::qr::QrService::new(
        database.pool.clone(),
        FingerprintKeyRing::new([("test".to_owned(), vec![9; 32])]).unwrap(),
        Arc::new(InMemoryRateLimiter::default()),
        AppEnvironment::Ci,
    );
    let now = chrono::Utc::now();
    let removed = qr.cleanup_retained(now, now).await.unwrap();
    assert_eq!(removed, (1, 1));
    database.cleanup().await;
}

#[tokio::test]
async fn qr_authorization_code_limit_approval_race_and_revocation_are_enforced() {
    let database = TestDatabase::create().await;
    let app = app(database.pool.clone());
    let email = "qr-authorization@example.test";
    let scanner_cookie = register_and_login(&app, email).await;
    let scanner_csrf = csrf_token(&app, &scanner_cookie).await;
    let guarded = create_and_scan_qr(&app, &scanner_cookie, &scanner_csrf).await;

    let credentials = format!(r#"{{"email":"{email}","password":"{TEST_PASSWORD}"}}"#);
    let same_user_login = app
        .clone()
        .oneshot(mutation_request("/v1/auth/login", &credentials))
        .await
        .unwrap();
    let other_session_cookie = cookie_from(&same_user_login);
    let hidden_from_other_session = app
        .clone()
        .oneshot(session_request(
            &format!("/v1/qr-login/challenges/{}", guarded.id),
            &other_session_cookie,
        ))
        .await
        .unwrap();
    assert_eq!(hidden_from_other_session.status(), StatusCode::NOT_FOUND);
    let visible_to_scanner = app
        .clone()
        .oneshot(session_request(
            &format!("/v1/qr-login/challenges/{}", guarded.id),
            &scanner_cookie,
        ))
        .await
        .unwrap();
    assert_eq!(visible_to_scanner.status(), StatusCode::OK);

    for attempt in 1..=5 {
        let version: i32 =
            sqlx::query_scalar("SELECT lock_version FROM qr_login_challenges WHERE id=$1")
                .bind(guarded.id)
                .fetch_one(&database.pool)
                .await
                .unwrap();
        let response = app
            .clone()
            .oneshot(authenticated_mutation(
                &format!("/v1/qr-login/challenges/{}/verify-code", guarded.id),
                &format!(r#"{{"verification_code":"invalid","lock_version":{version}}}"#),
                &scanner_cookie,
                &scanner_csrf,
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if attempt < 5 {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
    let cancelled: String =
        sqlx::query_scalar("SELECT status::text FROM qr_login_challenges WHERE id=$1")
            .bind(guarded.id)
            .fetch_one(&database.pool)
            .await
            .unwrap();
    assert_eq!(cancelled, "CANCELLED");

    let approvable = create_and_scan_qr(&app, &scanner_cookie, &scanner_csrf).await;
    let missing_csrf = app
        .clone()
        .oneshot(authenticated_mutation(
            &format!("/v1/qr-login/challenges/{}/verify-code", approvable.id),
            &format!(
                r#"{{"verification_code":"{}","lock_version":{}}}"#,
                approvable.verification_code, approvable.lock_version
            ),
            &scanner_cookie,
            "invalid",
        ))
        .await
        .unwrap();
    assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);
    let verified = app
        .clone()
        .oneshot(authenticated_mutation(
            &format!("/v1/qr-login/challenges/{}/verify-code", approvable.id),
            &format!(
                r#"{{"verification_code":"{}","lock_version":{}}}"#,
                approvable.verification_code, approvable.lock_version
            ),
            &scanner_cookie,
            &scanner_csrf,
        ))
        .await
        .unwrap();
    let verified_version = body_json(verified).await["lock_version"].as_i64().unwrap();
    let approval_uri = format!("/v1/qr-login/challenges/{}/approve", approvable.id);
    let approval_body = format!(r#"{{"lock_version":{verified_version}}}"#);
    let first = app.clone().oneshot(authenticated_mutation(
        &approval_uri,
        &approval_body,
        &scanner_cookie,
        &scanner_csrf,
    ));
    let second = app.clone().oneshot(authenticated_mutation(
        &approval_uri,
        &approval_body,
        &scanner_cookie,
        &scanner_csrf,
    ));
    let (first, second) = tokio::join!(first, second);
    let approval_statuses = [first.unwrap().status(), second.unwrap().status()];
    assert_eq!(
        approval_statuses
            .iter()
            .filter(|status| **status == StatusCode::OK)
            .count(),
        1
    );
    assert!(approval_statuses.contains(&StatusCode::CONFLICT));

    let mut logout = authenticated_mutation(
        "/v1/sessions/revoke-all",
        "",
        &scanner_cookie,
        &scanner_csrf,
    );
    logout
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    assert_eq!(
        app.clone().oneshot(logout).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
    let status: String =
        sqlx::query_scalar("SELECT status::text FROM qr_login_challenges WHERE id=$1")
            .bind(approvable.id)
            .fetch_one(&database.pool)
            .await
            .unwrap();
    assert_eq!(status, "CANCELLED");
    let active_sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.email_normalized = $1 AND s.revoked_at IS NULL",
    )
    .bind(email)
    .fetch_one(&database.pool)
    .await
    .unwrap();
    assert_eq!(active_sessions, 0);
    let exchange = app
        .oneshot(mutation_request(
            "/v1/qr-login/exchange",
            &format!(
                r#"{{"challenge_id":"{}","subscription_token":"{}"}}"#,
                approvable.id, approvable.subscription_token
            ),
        ))
        .await
        .unwrap();
    assert_eq!(exchange.status(), StatusCode::CONFLICT);
    database.cleanup().await;
}
