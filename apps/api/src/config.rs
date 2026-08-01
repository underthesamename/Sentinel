use std::{env, fmt, net::SocketAddr, str::FromStr, time::Duration};

use thiserror::Error;

const DEFAULT_SERVICE_NAME: &str = "sentinel-api";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEnvironment {
    Local,
    Ci,
    Staging,
    Production,
}

impl AppEnvironment {
    const fn migrations_default(self) -> bool {
        matches!(self, Self::Local | Self::Ci)
    }
}

impl fmt::Display for AppEnvironment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Local => "local",
            Self::Ci => "ci",
            Self::Staging => "staging",
            Self::Production => "production",
        };
        formatter.write_str(value)
    }
}

impl FromStr for AppEnvironment {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "local" => Ok(Self::Local),
            "ci" => Ok(Self::Ci),
            "staging" => Ok(Self::Staging),
            "production" => Ok(Self::Production),
            _ => Err(ConfigError::InvalidValue { key: "APP_ENV" }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    pub max_connections: u32,
    pub acquire_timeout: Duration,
    pub connect_timeout: Duration,
    pub run_migrations: bool,
}

#[derive(Debug, Clone)]
pub struct PublicConfig {
    pub service_name: &'static str,
    pub environment: AppEnvironment,
    pub app_origin: String,
    pub websocket_origins: Vec<String>,
    pub session_idle_ttl: Duration,
    pub session_absolute_ttl: Duration,
    pub csrf_ttl: Duration,
    pub session_touch_interval: Duration,
    pub qr_challenge_ttl: Duration,
    pub qr_approval_ttl: Duration,
    pub qr_continuation_ttl: Duration,
}

#[derive(Clone)]
pub struct AppConfig {
    pub environment: AppEnvironment,
    bind_address: SocketAddr,
    app_origin: String,
    websocket_origins: Vec<String>,
    database_url: String,
    token_fingerprint_keys: Vec<(String, Vec<u8>)>,
    session_idle_ttl: Duration,
    session_absolute_ttl: Duration,
    csrf_ttl: Duration,
    session_touch_interval: Duration,
    qr_challenge_ttl: Duration,
    qr_approval_ttl: Duration,
    qr_continuation_ttl: Duration,
    pub database: DatabaseConfig,
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppConfig")
            .field("environment", &self.environment)
            .field("bind_address", &self.bind_address)
            .field("app_origin", &self.app_origin)
            .field("websocket_origins", &self.websocket_origins)
            .field("database_url", &"[REDACTED]")
            .field("token_fingerprint_keys", &"[REDACTED]")
            .field("database", &self.database)
            .finish()
    }
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(|key| env::var(key).ok())
    }

    fn from_source(source: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let environment = source("APP_ENV")
            .unwrap_or_else(|| "local".to_owned())
            .parse()?;
        let bind_address = parse_required_or_default(&source, "API_BIND", "0.0.0.0:8080")?;
        let app_origin = source("APP_ORIGIN").unwrap_or_else(|| "http://localhost:5173".to_owned());
        validate_origin(&app_origin, environment)?;
        let websocket_origins = source("WS_ORIGIN_ALLOWLIST")
            .unwrap_or_else(|| app_origin.clone())
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if websocket_origins.is_empty()
            || websocket_origins
                .iter()
                .any(|origin| validate_origin(origin, environment).is_err())
        {
            return Err(ConfigError::InvalidValue {
                key: "WS_ORIGIN_ALLOWLIST",
            });
        }

        let token_fingerprint_keys = parse_fingerprint_keys(&source, environment)?;
        let cookie_secure = source("COOKIE_SECURE")
            .map(|value| parse_bool("COOKIE_SECURE", &value))
            .transpose()?
            .unwrap_or(environment != AppEnvironment::Local);
        if environment != AppEnvironment::Local && !cookie_secure {
            return Err(ConfigError::InvalidValue {
                key: "COOKIE_SECURE",
            });
        }

        let database_url = required(&source, "DATABASE_URL")?;
        validate_database_url(&database_url)?;

        let max_connections = parse_required_or_default(&source, "DB_MAX_CONNECTIONS", "10")?;
        if max_connections == 0 {
            return Err(ConfigError::InvalidValue {
                key: "DB_MAX_CONNECTIONS",
            });
        }

        let acquire_timeout = Duration::from_secs(parse_required_or_default(
            &source,
            "DB_ACQUIRE_TIMEOUT_SECS",
            "5",
        )?);
        let connect_timeout = Duration::from_secs(parse_required_or_default(
            &source,
            "DB_CONNECT_TIMEOUT_SECS",
            "10",
        )?);
        let run_migrations = match source("RUN_MIGRATIONS") {
            Some(value) => parse_bool("RUN_MIGRATIONS", &value)?,
            None => environment.migrations_default(),
        };
        let session_idle_ttl = parse_duration_value(
            "SESSION_IDLE_TTL",
            &source("SESSION_IDLE_TTL").unwrap_or_else(|| "30m".to_owned()),
        )?;
        let session_absolute_ttl = parse_duration_value(
            "SESSION_ABSOLUTE_TTL",
            &source("SESSION_ABSOLUTE_TTL").unwrap_or_else(|| "720h".to_owned()),
        )?;
        let csrf_ttl = parse_duration_value(
            "CSRF_TTL",
            &source("CSRF_TTL").unwrap_or_else(|| "30m".to_owned()),
        )?;
        let session_touch_interval = parse_duration_value(
            "SESSION_TOUCH_INTERVAL",
            &source("SESSION_TOUCH_INTERVAL").unwrap_or_else(|| "5m".to_owned()),
        )?;
        let qr_challenge_ttl = parse_duration_value(
            "QR_CHALLENGE_TTL",
            &source("QR_CHALLENGE_TTL").unwrap_or_else(|| "90s".to_owned()),
        )?;
        let qr_approval_ttl = parse_duration_value(
            "QR_APPROVAL_TTL",
            &source("QR_APPROVAL_TTL").unwrap_or_else(|| "90s".to_owned()),
        )?;
        let qr_continuation_ttl = parse_duration_value(
            "QR_CONTINUATION_TTL",
            &source("QR_CONTINUATION_TTL").unwrap_or_else(|| "5m".to_owned()),
        )?;
        if session_idle_ttl > session_absolute_ttl || session_touch_interval >= session_idle_ttl {
            return Err(ConfigError::InvalidValue {
                key: "SESSION_IDLE_TTL",
            });
        }

        Ok(Self {
            environment,
            bind_address,
            app_origin,
            websocket_origins,
            database_url,
            token_fingerprint_keys,
            session_idle_ttl,
            session_absolute_ttl,
            csrf_ttl,
            session_touch_interval,
            qr_challenge_ttl,
            qr_approval_ttl,
            qr_continuation_ttl,
            database: DatabaseConfig {
                max_connections,
                acquire_timeout,
                connect_timeout,
                run_migrations,
            },
        })
    }

    pub const fn bind_address(&self) -> SocketAddr {
        self.bind_address
    }

    pub fn database_url(&self) -> &str {
        &self.database_url
    }

    pub fn public(&self) -> PublicConfig {
        PublicConfig {
            service_name: DEFAULT_SERVICE_NAME,
            environment: self.environment,
            app_origin: self.app_origin.clone(),
            websocket_origins: self.websocket_origins.clone(),
            session_idle_ttl: self.session_idle_ttl,
            session_absolute_ttl: self.session_absolute_ttl,
            csrf_ttl: self.csrf_ttl,
            session_touch_interval: self.session_touch_interval,
            qr_challenge_ttl: self.qr_challenge_ttl,
            qr_approval_ttl: self.qr_approval_ttl,
            qr_continuation_ttl: self.qr_continuation_ttl,
        }
    }

    pub fn token_fingerprint_keys(&self) -> Vec<(String, Vec<u8>)> {
        self.token_fingerprint_keys.clone()
    }
}

fn parse_duration_value(key: &'static str, value: &str) -> Result<Duration, ConfigError> {
    let (number, multiplier) = match value.chars().last() {
        Some('s') => (&value[..value.len() - 1], 1_u64),
        Some('m') => (&value[..value.len() - 1], 60),
        Some('h') => (&value[..value.len() - 1], 3600),
        _ => return Err(ConfigError::InvalidValue { key }),
    };
    let amount = number
        .parse::<u64>()
        .map_err(|_| ConfigError::InvalidValue { key })?;
    if amount == 0 {
        return Err(ConfigError::InvalidValue { key });
    }
    amount
        .checked_mul(multiplier)
        .map(Duration::from_secs)
        .ok_or(ConfigError::InvalidValue { key })
}

fn parse_fingerprint_keys(
    source: &impl Fn(&str) -> Option<String>,
    environment: AppEnvironment,
) -> Result<Vec<(String, Vec<u8>)>, ConfigError> {
    let configured = source("TOKEN_FINGERPRINT_KEYS")
        .or_else(|| source("TOKEN_FINGERPRINT_KEY").map(|key| format!("v1:{key}")));
    let Some(configured) = configured else {
        if matches!(environment, AppEnvironment::Local | AppEnvironment::Ci) {
            return Ok(vec![("local-only".to_owned(), vec![0x5a; 32])]);
        }
        return Err(ConfigError::Missing {
            key: "TOKEN_FINGERPRINT_KEYS",
        });
    };

    let mut keys = Vec::new();
    for item in configured.split(',') {
        let Some((id, key)) = item.trim().split_once(':') else {
            return Err(ConfigError::InvalidValue {
                key: "TOKEN_FINGERPRINT_KEYS",
            });
        };
        if id.trim().is_empty()
            || key.len() < 32
            || key.contains("replace-with")
            || keys.iter().any(|(existing, _)| existing == id)
        {
            return Err(ConfigError::InvalidValue {
                key: "TOKEN_FINGERPRINT_KEYS",
            });
        }
        keys.push((id.to_owned(), key.as_bytes().to_vec()));
    }
    if keys.is_empty() {
        return Err(ConfigError::InvalidValue {
            key: "TOKEN_FINGERPRINT_KEYS",
        });
    }
    Ok(keys)
}

fn required(
    source: &impl Fn(&str) -> Option<String>,
    key: &'static str,
) -> Result<String, ConfigError> {
    source(key)
        .filter(|value| !value.trim().is_empty())
        .ok_or(ConfigError::Missing { key })
}

fn parse_required_or_default<T: FromStr>(
    source: &impl Fn(&str) -> Option<String>,
    key: &'static str,
    default: &str,
) -> Result<T, ConfigError> {
    source(key)
        .unwrap_or_else(|| default.to_owned())
        .parse()
        .map_err(|_| ConfigError::InvalidValue { key })
}

fn parse_bool(key: &'static str, value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(ConfigError::InvalidValue { key }),
    }
}

fn validate_origin(value: &str, environment: AppEnvironment) -> Result<(), ConfigError> {
    let is_http = value.starts_with("http://");
    let is_https = value.starts_with("https://");
    let has_path = value
        .split_once("://")
        .is_some_and(|(_, authority)| authority.contains('/'));

    if (!is_http && !is_https) || has_path || (environment != AppEnvironment::Local && !is_https) {
        return Err(ConfigError::InvalidValue { key: "APP_ORIGIN" });
    }
    Ok(())
}

fn validate_database_url(value: &str) -> Result<(), ConfigError> {
    if !value.starts_with("postgres://") && !value.starts_with("postgresql://") {
        return Err(ConfigError::InvalidValue {
            key: "DATABASE_URL",
        });
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("variável obrigatória ausente: {key}")]
    Missing { key: &'static str },
    #[error("valor inválido para a variável: {key}")]
    InvalidValue { key: &'static str },
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config(values: &[(&str, &str)]) -> Result<AppConfig, ConfigError> {
        let values = values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect::<HashMap<_, _>>();
        AppConfig::from_source(|key| values.get(key).cloned())
    }

    #[test]
    fn parses_valid_local_configuration() {
        let result = config(&[("DATABASE_URL", "postgres://user:secret@db/sentinel")]).unwrap();
        assert_eq!(result.environment, AppEnvironment::Local);
        assert!(result.database.run_migrations);
        assert_eq!(result.database.max_connections, 10);
    }

    #[test]
    fn requires_database_url_without_exposing_a_value() {
        let error = config(&[]).unwrap_err();
        assert_eq!(
            error,
            ConfigError::Missing {
                key: "DATABASE_URL"
            }
        );
        assert!(!error.to_string().contains("secret"));
    }

    #[test]
    fn production_requires_https_origin_and_disables_migrations_by_default() {
        let valid = config(&[
            ("APP_ENV", "production"),
            ("APP_ORIGIN", "https://sentinel.example"),
            ("DATABASE_URL", "postgres://user:secret@db/sentinel"),
            (
                "TOKEN_FINGERPRINT_KEYS",
                "v1:0123456789abcdef0123456789abcdef",
            ),
        ])
        .unwrap();
        assert!(!valid.database.run_migrations);

        let error = config(&[
            ("APP_ENV", "production"),
            ("APP_ORIGIN", "http://sentinel.example"),
            ("DATABASE_URL", "postgres://user:secret@db/sentinel"),
        ])
        .unwrap_err();
        assert_eq!(error, ConfigError::InvalidValue { key: "APP_ORIGIN" });
    }

    #[test]
    fn debug_output_redacts_database_url() {
        let result =
            config(&[("DATABASE_URL", "postgres://user:super-secret@db/sentinel")]).unwrap();
        let debug = format!("{result:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super-secret"));
    }

    #[test]
    fn production_rejects_missing_weak_or_insecure_security_defaults() {
        let base = [
            ("APP_ENV", "production"),
            ("APP_ORIGIN", "https://sentinel.example"),
            ("DATABASE_URL", "postgres://user:secret@db/sentinel"),
        ];
        assert_eq!(
            config(&base).unwrap_err(),
            ConfigError::Missing {
                key: "TOKEN_FINGERPRINT_KEYS"
            }
        );

        let mut weak = base.to_vec();
        weak.push(("TOKEN_FINGERPRINT_KEYS", "v1:short"));
        assert_eq!(
            config(&weak).unwrap_err(),
            ConfigError::InvalidValue {
                key: "TOKEN_FINGERPRINT_KEYS"
            }
        );

        let mut insecure_cookie = base.to_vec();
        insecure_cookie.push((
            "TOKEN_FINGERPRINT_KEYS",
            "v1:0123456789abcdef0123456789abcdef",
        ));
        insecure_cookie.push(("COOKIE_SECURE", "false"));
        assert_eq!(
            config(&insecure_cookie).unwrap_err(),
            ConfigError::InvalidValue {
                key: "COOKIE_SECURE"
            }
        );
    }

    #[test]
    fn fingerprint_keys_support_rotation_and_are_redacted() {
        let result = config(&[
            ("DATABASE_URL", "postgres://user:secret@db/sentinel"),
            (
                "TOKEN_FINGERPRINT_KEYS",
                "v2:22222222222222222222222222222222,v1:11111111111111111111111111111111",
            ),
        ])
        .unwrap();
        assert_eq!(result.token_fingerprint_keys.len(), 2);
        let debug = format!("{result:?}");
        assert!(!debug.contains("22222222222222222222222222222222"));
    }
}
