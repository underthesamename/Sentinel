//! Adaptadores de PostgreSQL, hashing, relógio, rate limiting e publicação de eventos.

pub mod auth;
pub mod security;

use std::time::Duration;

use sqlx::{PgPool, postgres::PgPoolOptions};

#[derive(Debug, Clone, Copy)]
pub struct PostgresPoolConfig {
    pub max_connections: u32,
    pub acquire_timeout: Duration,
    pub connect_timeout: Duration,
}

pub async fn connect_postgres(
    database_url: &str,
    config: PostgresPoolConfig,
) -> Result<PgPool, sqlx::Error> {
    let connect = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .acquire_timeout(config.acquire_timeout)
        .connect(database_url);

    match tokio::time::timeout(config.connect_timeout, connect).await {
        Ok(result) => result,
        Err(_) => Err(sqlx::Error::PoolTimedOut),
    }
}
