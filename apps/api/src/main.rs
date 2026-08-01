use std::sync::Arc;

use anyhow::Context;
use sentinel_api::{AppState, DatabaseHealthProbe, build_router, config::AppConfig, init_tracing};
use sentinel_infrastructure::{PostgresPoolConfig, connect_postgres, security::FingerprintKeyRing};
use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let config = AppConfig::from_env().context("configuração inválida")?;
    let _fingerprint_keys = FingerprintKeyRing::new(config.token_fingerprint_keys())
        .context("keyring de fingerprints inválido")?;
    let public_config = Arc::new(config.public());

    let pool = connect_postgres(
        config.database_url(),
        PostgresPoolConfig {
            max_connections: config.database.max_connections,
            acquire_timeout: config.database.acquire_timeout,
            connect_timeout: config.database.connect_timeout,
        },
    )
    .await
    .context("não foi possível conectar ao PostgreSQL")?;

    if config.database.run_migrations {
        info!(
            event = "database.migrations.started",
            "executando migrações"
        );
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .context("não foi possível aplicar as migrações")?;
        info!(
            event = "database.migrations.completed",
            "migrações concluídas"
        );
    }

    let state = AppState::new(
        pool.clone(),
        public_config,
        Arc::new(DatabaseHealthProbe::new(pool)),
    );
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(config.bind_address())
        .await
        .context("não foi possível abrir o listener HTTP")?;

    info!(
        event = "api.started",
        address = %config.bind_address(),
        environment = %config.environment,
        "Sentinel API iniciada"
    );

    if let Err(error) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
    {
        error!(event = "api.serve.failed", error = %error, "servidor HTTP encerrou com erro");
        return Err(error.into());
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            error!(event = "api.signal.failed", error = %error, "falha ao instalar sinal Ctrl+C");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                error!(event = "api.signal.failed", error = %error, "falha ao instalar SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }

    info!(
        event = "api.shutdown.started",
        "encerramento gracioso solicitado"
    );
}
