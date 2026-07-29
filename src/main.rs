use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tim_on_rust::{
    config::AppConfig,
    crypto::JwtSigner,
    db,
    jwt::JwtService,
    oauth2::ProviderRegistry,
    router::{build_router, AppState},
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "tim-on-rust", version, about = "Token Identity Manager")]
struct Cli {
    /// Path to config file (YAML). Overrides TIM_CONFIG env var.
    #[arg(short, long, env = "TIM_CONFIG")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    let cli = Cli::parse();
    let config = AppConfig::load(cli.config.as_deref()).context("failed to load config")?;
    info!(bind = %config.server.bind, port = config.server.port, "loaded config");

    if config.oauth2.session_store == "memory" {
        warn!(
            "OAuth2 session store is 'memory' (in-process). Sessions will not survive restart or span replicas. \
             See STANDARDS.md §Project-specific extras and tasks/backlog/002-oauth2-session-store.md."
        );
    }

    let signer = JwtSigner::load_from_pem(&config.jwt.private_key_path, config.jwt.key_id.clone())
        .with_context(|| {
            format!(
                "failed to load JWT key from {}",
                config.jwt.private_key_path.display()
            )
        })?;
    info!(kid = %signer.kid(), "loaded RSA signing key");

    let db_url = std::env::var(&config.database.url_env).with_context(|| {
        format!(
            "database URL env var `{}` is not set (see tim.yaml database.url_env)",
            config.database.url_env
        )
    })?;
    let pool = db::connect(&db_url, &config.database).await?;
    if config.database.auto_migrate {
        db::run_migrations(&pool).await?;
        info!("database migrations applied");
    }

    let jwt_service = JwtService::new(pool.clone(), signer.clone(), config.jwt.clone());
    let providers = ProviderRegistry::from_config(&config.oauth2).await?;

    let state = AppState {
        config: Arc::new(config.clone()),
        db: pool,
        signer: Arc::new(signer),
        jwt: Arc::new(jwt_service),
        providers: Arc::new(providers),
        sessions: Arc::new(oauth2_session_store(&config)),
    };

    let addr: SocketAddr = format!("{}:{}", config.server.bind, config.server.port).parse()?;
    let router = build_router(state, &config);
    info!(%addr, "TIM-on-Rust listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

fn oauth2_session_store(config: &AppConfig) -> tim_on_rust::oauth2::session::MemoryStore {
    let ttl = std::time::Duration::from_secs(config.oauth2.session_ttl_seconds);
    tim_on_rust::oauth2::session::MemoryStore::new(ttl)
}
