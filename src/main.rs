use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tim::{
    config::AppConfig,
    crypto::JwtSigner,
    db,
    jwt::JwtService,
    oauth2::{session as sessions_mod, state_sweeper, ProviderRegistry},
    router::{build_router, AppState},
    security::{admin::AdminGate, introspect_auth::IntrospectionGate},
};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "tim", version, about = "Token Identity Manager")]
struct Cli {
    /// Path to config file (YAML). Overrides TIM_CONFIG env var.
    #[arg(short, long, env = "TIM_CONFIG")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Audit LOG-v1 FN-LOG-1: emit ANSI colour codes only when stderr is
    // a TTY (developer running `cargo run` locally). Under Docker /
    // systemd / any log-shipper pipe, disable ANSI to keep the log
    // stream SIEM-friendly and prevent attacker-injected ESC bytes
    // from blending with server-emitted noise.
    use std::io::IsTerminal;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .with_ansi(std::io::stderr().is_terminal())
        .init();

    let cli = Cli::parse();
    let config = AppConfig::load(cli.config.as_deref()).context("failed to load config")?;
    config.validate().context("config validation")?;
    info!(bind = %config.server.bind, port = config.server.port, "loaded config");
    // Boot-time diagnostic pass — logs every parsed config field
    // at INFO with WARN on non-secure or attention-required
    // settings. Grep `tim::config::diagnose` in logs.
    config.diagnose();

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
    let sessions = sessions_mod::build(&config, pool.clone()).await?;
    let admin = AdminGate::from_config(&config.security)?;
    let introspect_gate = IntrospectionGate::from_config(&config.introspection)?;

    state_sweeper::spawn(&config.oauth2, pool.clone(), sessions.clone());

    let state = AppState {
        config: Arc::new(config.clone()),
        db: pool,
        signer: Arc::new(signer),
        jwt: Arc::new(jwt_service),
        providers: Arc::new(providers),
        sessions,
        admin,
        introspect_gate,
    };

    let addr: SocketAddr = format!("{}:{}", config.server.bind, config.server.port).parse()?;
    let router = build_router(state, &config);
    info!(%addr, "TIM listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}
