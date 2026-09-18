use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tim::{
    config::AppConfig,
    crypto::JwtSigner,
    db, doctor,
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
    #[arg(short, long, env = "TIM_CONFIG", global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the HTTP server (default when no subcommand is given).
    Serve,
    /// Pre-boot validator: parse config, resolve every referenced env
    /// var, verify the JWT key file loads, print a PASS/WARN/FAIL
    /// table, exit non-zero on any FAIL. Never binds a port or opens
    /// a database connection.
    Doctor {
        /// Also exit non-zero on any WARN (for CI gating). Default
        /// treats WARN as advisory.
        #[arg(long)]
        strict: bool,
    },
    /// Probe the /health endpoint and exit 0 on 200, 1 otherwise.
    /// Wired as the container HEALTHCHECK on distroless images which
    /// have no `curl` / `wget` / shell available to Docker.
    Healthcheck {
        /// URL to probe. Defaults to http://127.0.0.1:<port> where
        /// <port> is read from tim.yaml (server.port).
        #[arg(long)]
        url: Option<String>,
        /// Overall timeout in seconds. Default 5.
        #[arg(long, default_value = "5")]
        timeout_seconds: u64,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e:?}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let command = cli.command.unwrap_or(Command::Serve);
    match command {
        Command::Doctor { strict } => {
            // Doctor prints its own structured report; do NOT install
            // the tracing subscriber (it would compete with stdout).
            let report = doctor::run(cli.config.as_deref());
            report.render_to(&mut std::io::stdout())?;
            Ok(ExitCode::from(report.exit_code(strict) as u8))
        }
        Command::Serve => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(serve(cli.config))?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Healthcheck {
            url,
            timeout_seconds,
        } => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let code = runtime.block_on(healthcheck(cli.config, url, timeout_seconds));
            Ok(ExitCode::from(code as u8))
        }
    }
}

/// Docker HEALTHCHECK entry point for the distroless image (which has
/// no `curl` / shell). Reads `server.port` from tim.yaml if `--url` is
/// omitted; probes `<url>/health` with a short timeout; exits 0 on
/// HTTP 200, 1 on anything else.
async fn healthcheck(
    config_path: Option<PathBuf>,
    url_override: Option<String>,
    timeout_seconds: u64,
) -> i32 {
    let url = match url_override {
        Some(u) => u,
        None => match AppConfig::load(config_path.as_deref()) {
            Ok(c) => format!("http://127.0.0.1:{}/health", c.server.port),
            Err(_) => "http://127.0.0.1:8085/health".into(),
        },
    };
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_seconds))
        .build()
    {
        Ok(c) => c,
        Err(_) => return 1,
    };
    match client.get(&url).send().await {
        Ok(r) if r.status().is_success() => 0,
        _ => 1,
    }
}

async fn serve(config_path: Option<PathBuf>) -> Result<()> {
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

    let config = AppConfig::load(config_path.as_deref()).context("failed to load config")?;
    config.validate().context("config validation")?;
    info!(bind = %config.server.bind, port = config.server.port, "loaded config");
    // Boot-time diagnostic pass — logs every parsed config field
    // at INFO with WARN on non-secure or attention-required
    // settings. Grep `tim::config::diagnose` in logs.
    config.diagnose();
    // Fleet §9.1: emit the TIM_OFFLINE WARN alongside other posture
    // diagnostics so operators see it in the same boot log paragraph.
    tim::http::diagnose_at_boot();

    let signer = JwtSigner::load_from_pem(&config.jwt.private_key_path, config.jwt.key_id.clone())
        .with_context(|| {
            format!(
                "failed to load JWT key from {}",
                config.jwt.private_key_path.display()
            )
        })?;
    let signer = if let Some(prev) = &config.jwt.previous_key {
        let signer = signer
            .load_previous_from_pem(&prev.private_key_path, prev.key_id.clone(), prev.retires_at)
            .with_context(|| {
                format!(
                    "failed to load previous JWT key from {}",
                    prev.private_key_path.display()
                )
            })?;
        // Boot WARN when the retirement cliff is within the operator-
        // configured window. Complements the JWKS shape by putting the
        // clock-check into the boot log paragraph.
        let days_left = (prev.retires_at - chrono::Utc::now()).num_days();
        if days_left < 0 {
            tracing::warn!(
                previous_kid = %prev.key_id,
                retires_at = %prev.retires_at,
                "previous JWT signing key retired {} day(s) ago; still loaded but excluded from JWKS + refused on verification. Remove `jwt.previous_key` from tim.yaml to clear this WARN.",
                -days_left,
            );
        } else if days_left as u32 <= config.jwt.rotation_warn_days {
            tracing::warn!(
                previous_kid = %prev.key_id,
                retires_at = %prev.retires_at,
                days_left,
                "previous JWT signing key retires in {days_left} day(s). Plan the next rotation or drop `jwt.previous_key` before it cliffs.",
            );
        } else {
            info!(
                previous_kid = %prev.key_id,
                retires_at = %prev.retires_at,
                days_left,
                "previous JWT signing key active during rotation grace period"
            );
        }
        signer
    } else {
        signer
    };
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
