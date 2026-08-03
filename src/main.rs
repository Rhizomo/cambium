mod config;
mod error;
mod keycloak;
mod lock;
mod manifest;
mod nexus;
mod ropc;
mod sync;

use clap::{Parser, Subcommand};
use tracing::{error, info};

use config::{Config, RopcConfig};
use keycloak::KeycloakClient;
use manifest::Manifest;
use nexus::NexusClient;

/// Cambium: a Keycloak/OIDC translator for Nexus Repository 3 CE. See
/// ARCHITECTURE.md for the full design.
#[derive(Parser, Debug)]
#[command(name = "cambium", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Role-sync daemon: reconciles Keycloak group membership into Nexus
    /// User/Role assignments (see docs/sync-semantics.md). This is the
    /// default when no subcommand is given, for backward compatibility with
    /// existing deployments that invoke `cambium` with no arguments.
    Sync,
    /// ROPC-to-header-injection HTTP proxy for CLI tools (docker/npm/pip)
    /// that can't do a browser OIDC redirect. See
    /// docs/oidc-proxy-pairing.md section 3/4b.
    RopcProxy,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    let cli = Cli::parse();
    match cli.command.unwrap_or(Commands::Sync) {
        Commands::Sync => run_sync().await,
        Commands::RopcProxy => run_ropc_proxy().await,
    }
}

async fn run_ropc_proxy() {
    let config = RopcConfig::from_env();
    if let Err(e) = ropc::run(config).await {
        error!(error = %e, "ropc-proxy exited with an error");
        std::process::exit(1);
    }
}

async fn run_sync() {
    let config = Config::from_env();
    info!(
        keycloak_realm = %config.keycloak_realm,
        nexus_url = %config.nexus_url,
        poll_interval_seconds = config.poll_interval_seconds,
        mapped_roles = config.role_map.len(),
        "cambium starting"
    );

    // Cambium v1 is single-instance-only: the manifest is a plain JSON file
    // with no internal locking, so two processes racing on it would
    // silently corrupt sync state (see src/lock.rs and
    // docs/sync-semantics.md). Fail fast and loudly instead of trusting
    // operators to never set replicas > 1.
    let _singleton_guard = match lock::acquire(&config.lock_file) {
        Ok(guard) => guard,
        Err(e) => {
            error!(error = %e, lock_file = %config.lock_file.display(), "refusing to start");
            std::process::exit(1);
        }
    };

    let kc = KeycloakClient::new(
        config.keycloak_url.clone(),
        config.keycloak_realm.clone(),
        config.keycloak_client_id.clone(),
        config.keycloak_client_secret.clone(),
    );
    let nexus = NexusClient::new(
        config.nexus_url.clone(),
        config.nexus_username.clone(),
        config.nexus_password.clone(),
    );

    let mut manifest = match Manifest::load(&config.state_file) {
        Ok(m) => m,
        Err(e) => {
            error!(error = %e, "failed to load manifest, starting from an empty one (see docs/sync-semantics.md for why this fails safe)");
            Manifest::default()
        }
    };

    let mut interval = tokio::time::interval(std::time::Duration::from_secs(
        config.poll_interval_seconds,
    ));

    loop {
        interval.tick().await;
        info!("starting reconciliation pass");
        let result = sync::run_pass(
            &kc,
            &nexus,
            &config.keycloak_realm,
            &config.role_map,
            &mut manifest,
            &config.fallback_email_domain,
            &config.state_file,
        )
        .await;

        match result {
            Ok(()) => info!("reconciliation pass complete"),
            Err(e) => error!(error = %e, "reconciliation pass failed, will retry next interval"),
        }
    }
}
