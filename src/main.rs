mod config;
mod error;
mod keycloak;
mod lock;
mod manifest;
mod nexus;
mod sync;

use tracing::{error, info};

use config::Config;
use keycloak::KeycloakClient;
use manifest::Manifest;
use nexus::NexusClient;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

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
