//! Env-var configuration, following `grafter`'s `Config::from_env()` pattern
//! (`env_require` panics with a clear message on a missing required var,
//! `env_or` supplies a default).

use std::collections::HashMap;
use std::env;
use std::path::PathBuf;

use crate::error::{CambiumError, CambiumResult};

#[derive(Debug, Clone)]
pub struct Config {
    // Keycloak Admin API (service account, client-credentials grant)
    pub keycloak_url: String,
    pub keycloak_realm: String,
    pub keycloak_client_id: String,
    pub keycloak_client_secret: String,

    // Nexus REST API (a Nexus local admin/service account used only by
    // Cambium — never the end users' own credentials)
    pub nexus_url: String,
    pub nexus_username: String,
    pub nexus_password: String,

    /// Keycloak realm role name -> Nexus role ID.
    pub role_map: HashMap<String, String>,

    pub poll_interval_seconds: u64,
    pub state_file: PathBuf,
    pub fallback_email_domain: String,
    /// v1 is single-instance-only (see docs/sync-semantics.md and
    /// README.md) — this is the `flock`'d file that enforces it.
    pub lock_file: PathBuf,
}

impl Config {
    pub fn from_env() -> Self {
        let role_map_raw = env_require("ROLE_MAP");
        let role_map = parse_role_map(&role_map_raw)
            .unwrap_or_else(|e| panic!("invalid ROLE_MAP: {e}"));

        Self {
            keycloak_url: env_require("KEYCLOAK_URL"),
            keycloak_realm: env_require("KEYCLOAK_REALM"),
            keycloak_client_id: env_require("KEYCLOAK_CLIENT_ID"),
            keycloak_client_secret: env_require("KEYCLOAK_CLIENT_SECRET"),

            nexus_url: env_require("NEXUS_URL"),
            nexus_username: env_require("NEXUS_USERNAME"),
            nexus_password: env_require("NEXUS_PASSWORD"),

            role_map,

            poll_interval_seconds: env_or("POLL_INTERVAL_SECONDS", "60")
                .parse()
                .expect("POLL_INTERVAL_SECONDS must be a number"),
            state_file: PathBuf::from(env_or(
                "STATE_FILE",
                "/var/lib/cambium/state.json",
            )),
            fallback_email_domain: env_or("FALLBACK_EMAIL_DOMAIN", "cambium.invalid"),
            lock_file: PathBuf::from(env_or(
                "LOCK_FILE",
                "/var/lib/cambium/cambium.lock",
            )),
        }
    }
}

/// `"kc-role-a:nx-role-a,kc-role-b:nx-role-b"` -> map. Whitespace around
/// entries/keys/values is trimmed; empty entries (from trailing commas) are
/// skipped.
pub fn parse_role_map(raw: &str) -> CambiumResult<HashMap<String, String>> {
    let mut map = HashMap::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut parts = entry.splitn(2, ':');
        let kc_role = parts.next().map(str::trim).filter(|s| !s.is_empty());
        let nx_role = parts.next().map(str::trim).filter(|s| !s.is_empty());
        match (kc_role, nx_role) {
            (Some(k), Some(n)) => {
                map.insert(k.to_string(), n.to_string());
            }
            _ => return Err(CambiumError::InvalidRoleMapEntry(entry.to_string())),
        }
    }
    Ok(map)
}

fn env_require(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| panic!("missing required env var: {key}"))
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiple_entries() {
        let map = parse_role_map("kc-dev:nx-developer, kc-admin:nx-admin").unwrap();
        assert_eq!(map.get("kc-dev"), Some(&"nx-developer".to_string()));
        assert_eq!(map.get("kc-admin"), Some(&"nx-admin".to_string()));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn ignores_trailing_comma() {
        let map = parse_role_map("kc-dev:nx-developer,").unwrap();
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn rejects_malformed_entry() {
        assert!(parse_role_map("not-a-valid-entry").is_err());
    }
}
