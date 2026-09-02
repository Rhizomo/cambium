//! Env-var configuration, following `grafter`'s `Config::from_env()` pattern
//! (`env_require` panics with a clear message on a missing required var,
//! `env_or` supplies a default).

use std::collections::{HashMap, HashSet};
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
    /// Nexus `userId`s Cambium refuses to sync, lowercased. Nexus ships
    /// built-in local accounts, and RutAuth maps a header value straight onto
    /// a `userId` — so a Keycloak user named `admin` authenticates as Nexus's
    /// built-in superuser. Cambium cannot stop RutAuth trusting the header,
    /// but it can decline to provision or modify those accounts itself.
    pub reserved_usernames: HashSet<String>,
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
            reserved_usernames: parse_reserved_usernames(&env_or(
                "RESERVED_USERNAMES",
                DEFAULT_RESERVED_USERNAMES,
            )),
            lock_file: PathBuf::from(env_or(
                "LOCK_FILE",
                "/var/lib/cambium/cambium.lock",
            )),
        }
    }
}

/// Nexus's own built-in local accounts. Overridable via `RESERVED_USERNAMES`
/// for deployments that have added more privileged local accounts of their
/// own; setting it to an empty string disables the guard entirely.
pub const DEFAULT_RESERVED_USERNAMES: &str = "admin,anonymous";

/// `"admin, anonymous"` -> lowercased set. Comparison is case-insensitive
/// because Nexus treats `userId` case-insensitively on lookup, so `Admin`
/// would reach the same built-in account as `admin`.
pub fn parse_reserved_usernames(raw: &str) -> HashSet<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect()
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

/// Env-var configuration for `cambium ropc-proxy` (see
/// `docs/oidc-proxy-pairing.md` section 4b for the reference shape). Kept as
/// a separate struct from the sync daemon's [`Config`] because the two
/// subcommands share no config surface at all — running both from the same
/// env would be more confusing than a second `from_env()`.
#[derive(Debug, Clone)]
pub struct RopcConfig {
    /// Keycloak realm issuer, e.g. `https://kc.example.com/realms/myrealm`.
    /// The token endpoint is `{issuer}/protocol/openid-connect/token`.
    pub keycloak_issuer: String,
    pub keycloak_ropc_client_id: String,
    pub keycloak_ropc_client_secret: String,
    /// Which claim in the token response identifies the principal to hand
    /// to Nexus via RutAuth. `preferred_username` by default, but
    /// operator-configurable (e.g. `email`) per the design doc.
    pub identity_claim: String,
    /// Base URL of the Nexus instance this proxy sits in front of.
    pub nexus_upstream: String,
    /// Must match `RutAuthCapabilityConfiguration.httpHeader` on the Nexus
    /// side exactly.
    pub rutauth_header: String,
    pub cache_ttl_seconds: u64,
    pub listen_addr: String,
}

impl RopcConfig {
    pub fn from_env() -> Self {
        Self {
            keycloak_issuer: env_require("KEYCLOAK_ISSUER"),
            keycloak_ropc_client_id: env_require("KEYCLOAK_ROPC_CLIENT_ID"),
            keycloak_ropc_client_secret: env_require("KEYCLOAK_ROPC_CLIENT_SECRET"),
            identity_claim: env_or("IDENTITY_CLAIM", "preferred_username"),
            nexus_upstream: env_require("NEXUS_UPSTREAM"),
            rutauth_header: env_require("RUTAUTH_HEADER"),
            cache_ttl_seconds: env_or("CACHE_TTL_SECONDS", "60")
                .parse()
                .expect("CACHE_TTL_SECONDS must be a number"),
            listen_addr: env_or("LISTEN_ADDR", "0.0.0.0:8090"),
        }
    }
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
    fn parses_reserved_usernames_lowercased_and_trimmed() {
        let set = parse_reserved_usernames(" Admin , ANONYMOUS ,, deploy-bot ");
        assert!(set.contains("admin"));
        assert!(set.contains("anonymous"));
        assert!(set.contains("deploy-bot"));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn empty_reserved_usernames_disables_the_guard() {
        assert!(parse_reserved_usernames("").is_empty());
    }

    #[test]
    fn default_reserved_usernames_cover_nexus_builtins() {
        let set = parse_reserved_usernames(DEFAULT_RESERVED_USERNAMES);
        assert!(set.contains("admin"));
        assert!(set.contains("anonymous"));
    }

    #[test]
    fn rejects_malformed_entry() {
        assert!(parse_role_map("not-a-valid-entry").is_err());
    }
}
