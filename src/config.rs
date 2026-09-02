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
        let allow_insecure = allow_insecure_http();

        Self {
            keycloak_url: require_url("KEYCLOAK_URL", allow_insecure),
            keycloak_realm: env_require("KEYCLOAK_REALM"),
            keycloak_client_id: env_require("KEYCLOAK_CLIENT_ID"),
            keycloak_client_secret: env_require("KEYCLOAK_CLIENT_SECRET"),

            nexus_url: require_url("NEXUS_URL", allow_insecure),
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

/// Whether plaintext `http://` is permitted for the upstream URLs.
///
/// Off by default. Every one of those hops carries a credential — the user's
/// password to Keycloak, the RutAuth identity header to Nexus, a Keycloak
/// admin bearer token, Nexus admin Basic Auth — and
/// `docs/oidc-proxy-pairing.md` already lists "TLS-only end-to-end" as a
/// required mitigation. This makes that requirement enforced rather than
/// merely written down.
///
/// The escape hatch exists because same-pod loopback and the local dev stack
/// are legitimately plaintext. It has to be set deliberately, so a production
/// deployment cannot end up on plaintext by inheriting a default.
fn allow_insecure_http() -> bool {
    matches!(
        env_or("ALLOW_INSECURE_HTTP", "false").trim().to_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

/// Validates one upstream URL at startup and returns it unchanged.
///
/// Fails fast on a malformed URL, a non-HTTP scheme, a missing host, or —
/// unless `ALLOW_INSECURE_HTTP` is set — a plaintext one. Startup is the right
/// place: the alternative is discovering it per-request, which for
/// `KEYCLOAK_ISSUER` specifically means discovering it as a silent downgrade
/// of the trust the unverified-JWT decode depends on (see
/// `ropc::decode_jwt_claims` and THREAT_MODEL.md 2.4), not as an error.
///
/// Returns the input verbatim rather than `Url`'s normalized form, because
/// callers build paths by string concatenation and normalization would add a
/// trailing slash that changes the resulting URLs.
pub fn validate_upstream_url(var_name: &str, raw: &str, allow_insecure: bool) -> CambiumResult<String> {
    let parsed = url::Url::parse(raw)
        .map_err(|e| CambiumError::InvalidUpstreamUrl {
            var: var_name.to_string(),
            value: raw.to_string(),
            reason: e.to_string(),
        })?;

    let scheme = parsed.scheme();
    if scheme != "https" && scheme != "http" {
        return Err(CambiumError::InvalidUpstreamUrl {
            var: var_name.to_string(),
            value: raw.to_string(),
            reason: format!("scheme must be http or https, got {scheme:?}"),
        });
    }

    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(CambiumError::InvalidUpstreamUrl {
            var: var_name.to_string(),
            value: raw.to_string(),
            reason: "no host".to_string(),
        });
    }

    if scheme == "http" && !allow_insecure {
        return Err(CambiumError::InvalidUpstreamUrl {
            var: var_name.to_string(),
            value: raw.to_string(),
            reason: "plaintext http:// carries credentials in the clear; use https://, or set \
                     ALLOW_INSECURE_HTTP=1 to accept it deliberately (same-pod loopback, dev)"
                .to_string(),
        });
    }

    Ok(raw.to_string())
}

fn require_url(var_name: &str, allow_insecure: bool) -> String {
    let raw = env_require(var_name);
    validate_upstream_url(var_name, &raw, allow_insecure)
        .unwrap_or_else(|e| panic!("{e}"))
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
        let allow_insecure = allow_insecure_http();

        Self {
            keycloak_issuer: require_url("KEYCLOAK_ISSUER", allow_insecure),
            keycloak_ropc_client_id: env_require("KEYCLOAK_ROPC_CLIENT_ID"),
            keycloak_ropc_client_secret: env_require("KEYCLOAK_ROPC_CLIENT_SECRET"),
            identity_claim: env_or("IDENTITY_CLAIM", "preferred_username"),
            nexus_upstream: require_url("NEXUS_UPSTREAM", allow_insecure),
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
    fn https_upstream_is_accepted() {
        assert!(validate_upstream_url("NEXUS_URL", "https://nexus.example.com", false).is_ok());
        assert!(validate_upstream_url(
            "KEYCLOAK_ISSUER",
            "https://kc.example.com/realms/myrealm",
            false
        )
        .is_ok());
    }

    /// The default has to reject plaintext, or the "TLS-only end-to-end"
    /// mitigation stays a documentation claim rather than a guarantee.
    #[test]
    fn plaintext_upstream_is_rejected_by_default() {
        let err = validate_upstream_url("NEXUS_UPSTREAM", "http://nexus:8081", false)
            .expect_err("plaintext must not be accepted without the opt-in");
        let msg = err.to_string();
        assert!(msg.contains("NEXUS_UPSTREAM"), "names the var: {msg}");
        assert!(msg.contains("ALLOW_INSECURE_HTTP"), "names the escape hatch: {msg}");
    }

    /// Same-pod loopback and the dev stack are legitimately plaintext, but it
    /// has to be opted into rather than inherited from a default.
    #[test]
    fn plaintext_upstream_is_accepted_with_the_explicit_opt_in() {
        assert!(validate_upstream_url("NEXUS_UPSTREAM", "http://nexus:8081", true).is_ok());
    }

    /// A schemeless value used to fail closed as a 502 per request; catching
    /// it at startup turns a recurring runtime fault into one clear message.
    #[test]
    fn schemeless_or_malformed_upstream_is_rejected() {
        for raw in ["nexus:8081", "", "not a url", "//nexus:8081"] {
            assert!(
                validate_upstream_url("NEXUS_UPSTREAM", raw, true).is_err(),
                "{raw:?} must be rejected"
            );
        }
    }

    /// Only http(s) — a `file://` or `ftp://` upstream is always a
    /// misconfiguration, opt-in or not.
    #[test]
    fn non_http_schemes_are_rejected_even_with_the_opt_in() {
        for raw in ["file:///etc/passwd", "ftp://nexus/", "gopher://nexus/"] {
            assert!(
                validate_upstream_url("NEXUS_UPSTREAM", raw, true).is_err(),
                "{raw:?} must be rejected"
            );
        }
    }

    /// Returned verbatim: callers concatenate paths onto these strings, and
    /// `Url`'s normalized form would add a trailing slash and change the
    /// resulting request URLs.
    #[test]
    fn a_valid_url_is_returned_unchanged() {
        let raw = "https://nexus.example.com/context";
        assert_eq!(
            validate_upstream_url("NEXUS_URL", raw, false).unwrap(),
            raw
        );
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
