//! `cambium ropc-proxy` — the ROPC-to-header-injection HTTP shim documented
//! in `docs/oidc-proxy-pairing.md` section 3/4b.
//!
//! CLI tools (`docker login`, `npm login`, `pip`/`uv` credential config) only
//! ever speak HTTP Basic Auth — they cannot follow a browser OIDC redirect.
//! Neither `oauth2-proxy` nor Envoy's native OIDC filter does
//! `grant_type=password` credential exchange (verified in
//! `docs/oidc-proxy-pairing.md`), so this module is the dedicated shim: it
//! terminates Basic Auth, exchanges the credentials against Keycloak's token
//! endpoint, extracts a configured identity claim, and reverse-proxies the
//! request to Nexus with that identity injected as the RutAuth header (and
//! the original `Authorization` header stripped).
//!
//! Security posture (see the design doc's "honest gap" section — ROPC is a
//! deprecated pattern per RFC 9700, this only mitigates, it doesn't fix
//! that): credentials are never logged, never persisted to disk, and the
//! in-memory cache is keyed by `sha256(username + password)`, never
//! plaintext.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use crate::config::RopcConfig;

#[derive(Debug, thiserror::Error)]
pub enum RopcError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("upstream Keycloak error: {0}")]
    KeycloakUpstream(String),
    #[error("token response did not contain claim {0:?}")]
    ClaimMissing(String),
    #[error("failed to decode token")]
    TokenDecodeError,
    #[error("upstream Nexus request failed: {0}")]
    UpstreamRequest(#[from] reqwest::Error),
    #[error("identity claim value is not a valid HTTP header value: {0:?}")]
    IdentityNotHeaderSafe(String),
}

// ---------------------------------------------------------------------
// Basic Auth parsing
// ---------------------------------------------------------------------

/// Parses an `Authorization: Basic <base64(user:pass)>` header value.
/// Returns `None` for anything else (missing scheme, bad base64, no colon,
/// wrong scheme entirely) — callers treat every `None` identically: a `401`
/// with `WWW-Authenticate: Basic realm="Nexus"`, per the design doc.
pub fn parse_basic_auth(header_value: &str) -> Option<(String, String)> {
    let encoded = header_value.strip_prefix("Basic ")?;
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded.trim())
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, pass) = decoded.split_once(':')?;
    if user.is_empty() {
        return None;
    }
    Some((user.to_string(), pass.to_string()))
}

fn unauthorized() -> Response {
    let mut resp = (StatusCode::UNAUTHORIZED, "").into_response();
    resp.headers_mut().insert(
        axum::http::header::WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"Basic realm="Nexus""#),
    );
    resp
}

// ---------------------------------------------------------------------
// Clock abstraction (so cache TTL is unit-testable without real sleeps)
// ---------------------------------------------------------------------

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

#[derive(Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// A controllable clock for tests: starts at `Instant::now()` at
/// construction time and only moves forward when explicitly told to via
/// [`FakeClock::advance`] — never by real wall-clock time passing, so tests
/// never need to sleep. Only used by this module's own tests (this binary
/// has no external consumers), so it's gated behind `#[cfg(test)]` rather
/// than shipped in the release binary.
#[cfg(test)]
#[derive(Clone)]
pub struct FakeClock {
    now: Arc<Mutex<Instant>>,
}

#[cfg(test)]
impl FakeClock {
    pub fn new() -> Self {
        Self {
            now: Arc::new(Mutex::new(Instant::now())),
        }
    }

    pub fn advance(&self, d: Duration) {
        let mut now = self.now.lock().unwrap();
        *now += d;
    }
}

#[cfg(test)]
impl Clock for FakeClock {
    fn now(&self) -> Instant {
        *self.now.lock().unwrap()
    }
}

// ---------------------------------------------------------------------
// Token exchange (abstracted behind a trait so tests never make a live
// Keycloak call — mirrors how the rest of this codebase keeps network calls
// behind a thin client and tests the surrounding logic in isolation, see
// `src/sync.rs`'s pure `reconcile_roles`).
// ---------------------------------------------------------------------

/// The subset of a Keycloak token response this shim cares about. Real
/// Keycloak responses have more fields (`refresh_token`,
/// `refresh_expires_in`, `token_type`, ...) — deliberately not modeled since
/// nothing here uses them.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
}

#[async_trait]
pub trait TokenExchanger: Send + Sync {
    /// Performs (or fakes) the `grant_type=password` exchange. `Ok` means
    /// Keycloak accepted the credentials; any failure — network error,
    /// non-200, `invalid_grant` in the body — must come back as
    /// [`RopcError::InvalidCredentials`] (never a more specific variant that
    /// could leak into a differentiated client-visible response) unless it's
    /// a genuine upstream/transport problem.
    async fn exchange(&self, username: &str, password: &str) -> Result<TokenResponse, RopcError>;
}

pub struct KeycloakTokenExchanger {
    http: reqwest::Client,
    issuer: String,
    client_id: String,
    client_secret: String,
}

impl KeycloakTokenExchanger {
    pub fn new(issuer: impl Into<String>, client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            issuer: issuer.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
        }
    }
}

#[async_trait]
impl TokenExchanger for KeycloakTokenExchanger {
    async fn exchange(&self, username: &str, password: &str) -> Result<TokenResponse, RopcError> {
        let url = format!("{}/protocol/openid-connect/token", self.issuer.trim_end_matches('/'));

        // Deliberately not logging `username`/`password` anywhere in this
        // function, nor the request/response bodies on the error path — see
        // docs/oidc-proxy-pairing.md's mitigations list ("never log the
        // Authorization header").
        let resp = self
            .http
            .post(&url)
            .form(&[
                ("grant_type", "password"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("username", username),
                ("password", password),
                ("scope", "openid"),
            ])
            .send()
            .await
            .map_err(|e| {
                // Transport-level failure talking to Keycloak itself (DNS,
                // connection refused, TLS, timeout) is a real operational
                // problem, distinct from "these credentials are wrong" — but
                // the caller-facing behavior per the design doc is the same
                // either way (401, nothing forwarded), so this is only kept
                // as a distinct variant for logging, not for a different
                // client response.
                RopcError::KeycloakUpstream(e.to_string())
            })?;

        let status = resp.status();
        let body_text = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            // Covers both a clean `400 invalid_grant` and any other non-200
            // — per the design doc, any failure here is a flat 401 to the
            // client with nothing forwarded and nothing logged about the
            // credentials themselves.
            return Err(RopcError::InvalidCredentials);
        }

        // Some Keycloak error responses come back with a 200 in edge cases
        // (shouldn't normally happen, but don't trust status code alone) —
        // check for an explicit `error` field too.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body_text) {
            if v.get("error").is_some() {
                return Err(RopcError::InvalidCredentials);
            }
        }

        serde_json::from_str::<TokenResponse>(&body_text).map_err(|_| RopcError::TokenDecodeError)
    }
}

// ---------------------------------------------------------------------
// Claim extraction (decodes the JWT payload — no signature verification
// needed here: Keycloak itself already authenticated the credentials via
// the password grant before minting this token, and the token traveled over
// this process's own TLS-terminated connection to Keycloak, not from an
// untrusted caller. This shim never trusts a JWT it didn't just fetch
// itself.)
// ---------------------------------------------------------------------

fn decode_jwt_claims(jwt: &str) -> Result<serde_json::Value, RopcError> {
    let mut parts = jwt.split('.');
    let _header = parts.next().ok_or(RopcError::TokenDecodeError)?;
    let payload = parts.next().ok_or(RopcError::TokenDecodeError)?;

    let decoded = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload)
        .map_err(|_| RopcError::TokenDecodeError)?;
    serde_json::from_slice(&decoded).map_err(|_| RopcError::TokenDecodeError)
}

/// Extracts `claim` from the token response, preferring the ID token (the
/// token type actually meant to carry identity claims) and falling back to
/// the access token if no ID token was returned (e.g. `scope=openid` was
/// requested but the client isn't configured to issue one).
pub fn extract_identity_claim(token: &TokenResponse, claim: &str) -> Result<String, RopcError> {
    let jwt = token.id_token.as_deref().unwrap_or(&token.access_token);
    let claims = decode_jwt_claims(jwt)?;
    claims
        .get(claim)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| RopcError::ClaimMissing(claim.to_string()))
}

// ---------------------------------------------------------------------
// Cache: sha256(username + password) -> identity claim, short TTL, memory
// only.
// ---------------------------------------------------------------------

fn cache_key(username: &str, password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    // A separator byte (rather than string concatenation) makes
    // `("ab", "c")` and `("a", "bc")` hash differently.
    hasher.update([0u8]);
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

struct CacheEntry {
    identity: String,
    expires_at: Instant,
}

pub struct TokenCache<C: Clock> {
    entries: Mutex<HashMap<String, CacheEntry>>,
    ttl: Duration,
    clock: C,
}

impl<C: Clock> TokenCache<C> {
    pub fn new(ttl: Duration, clock: C) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
            clock,
        }
    }

    fn get(&self, username: &str, password: &str) -> Option<String> {
        let key = cache_key(username, password);
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(&key)?;
        if self.clock.now() < entry.expires_at {
            Some(entry.identity.clone())
        } else {
            None
        }
    }

    fn put(&self, username: &str, password: &str, identity: String) {
        let key = cache_key(username, password);
        let expires_at = self.clock.now() + self.ttl;
        self.entries.lock().unwrap().insert(key, CacheEntry { identity, expires_at });
    }
}

/// The full authenticate-or-reject decision: cache hit, or exchange +
/// extract + cache. Deliberately network/IO-free apart from `exchanger`, so
/// it's testable against a fake exchanger + fake clock without a live
/// Keycloak.
pub async fn authenticate<C: Clock>(
    username: &str,
    password: &str,
    exchanger: &dyn TokenExchanger,
    cache: &TokenCache<C>,
    identity_claim: &str,
) -> Result<String, RopcError> {
    if let Some(identity) = cache.get(username, password) {
        return Ok(identity);
    }

    let token = exchanger.exchange(username, password).await?;
    let identity = extract_identity_claim(&token, identity_claim)?;
    cache.put(username, password, identity.clone());
    Ok(identity)
}

// ---------------------------------------------------------------------
// The reverse proxy itself
// ---------------------------------------------------------------------

/// Hop-by-hop headers per RFC 7230 §6.1 — never forwarded in either
/// direction, since they're connection-scoped, not request/response
/// semantics.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
];

fn is_forwardable_request_header(name: &HeaderName) -> bool {
    let n = name.as_str().to_ascii_lowercase();
    n != "authorization" && n != "host" && !HOP_BY_HOP.contains(&n.as_str())
}

fn is_forwardable_response_header(name: &HeaderName) -> bool {
    let n = name.as_str().to_ascii_lowercase();
    !HOP_BY_HOP.contains(&n.as_str())
}

pub struct RopcState {
    pub exchanger: Arc<dyn TokenExchanger>,
    pub cache: Arc<TokenCache<SystemClock>>,
    pub identity_claim: String,
    pub rutauth_header: HeaderName,
    pub nexus_upstream: String,
    pub http: reqwest::Client,
    // Test/observability hook: counts requests that reached the proxy
    // handler at all (used by the live sanity check, harmless in prod).
    pub requests_handled: AtomicU64,
}

async fn proxy_handler(State(state): State<Arc<RopcState>>, req: Request) -> Response {
    state.requests_handled.fetch_add(1, Ordering::Relaxed);

    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    let Some(auth_header) = auth_header else {
        return unauthorized();
    };
    let Some((username, password)) = parse_basic_auth(auth_header) else {
        return unauthorized();
    };

    let identity = match authenticate(&username, &password, state.exchanger.as_ref(), &state.cache, &state.identity_claim).await {
        Ok(identity) => identity,
        Err(e) => {
            // Never log `username`/`password` themselves; the error
            // variant and (for ClaimMissing) the claim name are safe to log.
            warn!(error = %e, "ROPC authentication rejected");
            return unauthorized();
        }
    };

    match forward_to_nexus(&state, &identity, req).await {
        Ok(resp) => resp,
        Err(RopcError::IdentityNotHeaderSafe(bad_identity)) => {
            // `{:?}` (Debug) escapes control characters/newlines, so this
            // can't be used to inject fake log lines even though
            // `bad_identity` is attacker-influenced (it came from a token
            // claim, not from our own trusted config).
            warn!(
                identity = ?bad_identity,
                "identity claim is not a valid HTTP header value — rejecting request rather than forwarding an empty RutAuth header"
            );
            (StatusCode::INTERNAL_SERVER_ERROR, "identity claim could not be forwarded").into_response()
        }
        Err(e) => {
            warn!(error = %e, "failed to reach Nexus upstream");
            (StatusCode::BAD_GATEWAY, "upstream request failed").into_response()
        }
    }
}

async fn forward_to_nexus(state: &Arc<RopcState>, identity: &str, req: Request) -> Result<Response, RopcError> {
    let (parts, body) = req.into_parts();
    let upstream_url = build_upstream_url(&state.nexus_upstream, &parts.uri);

    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);

    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        if is_forwardable_request_header(name) {
            if let Ok(v) = reqwest::header::HeaderValue::from_bytes(value.as_bytes()) {
                if let Ok(n) = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()) {
                    headers.append(n, v);
                }
            }
        }
    }
    // If the identity claim can't be encoded as a valid HTTP header value
    // (Keycloak claims are fairly permissive about content — a raw
    // newline/control character, non-ASCII byte, etc. is possible depending
    // on realm config), this must be a hard failure, not a silent
    // downgrade. Falling back to an empty header would forward the request
    // to Nexus with no usable principal at all — a fail-open hole in the
    // authentication path. Reject before anything is sent upstream.
    let rutauth_value = reqwest::header::HeaderValue::from_str(identity)
        .map_err(|_| RopcError::IdentityNotHeaderSafe(identity.to_string()))?;
    headers.insert(
        reqwest::header::HeaderName::from_bytes(state.rutauth_header.as_str().as_bytes()).unwrap(),
        rutauth_value,
    );

    // Stream the request body straight through rather than buffering it —
    // CLI clients this shim exists for (`docker push`, in particular) can
    // send multi-GB layer blobs; buffering the whole thing in memory per
    // request would make that a real problem.
    let body_stream = body.into_data_stream();
    let reqwest_body = reqwest::Body::wrap_stream(body_stream);

    let upstream_resp = state
        .http
        .request(method, upstream_url)
        .headers(headers)
        .body(reqwest_body)
        .send()
        .await?;

    let status = StatusCode::from_u16(upstream_resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut resp_headers = HeaderMap::new();
    for (name, value) in upstream_resp.headers().iter() {
        let Ok(axum_name) = HeaderName::from_bytes(name.as_str().as_bytes()) else {
            continue;
        };
        if !is_forwardable_response_header(&axum_name) {
            continue;
        }
        if let Ok(v) = HeaderValue::from_bytes(value.as_bytes()) {
            resp_headers.append(axum_name, v);
        }
    }

    let resp_body_stream = upstream_resp.bytes_stream();
    let body = Body::from_stream(resp_body_stream);

    let mut response = Response::builder().status(status).body(body).unwrap_or_else(|_| {
        Response::builder().status(StatusCode::BAD_GATEWAY).body(Body::empty()).unwrap()
    });
    *response.headers_mut() = resp_headers;
    Ok(response)
}

fn build_upstream_url(base: &str, uri: &Uri) -> String {
    let base = base.trim_end_matches('/');
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    format!("{base}{path_and_query}")
}

pub fn build_router(state: Arc<RopcState>) -> Router {
    Router::new().fallback(any(proxy_handler)).with_state(state)
}

pub async fn run(config: RopcConfig) -> anyhow::Result<()> {
    info!(
        listen_addr = %config.listen_addr,
        nexus_upstream = %config.nexus_upstream,
        rutauth_header = %config.rutauth_header,
        identity_claim = %config.identity_claim,
        cache_ttl_seconds = config.cache_ttl_seconds,
        "cambium ropc-proxy starting"
    );

    let exchanger: Arc<dyn TokenExchanger> = Arc::new(KeycloakTokenExchanger::new(
        config.keycloak_issuer.clone(),
        config.keycloak_ropc_client_id.clone(),
        config.keycloak_ropc_client_secret.clone(),
    ));
    let cache = Arc::new(TokenCache::new(Duration::from_secs(config.cache_ttl_seconds), SystemClock));
    let rutauth_header = HeaderName::from_bytes(config.rutauth_header.as_bytes())
        .map_err(|e| anyhow::anyhow!("invalid RUTAUTH_HEADER {:?}: {e}", config.rutauth_header))?;

    let state = Arc::new(RopcState {
        exchanger,
        cache,
        identity_claim: config.identity_claim,
        rutauth_header,
        nexus_upstream: config.nexus_upstream,
        http: reqwest::Client::new(),
        requests_handled: AtomicU64::new(0),
    });

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    info!(addr = %config.listen_addr, "listening");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    // -------------------------------------------------------------
    // Basic Auth parsing
    // -------------------------------------------------------------

    #[test]
    fn parses_valid_basic_auth() {
        // "alice:s3cret" base64-encoded
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"alice:s3cret");
        let header = format!("Basic {encoded}");
        let (user, pass) = parse_basic_auth(&header).expect("should parse");
        assert_eq!(user, "alice");
        assert_eq!(pass, "s3cret");
    }

    #[test]
    fn password_containing_colon_is_preserved_in_full() {
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"alice:pass:with:colons");
        let header = format!("Basic {encoded}");
        let (user, pass) = parse_basic_auth(&header).expect("should parse");
        assert_eq!(user, "alice");
        assert_eq!(pass, "pass:with:colons");
    }

    #[test]
    fn rejects_missing_basic_prefix() {
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"alice:s3cret");
        assert!(parse_basic_auth(&encoded).is_none());
    }

    #[test]
    fn rejects_bearer_scheme() {
        assert!(parse_basic_auth("Bearer sometoken").is_none());
    }

    #[test]
    fn rejects_malformed_base64() {
        assert!(parse_basic_auth("Basic not-valid-base64!!!").is_none());
    }

    #[test]
    fn rejects_missing_colon() {
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"no-colon-here");
        let header = format!("Basic {encoded}");
        assert!(parse_basic_auth(&header).is_none());
    }

    #[test]
    fn rejects_empty_username() {
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b":somepassword");
        let header = format!("Basic {encoded}");
        assert!(parse_basic_auth(&header).is_none());
    }

    #[test]
    fn empty_password_is_allowed_by_the_parser() {
        // Basic-Auth syntax itself permits an empty password; whether
        // Keycloak accepts it is a separate (exchange-time) concern.
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"alice:");
        let header = format!("Basic {encoded}");
        let (user, pass) = parse_basic_auth(&header).expect("should parse");
        assert_eq!(user, "alice");
        assert_eq!(pass, "");
    }

    // -------------------------------------------------------------
    // Claim extraction
    // -------------------------------------------------------------

    fn fake_jwt(claims: serde_json::Value) -> String {
        let header = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, b"{\"alg\":\"none\"}");
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            serde_json::to_vec(&claims).unwrap(),
        );
        format!("{header}.{payload}.fakesig")
    }

    #[test]
    fn extracts_claim_from_id_token_when_present() {
        let id_token = fake_jwt(serde_json::json!({"preferred_username": "alice"}));
        let token = TokenResponse {
            access_token: "irrelevant".to_string(),
            id_token: Some(id_token),
        };
        let claim = extract_identity_claim(&token, "preferred_username").unwrap();
        assert_eq!(claim, "alice");
    }

    #[test]
    fn falls_back_to_access_token_when_no_id_token() {
        let access_token = fake_jwt(serde_json::json!({"preferred_username": "bob"}));
        let token = TokenResponse {
            access_token,
            id_token: None,
        };
        let claim = extract_identity_claim(&token, "preferred_username").unwrap();
        assert_eq!(claim, "bob");
    }

    #[test]
    fn missing_claim_is_an_error() {
        let id_token = fake_jwt(serde_json::json!({"sub": "abc-123"}));
        let token = TokenResponse {
            access_token: "irrelevant".to_string(),
            id_token: Some(id_token),
        };
        let err = extract_identity_claim(&token, "preferred_username").unwrap_err();
        assert!(matches!(err, RopcError::ClaimMissing(c) if c == "preferred_username"));
    }

    #[test]
    fn operator_configurable_claim_name_is_respected() {
        let id_token = fake_jwt(serde_json::json!({"email": "alice@example.com", "preferred_username": "alice"}));
        let token = TokenResponse {
            access_token: "irrelevant".to_string(),
            id_token: Some(id_token),
        };
        let claim = extract_identity_claim(&token, "email").unwrap();
        assert_eq!(claim, "alice@example.com");
    }

    #[test]
    fn malformed_jwt_is_a_decode_error() {
        let token = TokenResponse {
            access_token: "not-a-jwt".to_string(),
            id_token: None,
        };
        let err = extract_identity_claim(&token, "preferred_username").unwrap_err();
        assert!(matches!(err, RopcError::TokenDecodeError));
    }

    // -------------------------------------------------------------
    // Cache key / TTL behavior, via a fake exchanger + fake clock (no real
    // sleeps, no live network).
    // -------------------------------------------------------------

    struct CountingExchanger {
        calls: AtomicUsize,
        result: TokenResponse,
        should_fail: bool,
    }

    #[async_trait]
    impl TokenExchanger for CountingExchanger {
        async fn exchange(&self, _username: &str, _password: &str) -> Result<TokenResponse, RopcError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.should_fail {
                Err(RopcError::InvalidCredentials)
            } else {
                Ok(self.result.clone())
            }
        }
    }

    fn make_exchanger(username_claim: &str) -> CountingExchanger {
        let id_token = fake_jwt(serde_json::json!({"preferred_username": username_claim}));
        CountingExchanger {
            calls: AtomicUsize::new(0),
            result: TokenResponse {
                access_token: "irrelevant".to_string(),
                id_token: Some(id_token),
            },
            should_fail: false,
        }
    }

    #[tokio::test]
    async fn repeated_credentials_within_ttl_hit_the_cache_not_keycloak() {
        let exchanger = make_exchanger("alice");
        let clock = FakeClock::new();
        let cache = TokenCache::new(Duration::from_secs(60), clock.clone());

        let first = authenticate("alice", "pw", &exchanger, &cache, "preferred_username").await.unwrap();
        assert_eq!(first, "alice");
        assert_eq!(exchanger.calls.load(Ordering::SeqCst), 1);

        // Well within the 60s TTL — no time has passed at all.
        let second = authenticate("alice", "pw", &exchanger, &cache, "preferred_username").await.unwrap();
        assert_eq!(second, "alice");
        assert_eq!(exchanger.calls.load(Ordering::SeqCst), 1, "second call within TTL must be served from cache");
    }

    #[tokio::test]
    async fn cache_expires_after_ttl_and_re_exchanges() {
        let exchanger = make_exchanger("alice");
        let clock = FakeClock::new();
        let cache = TokenCache::new(Duration::from_secs(60), clock.clone());

        authenticate("alice", "pw", &exchanger, &cache, "preferred_username").await.unwrap();
        assert_eq!(exchanger.calls.load(Ordering::SeqCst), 1);

        clock.advance(Duration::from_secs(61));

        authenticate("alice", "pw", &exchanger, &cache, "preferred_username").await.unwrap();
        assert_eq!(exchanger.calls.load(Ordering::SeqCst), 2, "past TTL must re-exchange with Keycloak");
    }

    #[tokio::test]
    async fn different_passwords_for_the_same_username_are_different_cache_keys() {
        let exchanger = make_exchanger("alice");
        let clock = FakeClock::new();
        let cache = TokenCache::new(Duration::from_secs(60), clock.clone());

        authenticate("alice", "pw1", &exchanger, &cache, "preferred_username").await.unwrap();
        authenticate("alice", "pw2", &exchanger, &cache, "preferred_username").await.unwrap();
        assert_eq!(exchanger.calls.load(Ordering::SeqCst), 2, "different passwords must not share a cache entry");
    }

    #[tokio::test]
    async fn failed_exchange_is_never_cached() {
        let exchanger = CountingExchanger {
            calls: AtomicUsize::new(0),
            result: TokenResponse { access_token: String::new(), id_token: None },
            should_fail: true,
        };
        let clock = FakeClock::new();
        let cache = TokenCache::new(Duration::from_secs(60), clock);

        let first = authenticate("alice", "wrongpw", &exchanger, &cache, "preferred_username").await;
        assert!(first.is_err());
        let second = authenticate("alice", "wrongpw", &exchanger, &cache, "preferred_username").await;
        assert!(second.is_err());
        assert_eq!(exchanger.calls.load(Ordering::SeqCst), 2, "a failed exchange must never be cached — every attempt re-checks Keycloak");
    }

    #[test]
    fn cache_key_differs_for_different_username_password_boundary_split() {
        // Guards against a naive `username + password` string-concat cache
        // key colliding across a shifted boundary, e.g. ("ab","c") vs
        // ("a","bc").
        let k1 = cache_key("ab", "c");
        let k2 = cache_key("a", "bc");
        assert_ne!(k1, k2);
    }

    #[test]
    fn cache_key_never_contains_plaintext_credentials() {
        let key = cache_key("alice", "supersecretpassword");
        assert!(!key.contains("alice"));
        assert!(!key.contains("supersecretpassword"));
        // sha256 hex digest is 64 chars
        assert_eq!(key.len(), 64);
    }

    // -------------------------------------------------------------
    // Header forwarding rules
    // -------------------------------------------------------------

    #[test]
    fn authorization_and_hop_by_hop_headers_are_not_forwardable() {
        assert!(!is_forwardable_request_header(&axum::http::header::AUTHORIZATION));
        assert!(!is_forwardable_request_header(&axum::http::header::HOST));
        assert!(!is_forwardable_request_header(&HeaderName::from_static("connection")));
        assert!(!is_forwardable_request_header(&HeaderName::from_static("transfer-encoding")));
    }

    #[test]
    fn ordinary_headers_are_forwardable() {
        assert!(is_forwardable_request_header(&axum::http::header::CONTENT_TYPE));
        assert!(is_forwardable_request_header(&HeaderName::from_static("x-custom-header")));
    }

    #[test]
    fn build_upstream_url_preserves_path_and_query() {
        let uri: Uri = "/repository/npm-hosted/some-pkg?foo=bar".parse().unwrap();
        let url = build_upstream_url("http://nexus:8081/", &uri);
        assert_eq!(url, "http://nexus:8081/repository/npm-hosted/some-pkg?foo=bar");
    }

    // -------------------------------------------------------------
    // Fail-closed on a header-unsafe identity claim (regression test):
    // forward_to_nexus must reject the request outright rather than
    // silently substituting an empty RutAuth header and still forwarding
    // to Nexus.
    // -------------------------------------------------------------

    struct NeverCalledExchanger;

    #[async_trait]
    impl TokenExchanger for NeverCalledExchanger {
        async fn exchange(&self, _username: &str, _password: &str) -> Result<TokenResponse, RopcError> {
            panic!("forward_to_nexus must not need to re-authenticate; the exchanger should never be called by this test");
        }
    }

    fn dummy_state(nexus_upstream: &str) -> Arc<RopcState> {
        Arc::new(RopcState {
            exchanger: Arc::new(NeverCalledExchanger),
            cache: Arc::new(TokenCache::new(Duration::from_secs(60), SystemClock)),
            identity_claim: "preferred_username".to_string(),
            rutauth_header: HeaderName::from_static("x-forwarded-user"),
            nexus_upstream: nexus_upstream.to_string(),
            http: reqwest::Client::new(),
            requests_handled: AtomicU64::new(0),
        })
    }

    fn dummy_request() -> Request {
        Request::builder()
            .method("GET")
            .uri("/repository/npm-hosted/some-pkg")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn header_unsafe_identity_claim_is_rejected_not_forwarded_with_empty_header() {
        // Point at an address nothing is listening on. If the bug were
        // still present (silently falling back to an empty header value),
        // this test would instead observe a connection-refused
        // `UpstreamRequest` error, proving the code proceeded to actually
        // contact "Nexus" with a blank principal. The fix must reject
        // before ever reaching this point.
        let state = dummy_state("http://127.0.0.1:1"); // port 0/1 is never a live listener
        let identity_with_raw_newline = "alice\ninjected-header: evil";

        let result = forward_to_nexus(&state, identity_with_raw_newline, dummy_request()).await;

        match result {
            Err(RopcError::IdentityNotHeaderSafe(bad)) => {
                assert_eq!(bad, identity_with_raw_newline);
            }
            other => panic!("expected IdentityNotHeaderSafe, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn header_unsafe_identity_claim_with_control_character_is_rejected() {
        let state = dummy_state("http://127.0.0.1:1");
        // A raw control character (not just newline) is also invalid in an
        // HTTP header value.
        let identity_with_control_char = "alice\u{0007}bell";

        let result = forward_to_nexus(&state, identity_with_control_char, dummy_request()).await;

        assert!(
            matches!(result, Err(RopcError::IdentityNotHeaderSafe(_))),
            "expected rejection for a control-character identity claim, got {result:?}"
        );
    }

    #[test]
    fn ordinary_identity_claim_is_still_accepted() {
        // Sanity check the fix didn't make the header-value check overly
        // strict for the common case.
        assert!(HeaderValue::from_str("alice").is_ok());
        assert!(HeaderValue::from_str("alice@example.com").is_ok());
    }
}
