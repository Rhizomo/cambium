//! Shared `reqwest::Client` construction.
//!
//! Every client in this codebase used to be `reqwest::Client::new()`, which
//! has **no timeout of any kind** — reqwest's default is unlimited. An
//! upstream that accepts a connection and then never answers would park the
//! caller forever: on the proxy path that means a request task, a connection,
//! and (via `TokenCache::coalesced_exchange`) every concurrent waiter on the
//! same credential, all held indefinitely. `docs/operations.md` describes the
//! resulting wedged pod but prescribes only a liveness probe, which is
//! recovery at the orchestrator rather than a bound in the client.
//!
//! The two constructors differ in one deliberate way, and it matters:
//!
//! - [`api_client`] sets a **total** deadline. Correct for request/response
//!   JSON calls against Keycloak's and Nexus's REST APIs, where a bounded,
//!   small response is expected and a slow one is a fault.
//! - [`streaming_client`] sets **no total deadline** and a per-read timeout
//!   instead. The ROPC proxy forwards `docker push` layer blobs that are
//!   legitimately multi-gigabyte and legitimately slow; a total deadline
//!   would cap transfer size as a function of bandwidth and break exactly the
//!   traffic the shim exists to carry. A read timeout resets on every
//!   successful read, so it catches a *stalled* connection without caring how
//!   long a healthy transfer runs.

use std::time::Duration;

/// Applies to the connect phase only, so an unroutable or blackholed upstream
/// fails fast instead of waiting on the OS default TCP timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Total deadline for a REST call. Generous for a JSON request/response
/// against Keycloak or Nexus; anything slower is a fault worth surfacing to
/// the retry that the next poll interval provides anyway.
const API_TIMEOUT: Duration = Duration::from_secs(30);

/// Per-read timeout for proxied traffic. Resets after each successful read,
/// so it bounds a stall rather than the total transfer.
const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// For bounded request/response JSON calls (Keycloak Admin API, Nexus REST
/// API, the ROPC token exchange).
pub fn api_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(API_TIMEOUT)
        .build()
        .expect("reqwest client construction cannot fail with a rustls backend and no proxy config")
}

/// For the ROPC proxy's forwarding path, where request and response bodies
/// are streamed and may be arbitrarily large.
pub fn streaming_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(STREAM_READ_TIMEOUT)
        .build()
        .expect("reqwest client construction cannot fail with a rustls backend and no proxy config")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both constructors must actually build — the `expect`s above are
    /// load-bearing, and a feature-flag change to `reqwest` could invalidate
    /// them silently otherwise.
    #[test]
    fn both_clients_construct() {
        let _ = api_client();
        let _ = streaming_client();
    }

    /// The streaming client must not carry a total deadline: a `docker push`
    /// of a multi-GB layer is legitimately slower than any fixed cap, so a
    /// total timeout would make transfer success depend on bandwidth. This
    /// and its sibling below assert the distinction the module exists to draw.
    ///
    /// Both check `reqwest`'s `Debug` output, the only introspection it
    /// exposes for a built `Client`. That is brittle against an upgrade
    /// renaming the field — but a rename fails the test loudly rather than
    /// silently dropping the guarantee, which is the right failure direction.
    #[test]
    fn streaming_client_has_no_total_deadline() {
        let debug = format!("{:?}", streaming_client());
        assert!(
            !debug.contains("TotalTimeout"),
            "streaming client must not set a total request timeout, got: {debug}"
        );
    }

    #[test]
    fn api_client_has_a_total_deadline() {
        let debug = format!("{:?}", api_client());
        assert!(
            debug.contains("TotalTimeout"),
            "api client must set a total request timeout, got: {debug}"
        );
    }
}
