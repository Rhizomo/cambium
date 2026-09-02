# Cambium

[![CI](https://github.com/Rhizomo/cambium/actions/workflows/ci.yml/badge.svg)](https://github.com/Rhizomo/cambium/actions/workflows/ci.yml)

An OIDC/Keycloak translator for [Sonatype Nexus Repository 3](https://www.sonatype.com/products/sonatype-nexus-repository) (Community Edition). Nexus 3 has no native OIDC support and the one prior community plugin (`flytreeleft/nexus3-keycloak-plugin`) has been archived since 2021. Cambium closes the gap without touching Nexus's own code — no custom auth realm, no jar patching, no classloading tricks.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full design and why this approach was chosen over writing a custom Shiro `Realm`.

## Status

v1 role-sync daemon implemented. See [docs/sync-semantics.md](./docs/sync-semantics.md) for how it reconciles Keycloak group membership into Nexus roles without clobbering manually-assigned ones.

v1 ROPC-to-header-injection CLI proxy implemented (`cambium ropc-proxy`). See [docs/oidc-proxy-pairing.md](./docs/oidc-proxy-pairing.md) for the full design — why `oauth2-proxy`/Envoy can't do this, the exact request flow, config shape, caching behavior, and the security mitigations (this is a deprecated OAuth grant type per RFC 9700; the doc is explicit about what this shim does and doesn't fix).

> **Nexus must be unreachable except through the proxy.** `RutAuthRealm`
> treats the configured header as an already-authenticated principal and
> verifies nothing else — no signature, no shared secret, no source-address
> check. Anyone who can reach Nexus's port directly with that header set *is*
> that user, including Nexus's built-in `admin`. Restrict the port at the
> network layer (Kubernetes `NetworkPolicy`, firewall rule, `localhost`-only
> listener, or same-pod co-location) so the proxy is the only path in.
> This is a deployment requirement Cambium cannot enforce for you, and it is
> the single assumption the whole architecture rests on. See
> [THREAT_MODEL.md](./THREAT_MODEL.md) §2.1.

> **Run exactly one instance.** Cambium's sync manifest is a plain JSON file with no internal locking. v1 enforces this at startup with an OS-level `flock` (`LOCK_FILE`, default `/var/lib/cambium/cambium.lock`) — a second instance pointed at the same lock file refuses to start rather than racing on the manifest. Do not scale this deployment beyond `replicas: 1`. See [docs/sync-semantics.md](./docs/sync-semantics.md) for why.

## Subcommands

`cambium` is one binary with two subcommands:

- `cambium sync` (also the default with no subcommand, for backward compatibility) — the role-sync daemon.
- `cambium ropc-proxy` — the CLI/ROPC HTTP shim in front of Nexus. Config via env vars: `KEYCLOAK_ISSUER`, `KEYCLOAK_ROPC_CLIENT_ID`, `KEYCLOAK_ROPC_CLIENT_SECRET`, `IDENTITY_CLAIM` (default `preferred_username`), `NEXUS_UPSTREAM`, `RUTAUTH_HEADER`, `CACHE_TTL_SECONDS` (default `60`), `LISTEN_ADDR` (default `0.0.0.0:8090`). See [docs/oidc-proxy-pairing.md](./docs/oidc-proxy-pairing.md) section 4b for the reference config and routing setup.

## The short version

Nexus CE already ships a built-in, free capability called `RutAuthRealm` that trusts an HTTP header as an already-authenticated principal. Pair that with a real OIDC proxy in front of Nexus (handles the actual Keycloak login), and the only genuinely missing piece is keeping Nexus's own user/role assignments in sync with Keycloak group membership. That sync tool is what Cambium actually is.

## Security

Trust boundaries, deployment requirements, and known non-goals:
[THREAT_MODEL.md](./THREAT_MODEL.md).

Vulnerability reports: _(reporting address TBD — to be filled in before this
repo is publicised; until then, open a private security advisory on GitHub.)_

## License

Apache-2.0 — see [LICENSE](./LICENSE).
