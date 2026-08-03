# Cambium — Architecture

## What this is

Cambium is an OIDC/Keycloak translator for Sonatype Nexus Repository 3 (Community Edition — the free, standard binary distribution). Nexus 3 has no native OIDC support and no maintained community plugin fills the gap (see "Prior art" below). Cambium closes it without touching Nexus's own code at all — no custom Shiro `Realm`, no jar patching, no classloading tricks.

## Why not a custom Realm plugin

Current Nexus (verified against the vanilla `sonatype/nexus3:3.93.0` image) ships as a modern Spring Boot 3.5.x fat jar (`Main-Class: org.springframework.boot.loader.launch.JarLauncher`). There is no OSGi/Karaf container, despite legacy `-Dkaraf.*` flags some old docs still reference. The one prior community plugin, `flytreeleft/nexus3-keycloak-plugin`, targets that dead OSGi/KAR packaging model, is archived since 2021, and never supported ROPC (password-grant CLI login — required for `docker`/`npm`/`pip` command-line auth). Building a fresh custom Realm would mean solving JVM classloading/Spring Boot internals from scratch with no guarantee of a clean path — real risk for uncertain payoff.

## The actual mechanism

Nexus CE ships a built-in, free, **unpatched** capability: **`RutAuthRealm`** (`nexus-rutauth-plugin`, confirmed present in the vanilla image — not a Pro feature, not something requiring any patch). Configured via a Nexus "Capability" (`RutAuthCapabilityConfiguration`, one field: `httpHeader`, default `REMOTE_USER`). Its own UI help text: *"Handled HTTP Header should contain the name of the header that is used to source the principal of already authenticated user."*

That means Nexus already knows how to trust an externally-authenticated identity — it just needs something in front of it to do the actual authentication and pass the result through a header. That's a solved problem with mature, independent, existing tools:

```
                      ┌─────────────────────────────────────────┐
  Browser / CLI ────► │              OIDC Proxy                  │
                      │   (oauth2-proxy or equivalent)            │
                      │   - Authorization Code flow (browser)     │
                      │   - ROPC / password grant (CLI/CI)        │
                      └─────────────┬─────────────────────────────┘
                                    │ injects trusted header
                                    │ (e.g. X-Remote-User: alice@co.com)
                                    ▼
                      ┌─────────────────────────────────────────┐
                      │             Nexus Repository              │
                      │   RutAuthRealm trusts the header           │
                      │   as the authenticated principal           │
                      └─────────────┬─────────────────────────────┘
                                    │ authorization still needs
                                    │ real Nexus roles assigned
                                    ▼
                      ┌─────────────────────────────────────────┐
                      │         Cambium (this project)            │
                      │   Reads Keycloak group membership          │
                      │   Mirrors it into Nexus's native User/Role │
                      │   model via Nexus's own REST API           │
                      └─────────────────────────────────────────┘
```

RutAuth only solves **authentication** (who is this). It says nothing about **authorization** (what can they do) — Nexus still needs real `User`/`Role` records with privileges attached, exactly as it does today for any locally-managed user. That's the actual gap Cambium fills: a small, focused sync tool, not a full auth realm.

## Components

### 1. OIDC proxy pairing (docs + reference config, not code we maintain)
We don't build another OIDC proxy — that's a solved, mature problem (`oauth2-proxy` is the reference choice: widely used, actively maintained, handles both Authorization Code flow for browsers and can be configured for service-account/CLI flows). Cambium's job here is documentation + a tested reference config: how to point it at a Keycloak realm, how to configure it to inject the right header name matching Nexus's `RutAuthCapabilityConfiguration.httpHeader`, and how to wire the two together end-to-end (probably via Envoy/nginx/Traefik in front of both, matching whatever reverse-proxy the deployer already runs).

### 2. Role-sync daemon (the actual code)
Reads Keycloak group/role membership (via Keycloak's Admin REST API — same API surface Grafter already knows how to talk to) and reconciles it into Nexus's native `User`/`Role` assignments (via Nexus's own REST API, `/service/rest/v1/security/*`). Runs on an interval (polling) in v1; a webhook/event-driven model is a plausible v2 if Keycloak's event listener SPI turns out to support it cleanly — don't over-engineer v1 around that assumption.

Key design questions to resolve before writing code (do not guess — verify against real Keycloak/Nexus REST APIs):
- Does Nexus's REST API support creating/updating a `User` with roles in one call, or does it require separate user-creation and role-assignment calls?
- What happens to a Nexus user whose Keycloak group membership is removed — does Cambium revoke the Nexus role (destructive, needs to be deliberate and safe), or just stop granting new ones (safer default, but roles can go stale)?
- How does Cambium avoid fighting with roles a Nexus admin assigned manually outside of Cambium's sync (don't blindly overwrite everything Cambium didn't itself create)?
- Multi-realm support: v1 can assume a single Keycloak realm, but don't hardcode assumptions that make that impossible to extend later.

### 3. ROPC support (v1 scope, per decision — full parity with the original integration)
`oauth2-proxy` (or whichever proxy is chosen) needs to support password-grant login for CLI tools (`docker login`, `npm login`, `pip`/`uv` credentials) hitting Nexus directly, not through a browser redirect. This needs to be verified against the chosen proxy's actual capabilities — do not assume `oauth2-proxy` supports ROPC out of the box without checking; if it doesn't, this may require either a different proxy choice for the CLI path specifically, or a small dedicated ROPC-to-header-injection shim as part of Cambium itself.

## Non-goals for v1
- Not a general SSO gateway — scoped specifically to Nexus.
- Not a fork or derivative of any Sonatype code, patched or otherwise — clean-room, built only against public Nexus REST APIs and Keycloak's public Admin REST API.
- Not tied to Grafter or any specific IAM governance tool — must work standalone for any Keycloak + Nexus3 CE deployment.

## Tech stack (proposed, open to reconsidering)
Rust, matching `grafter`'s stack and the maintainer's existing tooling comfort — `reqwest` for both REST clients (Keycloak Admin API, Nexus REST API), `tokio` for the polling loop. Config via environment variables, same pattern as `grafter`.

## License
Apache-2.0.
