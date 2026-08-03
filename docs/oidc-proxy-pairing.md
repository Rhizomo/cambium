# OIDC proxy pairing — browser flow + CLI/ROPC flow

> **Status: the CLI/ROPC shim (section 3/4b) is implemented**, as
> `cambium ropc-proxy` (a subcommand of the same binary as the sync daemon,
> `src/ropc.rs`) — not just designed. See
> [ARCHITECTURE.md](../ARCHITECTURE.md) section "3. ROPC support" and
> [README.md](../README.md) for the subcommand/config summary. The browser
> path (section 4a, `oauth2-proxy` in upstream mode) remains
> docs-and-reference-config only, per this project's non-goals — Cambium
> does not ship or maintain an OIDC proxy itself.

This document answers ARCHITECTURE.md's open question: *does `oauth2-proxy`
support ROPC (password-grant) login for CLI tools, not just browser
Authorization Code flow?*

**Verified answer: no.** `oauth2-proxy` does not support ROPC and never has.
This was checked against its actual docs/config surface and GitHub issue
history, not assumed. Below is what was found, what to run instead, and a
concrete reference config for both flows. Everything here was checked by
reading `oauth2-proxy`'s own docs, Envoy's own docs, and public GitHub
issues — no live testing against any Keycloak/Nexus instance was needed to
answer this question, since it's a documentation-verifiable capability gap,
not a behavioral one.

## 1. oauth2-proxy: browser-only, confirmed

`oauth2-proxy` is architecturally a session-cookie proxy: it runs an
Authorization Code flow, sets an encrypted cookie, and on every subsequent
request either validates that cookie or (via `--skip-jwt-bearer-tokens`)
validates a *pre-existing* JWT already present in the `Authorization` header.
That second mode is bearer-token passthrough/validation, not credential
exchange — the caller must already hold a valid token from somewhere. There
is no code path anywhere in oauth2-proxy that takes a username+password and
performs `grant_type=password` against the IdP.

This is a known, long-standing gap, not an oversight nobody's raised:
[oauth2-proxy/oauth2-proxy#390](https://github.com/pusher/oauth2_proxy/issues/390)
("Support for direct access (aka resource owner) grant?") asked for exactly
this — an endpoint that accepts Basic Auth, exchanges it via
`grant_type=password` against Keycloak, and returns a session — describing
almost verbatim the `docker login`/`pip`/CLI use case. The issue was never
implemented; it was closed as stale with no maintainer commitment.

What oauth2-proxy *is* good at, confirmed from its own config docs: header
injection for the browser path. With `--pass-user-headers=true` it injects
`X-Forwarded-User`, `X-Forwarded-Email`, `X-Forwarded-Groups`,
`X-Forwarded-Preferred-Username` into the request it forwards upstream — but
**only when oauth2-proxy itself is the reverse proxy** (configured with
`--upstream=http://nexus:8081/`). If it's instead wired as an nginx
`auth_request` / Envoy `ext_authz` subrequest target, those headers land on
the *auth subrequest's response* and must be manually copied via
`auth_request_set` (nginx) or a Lua/WASM filter (Envoy) — a well-documented
footgun ([#1769](https://github.com/oauth2-proxy/oauth2-proxy/issues/1769),
[#1441](https://github.com/oauth2-proxy/oauth2-proxy/issues/1441)). **Run it
in upstream/reverse-proxy mode, not as an ext_authz sidecar, to avoid that
class of bug entirely.**

## 2. Envoy's native OIDC filter: same gap, not a better single-proxy answer

Checked because Smartech's own `devops-v2` cluster runs Envoy Gateway, and a
single-proxy answer would be simpler than pairing two components.

- Envoy Gateway's `SecurityPolicy.oidc` (as of v1.8) is documented as
  generating exactly one native `envoy.filters.http.oauth2` HTTP filter — it
  is a thin CRD wrapper, not an independent implementation.
- `envoy.filters.http.oauth2` itself implements only the three-legged
  Authorization Code flow (redirect → code → token exchange). Its docs
  describe no other grant type — no ROPC, no client-credentials passthrough
  for this purpose.
- It also has no equivalent of oauth2-proxy's `--pass-user-headers`: it can
  forward the raw access/ID token (`forward_bearer_token: true`) but does not
  extract a claim (e.g. `preferred_username`) into a plain header on its own.
  Getting from "Envoy has the ID token" to "Nexus sees `X-Remote-User: alice`"
  needs an extra Lua/WASM/ext_authz hop that oauth2-proxy gives for free.

Conclusion: Envoy's OIDC filter is not a better single-proxy replacement for
oauth2-proxy on the browser path (it does less, for equal ROPC support), and
using it doesn't remove the need for a separate CLI-path component. If a
deployer already standardizes on Envoy Gateway and wants one fewer moving
part, the browser leg *can* be done there instead of oauth2-proxy — the
tradeoff is more filter-chain plumbing to get the header right. Where the
deployer has no Envoy opinion, oauth2-proxy is the simpler default. Either
way, the CLI leg still needs a dedicated component (Section 3).

## 3. CLI/ROPC path: no proxy solves this — dedicated shim required

Neither tool does direct-credential exchange, so `docker login` / `npm
login` / `pip`/`uv` credential config (all of which send `Authorization:
Basic <base64(user:pass)>` on real requests, not a browser redirect) has no
off-the-shelf answer. Per ARCHITECTURE.md's own fallback ("a small dedicated
ROPC-to-header-injection shim as part of Cambium itself"), this is the only
viable option — confirmed, not assumed, by the above.

### What it does

A small HTTP reverse proxy, `cambium-ropc-gateway` (or a `cambium ropc-proxy`
subcommand — same Rust/`reqwest`/`tokio` stack as the sync daemon), placed in
front of Nexus on a separate route (e.g. path prefix or subdomain reserved
for CLI clients, kept off the browser-facing OIDC route):

1. Read `Authorization: Basic <base64>` from the incoming request. Missing
   or malformed → `401` + `WWW-Authenticate: Basic realm="Nexus"` (this is
   what makes `docker login` / `pip`'s credential prompt work at all).
2. Exchange it against Keycloak:
   `POST {issuer}/protocol/openid-connect/token`,
   `grant_type=password&client_id=...&client_secret=...&username=...&password=...&scope=openid`.
3. `invalid_grant` / non-200 → `401`, credentials discarded, nothing
   forwarded to Nexus.
4. On success, pull the identity claim (`preferred_username` or `email`,
   operator-configurable) from the returned ID/access token, set it as the
   RutAuth header, strip the client's original `Authorization` header, and
   forward the request to Nexus.
5. Short-lived in-memory cache keyed by `sha256(username + password)` (never
   plaintext), TTL well under the access token lifetime (e.g. 60s), so a
   `docker pull` with dozens of layer requests doesn't hit Keycloak's token
   endpoint once per blob. No disk persistence, cleared on restart.

### Prerequisite Keycloak-side config

- The client used for this flow must have **Direct Access Grants Enabled**
  turned on. Confirmed this is on by default for new Keycloak clients today,
  but upstream Keycloak has open issues
  ([#37237](https://github.com/keycloak/keycloak/issues/37237),
  [#30226](https://github.com/keycloak/keycloak/issues/30226)) proposing to
  flip that default off in a future release — don't rely on the default,
  set it explicitly and check it after any Keycloak upgrade.
- Use a **dedicated confidential client** scoped to only this purpose (not
  the same client ID as the browser OIDC flow), so it can be locked down and
  rotated independently.

### The honest gap: ROPC itself is a deprecated pattern

RFC 9700 (OAuth 2.0 Security BCP) says ROPC "MUST NOT be used," and OAuth 2.1
removes it entirely. This is not a Cambium-specific weakness — it's the
tradeoff inherent to any tool (`docker`, `npm`, `pip`) that only ever learned
Basic Auth and never speaks a browser redirect. There is no clean way to give
these CLIs a real Authorization Code flow without them changing how they
authenticate (some, like newer `docker` versions with credential helpers, are
moving off Basic Auth entirely — out of scope here). Mitigations, not a fix:
TLS-only end-to-end, never log the `Authorization` header, a client scoped
to nothing beyond `openid`, short access/refresh token lifetimes on that
client, and leaning on Keycloak's own brute-force detection since this
endpoint is a credential-guessing surface by construction. Document this
plainly to whoever deploys Cambium — don't let ARCHITECTURE.md's "full
parity" framing imply this is as safe as the browser path, because it isn't.

## 4. Reference config

### 4a. Browser path — oauth2-proxy in upstream mode

```yaml
# oauth2-proxy.cfg
provider = "keycloak-oidc"
oidc_issuer_url = "https://<keycloak-host>/realms/<realm>"
client_id = "nexus-browser"
client_secret = "<from vault, browser-flow client — separate from the ROPC client>"
redirect_url = "https://nexus.example.com/oauth2/callback"

upstreams = [ "http://nexus:8081/" ]   # oauth2-proxy IS the reverse proxy — avoids the auth_request header-copy bug

email_domains = [ "*" ]
cookie_secret = "<32-byte base64, from vault>"
cookie_secure = true
cookie_samesite = "lax"

pass_user_headers = true       # emits X-Forwarded-User / -Email / -Preferred-Username upstream
set_xauthrequest = false       # not needed; nothing consumes X-Auth-Request-* here
pass_authorization_header = false
skip_provider_button = true
```

Nexus side: set the RutAuth capability's `httpHeader` field to
`X-Forwarded-User` (or `X-Forwarded-Preferred-Username`, whichever claim the
deployer wants as the Nexus principal — must match whatever Keycloak claim
populates it) — this is the one field in
`RutAuthCapabilityConfiguration`, no header-rename step needed since the
value is directly configurable.

### 4b. CLI path — dedicated ROPC shim

```yaml
# cambium-ropc-gateway config (env vars, matching Cambium's existing pattern)
KEYCLOAK_ISSUER=https://<keycloak-host>/realms/<realm>
KEYCLOAK_ROPC_CLIENT_ID=nexus-cli
KEYCLOAK_ROPC_CLIENT_SECRET=<from vault — distinct client from nexus-browser>
IDENTITY_CLAIM=preferred_username     # must match the same principal space Cambium's sync daemon uses
NEXUS_UPSTREAM=http://nexus:8081/
RUTAUTH_HEADER=X-Forwarded-User        # must match RutAuthCapabilityConfiguration.httpHeader exactly
CACHE_TTL_SECONDS=60
LISTEN_ADDR=0.0.0.0:8090
```

Routing: point `docker`/`npm`/`pip` config at a host or path that resolves to
`cambium-ropc-gateway:8090` (e.g. `nexus-cli.example.com`, or the same
ingress with a path rule for `/repository/*` reserved for CLI traffic if
subdomains aren't available), keeping it on a distinct route from the
oauth2-proxy-fronted browser UI path.

## 5. Summary

| | Browser UI | CLI (docker/npm/pip) |
|---|---|---|
| Flow | Authorization Code | ROPC (password grant) |
| Component | `oauth2-proxy` (upstream mode) | dedicated Cambium ROPC shim |
| Verified against | oauth2-proxy config docs + GitHub issue history | Keycloak Admin/token endpoint docs (RFC 6749 §4.3) |
| Gap | none — this is oauth2-proxy's core use case | ROPC is a deprecated (RFC 9700) pattern; no clean fix, only mitigations |

No single existing proxy (oauth2-proxy or Envoy's native OIDC filter) covers
both flows. Two components, cleanly split by concern, is the actual answer —
not a compromise forced by not finding the "right" one-size tool.

## 6. Alternative: Teleport Application Access

Researched because Teleport's auth model — short-lived certs, native MFA,
no raw password ever sent to the app — looked like it might sidestep the
ROPC/Basic-Auth problem in Section 3 entirely. This is desk research against
Teleport's own docs, GitHub issues/discussions, and PRs; no live cluster was
stood up, since the questions below were all answerable from public docs
with reasonable confidence. Flagged below wherever a claim is inferred
rather than doc-confirmed.

### 6a. Does Teleport rewrite a header with the authenticated identity? Yes, confirmed — with two catches.

Teleport app resources support a `rewrite.headers` field, both statically
(`teleport.yaml`) and on a dynamic `app` resource:

```yaml
- name: "nexus"
  uri: http://nexus:8081
  public_addr: nexus.example.com
  rewrite:
    headers:
    - "X-Remote-User: {{external.preferred_username}}"
```

Header values use the same templating language as Teleport role variables:
`{{internal.<trait>}}` for traits set on the local Teleport user,
`{{external.<claim>}}` for traits sourced from an SSO connector, plus
`{{internal.jwt}}` to inject a Teleport-signed JWT instead of a plain claim.
Per Teleport's SSO docs (confirmed): when Teleport's OIDC connector is used
(e.g. pointed at the same Keycloak realm Cambium already talks to), **any
claim present in the ID token is preserved as an external trait** —
`preferred_username` becomes `{{external.preferred_username}}` automatically,
no extra Login Rule needed unless the claim needs reshaping. This is
functionally the same claim→header job oauth2-proxy's
`--pass-user-headers` does, just done by Teleport's proxy instead.

Two catches, both confirmed from docs:

- **Reserved header names**: `X-Teleport-*`, `Cf-Access-Token`, and
  **`X-Forwarded-*`** are explicitly reserved and cannot be set via
  `rewrite.headers`. This matters directly for this document — Section 4's
  reference config uses `X-Forwarded-User` as the RutAuth header name. That
  name is fine for the oauth2-proxy path but **cannot be reused verbatim** if
  a deployer also wants Teleport fronting Nexus; RutAuth's `httpHeader` would
  need a non-`X-Forwarded-*` name (e.g. `X-Remote-User`, as above) on
  whichever route Teleport owns. Small thing, easy to get bitten by if
  copy-pasting between the two paths.
- **No first-class "Teleport username" variable for local (non-SSO) users**:
  a Teleport GitHub discussion
  ([#25549](https://github.com/gravitational/teleport/discussions/25549))
  has a maintainer confirming there's "no easy way" to pass the Teleport
  username itself as a header for locally-authenticated Teleport users
  (open feature request #17616). This doesn't block Cambium's use case —
  Cambium's principal comes from the Keycloak claim via the SSO-connector
  trait path above, not from a local Teleport account — but it means
  Teleport's own username is not interchangeable with "the external IdP
  claim," and a deployer reading Teleport's docs casually could conflate the
  two.

Bottom line: RutAuth's one requirement (a configurable header carrying the
principal) is satisfiable, confirmed, via SSO-connector trait mapping — not
via any dedicated "just forward the username" toggle.

### 6b. CLI tools with only Basic Auth: how they'd actually route through this

The expected model is close to right, confirmed with one important
refinement:

- `tsh app login <app>` performs full Teleport auth (password/SSO + OTP/MFA
  per cluster policy) and issues a short-lived app-scoped client cert.
- `tsh proxy app <app> --port=<port>` starts a **local TLS proxy** on
  `localhost:<port>` (Teleport docs describe this as needed specifically in
  "single-port"/TLS-routing mode) that terminates TLS locally and forwards
  over an authenticated tunnel to the real Teleport Proxy Service, which in
  turn forwards to Nexus with the rewritten header attached.
- Confirmed: the downstream CLI tool (`docker`, `npm`, `pip`/`uv`) is
  pointed at `localhost:<port>` and needs **zero Teleport awareness** — it
  just sees a plain local HTTPS (or HTTP, depending on mode) endpoint. This
  is the same "CLI stays dumb" property the ROPC shim in Section 3 has, via
  a different mechanism (client cert + tunnel instead of Basic
  Auth-to-Bearer exchange).
- Refinement worth flagging: `tsh proxy app` local proxies bind to
  `localhost`/`127.0.0.1` only (confirmed via Teleport GitHub issues, e.g.
  [#40509](https://github.com/gravitational/teleport/issues/40509) requesting
  a `--listen` override, and [#35963](https://github.com/gravitational/teleport/issues/35963)
  reporting exactly this breaking access from sibling containers). If
  `docker`/CI tooling runs in a separate container from the one running
  `tsh proxy app` (e.g. Docker-in-Docker or a sidecar pattern) rather than
  on the same host network namespace, this doesn't just work out of the box
  — needs `--net=host`-equivalent sharing or the newer `--listen` support
  once it ships.
- Day-to-day human dev experience: `tsh proxy app` is a foreground process —
  it must keep running in a terminal (or as a background job) for the
  duration of use. There's no built-in "login once, tunnel persists after
  you close the shell" for this mode; that's a genuine UX cost against the
  ROPC shim, where there's nothing for the developer to keep alive at all
  once `docker login` succeeds (credentials are cached by the client tool
  itself).

### 6c. Machine ID (`tbot`) for CI/CD: compatible, confirmed, but the two modes matter

`tbot` supports non-interactive joining via join tokens — confirmed a
`gitlab` join method exists specifically for GitLab CI
(`goteleport.com/docs/.../deployment/gitlab/`), configured with a join
token scoped by allow-rules (project path, ref, etc.) and GitLab's own
`id_tokens` OIDC trust, no human MFA involved. This is exactly the
service-account model Cambium's CI use case needs.

For Application Access specifically, `tbot` has **two distinct output
modes**, and only one of them is usable by a Basic-Auth-only client like
`docker`/`npm`/`pip`:

1. **Application-tunnel service**: runs a local proxy, same shape as `tsh
   proxy app` — attaches credentials to the connection itself, so the
   client needs no client-cert support. **`tbot` must keep running** for as
   long as the client needs the endpoint. In a CI job this is fine (start
   `tbot` as a backgrounded step at job start, `docker login
   localhost:<port>`, do the work, job ends and takes the process with it)
   — but it's a real process to manage inside the job, not "run tsh once
   and forget."
2. **Application output ("output") mode**: `tbot` writes a TLS client cert +
   key to disk (e.g. `/opt/machine-id/tlscert`, `/opt/machine-id/key`) and
   can then exit — confirmed docs example is `curl --cert ... --key
   ...`. This mode does **not** require `tbot` to keep running, which is
   the mode Teleport's own docs pitch as CI/CD-friendly — **but it only
   works for clients that can present a client certificate.** `docker
   login`, `npm login`, and `pip`/`uv`'s credential config have no client-
   cert support; they only ever speak Basic Auth over the connection. So
   for Cambium's specific CLI tools, mode 2 (the one Teleport recommends for
   CI) is not usable — CI would have to fall back to mode 1
   (application-tunnel, keep-`tbot`-running), which is exactly the "not
   actually detached" caveat above, just running unattended inside a CI job
   instead of a human's terminal.

Net: Machine ID + Application Access is real and non-interactive-capable,
confirmed, but for this specific set of CLI tools it collapses to "run a
tunnel process for the job's duration," not the fully decoupled cert-on-disk
model Teleport advertises for Machine ID generally.

### 6d. Honest tradeoffs vs. the ROPC shim

- **Infrastructure weight**: this requires standing up (or already running)
  a Teleport cluster — Auth Service, Proxy Service, an SSO connector wired
  to Keycloak, an `app` resource per protected service, and either `tsh`
  installed on every developer machine or `tbot` deployed into every CI
  pipeline. The ROPC shim in Section 3 is a single small stateless Rust
  binary with no cluster, no additional identity broker, no per-developer
  client tooling beyond what they already run. For a team not already
  running Teleport, this is a materially bigger adoption cost for solving
  one narrow problem (a header for Nexus).
- **A second identity broker, not zero**: Teleport's OIDC connector to
  Keycloak means Teleport itself becomes a second trust hop between the
  developer and Nexus (Keycloak → Teleport → Nexus), versus the direct
  Keycloak → Cambium → Nexus path elsewhere in this document. That's not
  disqualifying, but it's a real architectural addition worth naming plainly
  rather than implying Teleport is a drop-in replacement for the shim.
- **Does avoid the actual RFC 9700 problem**: unlike the ROPC shim, no raw
  password is ever sent to an HTTP endpoint for the CLI path — this is a
  genuine, confirmed security improvement over Section 3, not a marketing
  claim. `tsh`/`tbot` auth is cert/MFA-based throughout.
- **Only clean for teams already on Teleport**: this is not "better in
  general," it's "better if the deployer already runs, or is willing to
  run, Teleport for other reasons (SSH/k8s/DB access etc.) and can amortize
  the cluster cost." As a Cambium-specific answer to "how do I get a header
  into Nexus," it is strictly heavier than Section 3's shim.
- **Gaps found, stated plainly (matching how oauth2-proxy's gaps were
  flagged in Section 1-2)**: the reserved-header-name collision with
  `X-Forwarded-*` (6a), the local-proxy-only-binds-to-localhost limitation
  that bites container-based CI runners (6b), and the fact that Teleport's
  own CI-recommended Machine ID mode (cert-on-disk, no persistent process)
  is unusable for Basic-Auth-only CLI tools, forcing the heavier
  keep-a-tunnel-running mode instead (6c). None of these are fatal, but
  none of them were mentioned in Teleport's own marketing framing of
  Application Access + Machine ID as a general CI/CD answer — they only
  surface once the specific CLI tools in play (docker/npm/pip, Basic Auth
  only) are checked against the two `tbot` output modes.

### 6e. Verdict

Feasible, not a clean win. Teleport Application Access **can** satisfy
RutAuth's header requirement (confirmed, via SSO-connector trait mapping
into `rewrite.headers`) and **does** remove the raw-password-over-HTTP
problem that Section 3 accepts as an unavoidable tradeoff. But it trades
one narrow, contained gap (ROPC being deprecated per RFC 9700) for a much
larger infrastructure and operational surface (a Teleport cluster, an
additional identity hop, and CI jobs that must keep a tunnel process alive
for the job's duration since the CLI tools involved can't do client certs).
Worth offering as a documented option for deployers who already run
Teleport — not worth recommending as Cambium's default CLI-path answer over
the dedicated shim in Section 3.
