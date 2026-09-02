# Cambium — Threat Model

Reviewed at commit `ef8d82c` (v1.0.0). Scope: `src/`, `dev/`, `Dockerfile`,
`docker-compose.yml`, `.github/workflows/`, and every document in the repo.

Cambium's security rests on one deployment-level guarantee that Cambium
cannot enforce in code: **Nexus must be unreachable except through the
proxy.** If that fails, nothing else in this document matters. §1 states it
first for that reason, and §2.2 demonstrates it against a running stack rather
than asserting it.

Findings that were documentation gaps were fixed in the same pass that
produced this document; findings that require code changes are filed as
issues and deliberately left unfixed here. §6 splits them.

## 1. The trust model, and what you must guarantee

Nexus Repository 3 CE's built-in `RutAuthRealm` treats the value of one
configured HTTP header (`RutAuthCapabilityConfiguration.httpHeader`, default
`REMOTE_USER`) as an already-authenticated principal. It performs no further
verification — no signature, no shared secret, no source-address check. The
capability has exactly one configurable field, the header name
(`ARCHITECTURE.md`, verified against the vanilla `sonatype/nexus3:3.93.0`
image; `dev/nexus-init/init.sh` sets that one property and no other).

Any request that reaches Nexus's port carrying that header **is** whoever the
header says it is.

Cambium sits on both sides of that fact: `cambium ropc-proxy` is one of the
things permitted to set the header, and `cambium sync` provisions the Nexus
`User`/`Role` records that give the resulting principal its authorization.

Five guarantees are the operator's, not Cambium's:

1. **Network isolation of Nexus** (§2.1) — the load-bearing one.
2. **Reachability of the ROPC proxy** (§2.9) — it is an unauthenticated
   endpoint that can lock out realm accounts.
3. **Uniqueness and immutability of the identity claim** (§2.7).
4. **No collision between Keycloak usernames and Nexus's built-in local
   accounts** (§2.6).
5. **Keycloak group administration is Nexus administration** (§2.8) — scope
   who can edit the mapped groups accordingly.

## 2. What Cambium explicitly does NOT protect against

### 2.1 Direct network access to Nexus — the load-bearing requirement

**Cambium provides no defense whatsoever against a request that reaches
Nexus's port without passing through the proxy.** It cannot: the check lives
in Nexus, and Nexus's check is "is the header present."

Once `RutAuthCapability` is enabled, anyone with network reachability to that
Nexus instance can authenticate as any user:

```
curl -H 'X-Forwarded-User: some-nx-admin-user' \
     http://nexus:8081/service/rest/v1/security/users
```

This is not this review's inference. Sonatype's own documentation states it:

> To make the configuration secure you must restrict access to Nexus by
> subnet or IP address. Without this restriction a user could bypass the
> Apache instance and log directly into Nexus, or worse, they could craft a
> malicious request with the remote user header set and gain access to
> resource.
>
> — [How to Configure Request Header Authentication with Apache](https://support.sonatype.com/hc/en-us/articles/214942368-How-to-Configure-Request-Header-Authentication-with-Apache)

Sonatype's reference deployment additionally binds Nexus to `localhost` only,
or firewalls its port, so the reverse proxy is the sole path in
([Authentication via Remote User Token](https://help.sonatype.com/en/authentication-via-remote-user-token.html)).

It is full privilege escalation to whatever the named account can do — and
Cambium's sync daemon is what guarantees high-privilege accounts exist and are
named predictably (a Keycloak username, typically an email address).

**The requirement:**

> Nexus's HTTP port MUST be reachable only from the OIDC proxy and the ROPC
> proxy. Enforce it at the network layer — a Kubernetes `NetworkPolicy`
> restricting ingress on Nexus's port to the proxy pods' selector, a firewall
> rule, a `localhost`-only listener, or same-pod co-location. Any path that
> reaches Nexus directly — an existing internal route, a `NodePort`, a
> forgotten `kubectl port-forward`, a service mesh in permissive mode — is an
> authentication bypass for every Nexus account.

**Status: remediated in the review pass that produced this document.** At the
time of review this requirement was stated nowhere in the public repo — not in
`README.md`, not in `ARCHITECTURE.md`, not in any tracked document. The only
places it appeared were `docs/cutover-plan.md` §3 step 3 and §4 — which is
`.gitignore`d (`.gitignore:7`) and does not ship — and one aside in
`docs/metabase-target.md:129`. It is now stated in `README.md` (as a callout
beside the existing single-instance warning) and in `ARCHITECTURE.md`
("The requirement this creates").

That `metabase-target.md` aside sharpened the finding rather than softening
it.
`metabase-target.md:129` states the requirement correctly and crisply, for the
*future* Metabase target:

> **metabase-proxy must be reachable only from oauth2-proxy** (NetworkPolicy /
> same-pod localhost). Anyone who can reach it directly with a forged
> `X-Forwarded-Email` is that user. This is a deployment requirement, stated
> in the doc and in the startup log, not something the proxy can enforce
> itself.

So the correct pattern was already known and already written down — applied to
the next target and never back-ported to the one that ships today, until this
pass. Note also the promise that the requirement is echoed *in the startup
log*:
`cambium ropc-proxy`'s startup `info!` (`src/ropc.rs:600-607`) logs
`listen_addr`, `nexus_upstream`, `rutauth_header`, `identity_claim` and
`cache_ttl_seconds`, and no trust warning. Back-porting both the doc wording
and the startup-log line is a small, well-precedented fix.

### 2.2 A shipped claim that was false — verified, then corrected

**Status: verified empirically against the dev stack, and the false text was
corrected in this pass.** Recorded here in full because the claim stood in a
public repo and the verification is the evidence for §2.1.

`CONTRIBUTING.md:55-58` said, of the local dev stack:

> A request to the same URL with no credentials, or straight to
> `localhost:8081` bypassing the proxy, gets a `401` — RutAuth only trusts
> the header when a proxy that's supposed to authenticate first,
> authenticated first.

Three claims, of which the third is flatly false:

- *"no credentials → 401"* — true.
- *"straight to `:8081` → 401"* — true only because the implied request sends
  no header. As written it presents bypassing the proxy as itself sufficient
  to be rejected. Misleading.
- *"RutAuth only trusts the header when a proxy … authenticated first"* —
  **false.** `RutAuthRealm` has no channel by which it could know whether a
  proxy authenticated anything. Its only input is the header's presence.

In the shipped dev stack this is directly exploitable:
`docker-compose.yml:38` publishes Nexus's `8081` to the host,
`dev/nexus-init/init.sh` enables `rutauth` with
`httpHeader=X-Forwarded-User`, and `dev/keycloak/realm-export.json` puts
`alice` in `/nexus-admins` → realm role `nexus-admin` → `ROLE_MAP`
`nexus-admin:nx-admin`. So `curl -H 'X-Forwarded-User: alice'
http://localhost:8081/…` yields full `nx-admin`, no proxy involved. The dev
stack demonstrates the anti-pattern the documentation denies.

This was worse than a missing warning: it told a deployer the bypass was
already handled.

#### Empirical verification

No spoof test had ever been run in this project — nothing in `docs/`, `dev/`,
`CONTRIBUTING.md` or the session reports records one. This review ran it
against the repo's own `docker-compose.yml` stack. Preconditions confirmed
first: the `rutauth` capability enabled with
`{"httpHeader": "X-Forwarded-User"}`, and `alice` present in Nexus as
`{"userId":"alice","status":"active","roles":["nx-admin"]}` — created by
`cambium sync` from her Keycloak group membership, exactly as designed.

All requests below went **directly to Nexus on `:8081`**, with the ROPC proxy
running but entirely bypassed:

| Request | Result |
|---|---|
| `GET /v1/security/users`, no header | `401` |
| `-H 'X-Forwarded-User: alice'` | **`200`** — full user list (22 users) |
| `-H 'X-Forwarded-User: admin'` | **`200`** — as Nexus's built-in superuser |
| `-H 'X-Forwarded-User: nonexistent-user-xyz'` | `401` |
| `-H 'X-Remote-User: alice'` (unconfigured header name) | `401` |

The last two are the controls that make the result meaningful: the identity is
genuinely being sourced from the configured header — an unknown principal is
rejected, and a header Nexus is not configured for is ignored — rather than
the endpoint being open. The `admin` row simultaneously confirms §2.6.

Both endpoints used (`/v1/security/users`, `/v1/security/privileges`) are
admin-only, as the `401` on the unauthenticated request establishes. So the
`200`s represent genuine authorized access obtained with nothing but a header.

### 2.3 ROPC itself

`grant_type=password` is prohibited by RFC 9700 and removed in OAuth 2.1.
`docs/oidc-proxy-pairing.md` §3 is already honest about this, so this review
only records it: the proxy is a credential-guessing surface by construction,
users' real passwords transit an HTTP endpoint, and MFA is impossible on this
path. Cambium mitigates; it does not fix. §6 of that document covers Teleport
as the architecture that removes the problem, at materially higher cost.

### 2.4 Plaintext transport is permitted, and the docs contradict themselves

**Status: fixed.** At the time of review, `docs/oidc-proxy-pairing.md:146`
listed **"TLS-only end-to-end"** as a required mitigation while the same
document's own production reference configs used plaintext — line 165
(`upstreams = [ "http://nexus:8081/" ]`) and line 199
(`NEXUS_UPSTREAM=http://nexus:8081/`). A deployer copy-pasting §4b got a
plaintext proxy→Nexus hop carrying the RutAuth identity header, the
credential-equivalent of the entire architecture.

All four URLs are now validated at startup (`validate_upstream_url` in
`src/config.rs`): a malformed URL, a non-HTTP scheme, or a missing host is a
startup failure, and **plaintext `http://` is refused unless
`ALLOW_INSECURE_HTTP=1`** is set deliberately. The reference configs now use
`https://`, and the dev stack sets the opt-in explicitly. The mitigation is
enforced rather than advisory.

The hops this protects, all of which were free-form `String`s with no
validation:

| Hop | What crosses it | Enforced? |
|---|---|---|
| client → ropc-proxy | the user's real password (Basic Auth) | no — TLS is the ingress's job |
| ropc-proxy → Keycloak | password in a POST form body | no |
| ropc-proxy → Nexus | the RutAuth header (identity, bearer-equivalent) | no |
| sync → Keycloak Admin API | client-credentials secret, admin bearer token | no |
| sync → Nexus REST API | Nexus admin Basic Auth credentials | no |

There is a validation asymmetry worth naming: `RUTAUTH_HEADER` *is* validated
at startup and fails fast (`src/ropc.rs`, `run()`), while the two URLs that
carry credentials get no validation at all. Parsing both as a `Url` at startup
and requiring `https` absent an explicit opt-in would follow a precedent
already present in the same function.

**On the unverified JWT.** `decode_jwt_claims` does not verify the token
signature, justified in comment by the token having arrived over the proxy's
own connection to Keycloak. That reasoning is sound *if* the connection is
authenticated TLS. With `KEYCLOAK_ISSUER=http://…`, an on-path attacker could
return a token whose `preferred_username` is any user they like, and the proxy
would inject it as a trusted identity. It was never a bug — it was a correct
decision resting on a premise the code did not check. The startup validation
above now checks it, so the premise is a guarantee rather than an assumption,
except where an operator sets `ALLOW_INSECURE_HTTP=1` and thereby takes it
back on purpose.

### 2.5 Availability of the ROPC path

- **No HTTP timeouts.** Every `reqwest::Client` is `Client::new()`
  (`src/ropc.rs:175`, `:625`; `src/nexus.rs:68`; `src/keycloak.rs:83`) with no
  `.timeout()` or `.connect_timeout()`, and reqwest has no default request
  timeout. On the proxy path a Keycloak that accepts connections and never
  answers parks requests indefinitely — each holding a connection and a
  coalescing `OnceCell`, so every concurrent waiter on that credential blocks
  with it. `docs/operations.md:233` acknowledges the symptom ("a wedged pod…
  stuck on a hung upstream Keycloak/Nexus connection") but prescribes only a
  liveness probe: mitigation at the orchestrator, not a fix in the client.
- **Unbounded cache.** `TokenCache::entries` is never reaped; expired entries
  are ignored on read but never removed (`src/ropc.rs:317`). Only *successful*
  exchanges are cached, so growth requires valid credentials — a slow leak,
  not an attacker-driven one.
- **No request-body limits.** Bodies stream through unbuffered — correct, for
  multi-GB `docker push` layers — so limits are Nexus's, not the proxy's.

### 2.6 Reserved Nexus usernames are not protected

RutAuth maps the header value straight onto a Nexus `userId`, and Nexus ships
built-in local accounts (`admin`, `anonymous`). **A Keycloak user named
`admin` authenticates, via RutAuth, as Nexus's built-in superuser** —
independent of `ROLE_MAP`, and independent of anything Cambium does. No
reserved-name guard exists anywhere in `src/` or in `docs/sync-semantics.md`.

**Verified**: against the dev stack,
`curl -H 'X-Forwarded-User: admin' http://localhost:8081/service/rest/v1/security/users`
returns `200` as the built-in `admin` account — see §2.2's table. Keycloak
never issued anything; the name alone was sufficient.

This is sharpest at cutover, where a production Nexus already has local
accounts and any colliding Keycloak username silently inherits one. The dev
stack itself co-locates a Nexus `admin` (password `admin123`) with the
Keycloak realm.

**Partially mitigated in code.** `cambium sync` now refuses to provision or
re-role a reserved account: `is_reserved_username` (`src/sync.rs`) skips it
with a `warn!` rather than syncing it. The list is `RESERVED_USERNAMES`,
default `admin,anonymous`, comma-separated and matched case-insensitively
(Nexus resolves `userId` case-insensitively, so `Admin` reaches the same
account). Setting it empty disables the guard.

That stops Cambium *making the collision worse* — it will no longer attach
`ROLE_MAP` roles to a built-in account. **It does not close the underlying
hole**, and cannot: RutAuth trusts the header regardless of what Cambium
does, so a Keycloak user named `admin` still authenticates as Nexus's
built-in superuser with whatever privileges that account already has.
Guaranteeing no collision exists in the first place remains the operator's,
per §1.

### 2.7 The identity claim has no uniqueness or immutability requirement

`IDENTITY_CLAIM` is documented as operator-configurable, "e.g. `email`"
(`src/config.rs`, and `docs/oidc-proxy-pairing.md` §4b), with no warning that
this choice makes the system's entire identity integrity depend on Keycloak
enforcing that claim unique, immutable, and admin-controlled.

With `IDENTITY_CLAIM=email` on a realm running `duplicateEmailsAllowed: true`,
a user can set their email to a colleague's and authenticate as them. The dev
realm sets `registrationAllowed: false` (good) and leaves
`duplicateEmailsAllowed` and `verifyEmail` at Keycloak's defaults (both
`false`), so uniqueness holds by default — this requires a non-default realm
setting to become exploitable. Severity is configuration-dependent, and stated
here at that level.

The general form is the point: any custom-mapper claim carries *no* uniqueness
guarantee, and the code validates nothing about the value it forwards beyond
header-safety.

### 2.8 Keycloak group administration is Nexus administration

Anyone able to add a member to a mapped Keycloak group can grant themselves
any Nexus role in `ROLE_MAP`. The dev stack's map contains
`nexus-admin:nx-admin`, so Keycloak group-admin ⇒ Nexus superuser.

This is inherent to the design and correct — it is the whole point of the
tool — but it is a privilege-coupling that a threat model must state rather
than leave implied. Scope Keycloak group-management rights as you would scope
Nexus admin.

### 2.9 The ROPC endpoint is an account-lockout vector

`docs/operations.md:166` already documents, accurately, that **no rate
limiting exists in this code at all**, with rationale for why a per-replica
limiter would fragment. So the absence is an accepted risk, not an oversight,
and this review does not re-file it as a gap.

What is under-described is the consequence. The documented mitigation is
"lean on Keycloak's own brute-force detection" — but Keycloak's brute-force
detection locks the *targeted account*. An unauthenticated attacker who can
reach `LISTEN_ADDR` (default `0.0.0.0:8090`) can spray bad passwords and
**lock out every named user in the realm**, turning the only stated mitigation
into the attack.

Failure results are deliberately not cached, so every wrong guess reaches
Keycloak — correct, in that it prevents bypassing Keycloak's detection, but it
also means the proxy is a clean amplifier. Reachability of the ROPC listener
is therefore a deployment decision that needs stating alongside §2.1.

### 2.10 Revocation lag

Two windows where access outlives the decision to remove it:

- The ROPC cache holds a credential→identity mapping for
  `CACHE_TTL_SECONDS` (default 60), fixed at config time and decoupled from
  the token's own `exp`. Because the cache key includes the password, a
  **rotated password's old value keeps working** for up to that long, and a
  disable or revoke lags by the same window.
- `cambium sync` revokes only on a pass, so a Keycloak group removal takes up
  to `POLL_INTERVAL_SECONDS` (default 60) to reach Nexus — plus the full
  duration of any sync outage. `docs/operations.md` §1 already names this
  correctly as a stale-access window.

### 2.11 Client-controlled `X-Forwarded-For` is passed through

`is_forwardable_request_header` (`src/ropc.rs:428`) strips only
`authorization`, `host`, and the hop-by-hop set. `X-Forwarded-For`,
`-Proto` and `-Host` are forwarded verbatim, and the proxy never appends the
real peer address. Two consequences:

- Nexus can never see the true client IP, so audit and forensics on the CLI
  path are unreliable — directly relevant given `docs/cutover-plan.md` treats
  Nexus auth-rate-limiter block rates as a monitored cutover signal.
- If Nexus keys anything on `X-Forwarded-For`, a client can poison or evade it
  by rotating a forged value.

One-line fix: overwrite (or append the peer address to) the inbound header
rather than trusting it.

### 2.12 Internal state in logs

`CambiumError::KeycloakUnexpected` and `NexusUnexpected` (`src/error.rs:9`,
`:12`) carry the upstream response body verbatim and are logged at
`warn!`/`error!` via `error = %e` (`src/sync.rs:201`, `:224`, `:243`;
`src/main.rs:128`). Nexus 5xx bodies are raw Java exception text; Keycloak
error bodies can carry realm and client identifiers.

The reassuring half, verified: Keycloak's token endpoint returns
`{"error":"unauthorized_client","error_description":"Invalid client or Invalid
client credentials"}` on a bad secret — **it does not echo the secret**. So
this is internal-detail verbosity in logs, not a secret leak. Nothing is
client-facing: proxy clients always receive a flat `401`/`500`/`502` with a
fixed string.

### 2.13 Container and CI hardening

- **Runs as root.** The `Dockerfile` has no `USER` directive (`grep -c
  '^USER'` → 0), so both subcommands run as uid 0 in the final
  `debian:bookworm-slim` stage. Neither needs it; the only writes are
  `state_file` and `lock_file`.
- **Floating base images.** `rust:1-slim-bookworm` and `debian:bookworm-slim`
  are unpinned tags with no digest, and `docker-compose.yml` uses
  `sonatype/nexus3:latest`. The Rust crate graph *is* reproducible
  (`Cargo.lock` + `--locked` in both CI and the Dockerfile); the base images
  are not. CI actions are pinned by tag rather than commit SHA.
- **No `permissions:` block in CI.** `.github/workflows/ci.yml` declares none,
  so the workflow takes the repo/org default `GITHUB_TOKEN` scope. Add
  `permissions: contents: read` — one line, standard for a public repo.
- **No dependency-audit gate.** See §4.

### 2.14 Secrets are env-var-only

`KEYCLOAK_CLIENT_SECRET`, `NEXUS_PASSWORD` and `KEYCLOAK_ROPC_CLIENT_SECRET`
come from `env_require` with no `*_FILE` indirection convention. Environment
variables are readable via `/proc/<pid>/environ` and appear in
`kubectl describe pod` when set inline rather than via `secretKeyRef`.
Low-to-medium, cheap to fix, and conventional for a tool that expects to run
in Kubernetes.

## 3. What Cambium does protect against

**Credential exposure on the ROPC path.** Credentials are never logged: all
20 log call sites across `src/` were enumerated for this review, and none
takes credential material. `KeycloakTokenExchanger::exchange` logs nothing at
all. `proxy_handler`'s two `warn!` sites (`src/ropc.rs:470`, `:477`) emit only
the error variant and, for `IdentityNotHeaderSafe`, the offending claim via
`{:?}` — Debug-escaped, so a claim carrying a newline cannot forge a log line.
Startup logs config but not `keycloak_ropc_client_secret`.

The one non-obvious path was checked rather than assumed: `RopcError::
KeycloakUpstream(e.to_string())` wraps a `reqwest::Error`, whose `Display`
renders the error kind and optionally the URL — **never the request body**.
The token URL carries no userinfo, and the credentials live in the form body,
so no credential can reach a log through that variant.

**Credentials are never persisted, and never keyed in plaintext.** The cache
is memory-only and cleared on restart. `cache_key` (`src/ropc.rs:278`) is
`hex(sha256(username || 0x00 || password))`; the `0x00` separator prevents
`("ab","c")` colliding with `("a","bc")`. Both properties are
regression-tested — `cache_key_never_contains_plaintext_credentials`
(`src/ropc.rs:1040`) and
`cache_key_differs_for_different_username_password_boundary_split` (`:1030`).

**Header spoofing at the proxy.** `forward_to_nexus` (`src/ropc.rs:495`) drops
`Authorization`, `Host` and the RFC 7230 §6.1 hop-by-hop set, then sets the
RutAuth header with `HeaderMap::insert`, which replaces the key's value and
removes all previous values — clearing anything the `append` loop copied in.
A client sending its own `X-Forwarded-User` has it discarded. Case variants
cannot survive: `HeaderName` normalizes to lowercase at parse, and a
trailing-space header name is not a valid HTTP token and is rejected by hyper
before reaching this code. (The `.unwrap()` at `src/ropc.rs:521` looks
alarming but is safe — it re-parses an already-validated, already-normalized
name.)

**Fail-closed on an unforwardable identity.** If the identity claim is not a
valid HTTP header value, the request is rejected with a `500` rather than
forwarded with an empty RutAuth header (`src/ropc.rs:518`). Forwarding an
empty principal to a header-trusting realm would be a fail-open authentication
hole; the code says so in comment and does the right thing.

**Uniform rejection.** Wrong password, Keycloak unreachable, missing claim,
malformed Basic Auth and non-UTF-8 `Authorization` all produce the same `401`
+ `WWW-Authenticate: Basic realm="Nexus"`. The variant distinction exists only
for logs.

**Clobber-safe authorization writes.** Nexus exposes only a whole-array
replace for a user's roles. `reconcile_roles` (`src/sync.rs:45`) preserves
`current_nexus_roles - last_synced_roles` — anything Cambium did not itself
grant last pass — before unioning in what Keycloak justifies now, so a
manually-assigned `nx-admin` survives a sync pass. Roles with no `ROLE_MAP`
entry are ignored, never invented. `set_user_roles` also preserves
`current.status`, so a manually-disabled Nexus user is never silently
re-enabled.

**Unguessable placeholder passwords.** Nexus requires a password at user
creation even though RutAuth is the real authentication path.
`random_placeholder_password` (`src/sync.rs:349`) draws 32 bytes from
`rand::thread_rng()` — ChaCha12, seeded and reseeded from OS entropy, a real
CSPRNG — and hex-encodes them. 256 bits, never logged, never written anywhere
but Nexus's own credential store. (Its doc comment says "`rand::rngs::OsRng`
via `rand::thread_rng()`", which is imprecise — `thread_rng` is seeded *from*
`OsRng`, it is not `OsRng`. Comment wording only; the security claim holds.)

**Manifest corruption from concurrent instances.** `src/lock.rs` takes an
exclusive `flock` at startup and holds it for process lifetime, so a second
replica exits rather than racing (`src/main.rs:80`). Not a confidentiality
control, but a lost manifest update is what makes a stale grant permanently
unrevocable — a security problem, per `docs/sync-semantics.md`.

**No dependency-confusion exposure.** 199 of 200 `Cargo.lock` entries resolve
to `registry+https://github.com/rust-lang/crates.io-index` with checksums (the
200th is the root package). No `git` dependencies, no `path` dependencies, no
alternate or private registry, no `[patch]` section, and `--locked` is used in
both CI and the Dockerfile. There is no private-name-shadowing surface here.

**No secrets in the repo or its history.** All secrets arrive as environment
variables, are read once into `Config`/`RopcConfig`, and are never written to
disk or logged. (Both structs `#[derive(Debug)]` and would print secrets if
ever formatted with `{:?}`; nothing does today.) Every credential committed to
`docker-compose.yml`, `dev/keycloak/realm-export.json` and
`dev/nexus-init/init.sh` is a fixed throwaway dev value, labelled as such in
three places. A scan across every commit reachable from all refs — including
the pre-`filter-branch` history still retained locally at
`refs/original/refs/heads/main`, whose tree and author identity are identical
to the rewritten history — found nothing. The internal deployment docs that
*do* name real Smartech hostnames (`docs/cutover-plan.md`,
`docs/load-test-results.md`) were never committed; they exist only in the
working tree and are `.gitignore`d. That is the correct handling.
Housekeeping only: `refs/original` can be pruned.

## 4. Dependency advisories

`cargo audit` v0.22.2 against `Cargo.lock`; advisory DB of 1239 advisories;
200 crate dependencies scanned.

**Vulnerabilities: 0.** No RUSTSEC advisory matches any crate in the graph,
direct or transitive.

| Advisory | Crate | Reachable? | Status |
|---|---|---|---|
| Yanked release (no RUSTSEC ID) | `chacha20 0.10.1` | **No** | **Accepted — not in the build graph.** |

`chacha20 0.10.1` (`Cargo.lock:221`) is reachable only from `rand 0.10.2`
(`:949`), whose only depender is `quinn-proto` — `reqwest`'s optional HTTP/3
support, which nothing in `Cargo.toml` enables.
`cargo tree --target all -e normal` yields only `rand v0.8.7` and
`rand_chacha v0.3.1` (which uses `ppv-lite86`, not the `chacha20` crate); no
`quinn`, no `chacha20`. `Cargo.lock` deliberately records the maximal
resolution including unenabled optional dependencies, which is exactly why
`cargo audit` flags it. No code from this crate is compiled or linked. No
version bump needed; the entry will clear on its own the next time `reqwest`'s
lock resolution moves.

Notably clean: `reqwest` is built `rustls-tls` with `default-features =
false`, so there is no `openssl`/`native-tls` anywhere in the graph — the
single largest historical source of advisories in Rust HTTP clients is simply
absent. `gzip`/`brotli`/`deflate` are likewise off.

**Recommendation:** add `cargo audit` to `.github/workflows/ci.yml` — but note
that a bare `cargo audit --deny warnings` **exits 1 today** on the yanked
`chacha20`. Add it either without `--deny warnings`, or with an explicit
`--ignore` for that advisory plus a comment pointing at this section.
Prescribing it unqualified would prescribe a red CI.

## 5. Considered and ruled out

Recorded because each is a reasonable thing to suspect in a streaming reverse
proxy, and each was checked rather than assumed.

- **Request smuggling (CL/TE desync).** `HOP_BY_HOP` (`src/ropc.rs:417`)
  strips `transfer-encoding` but not `content-length`, while the body is
  re-streamed as unknown-length via `Body::wrap_stream` — the textbook setup.
  It does not desync: hyper's client `set_length` takes `Encoder::length(len)`
  when `Transfer-Encoding` is vacant and a `Content-Length` is present, and
  does not additionally emit chunked; hyper's server role already removes
  `Content-Length` from any inbound chunked request. Both halves stay
  consistently framed. **No smuggling.**
- **SSRF via the upstream URL.** `build_upstream_url` (`src/ropc.rs:564`)
  concatenates the configured base with a client-controlled
  `path_and_query`. An absolute-form request URI (`GET http://evil.com/x`)
  reduces to just the path via `uri.path_and_query()`, and a `//evil.com/x`
  path stays a path because the base already carries scheme and authority.
  **No host override.** (A schemeless `NEXUS_UPSTREAM` fails closed as a
  `502` — though it should be a startup error; see §2.4.)
- **Response `Content-Length` mismatch.** reqwest's decompression features are
  not enabled, so `bytes_stream()` is the undecoded body and the forwarded
  `Content-Length` stays accurate.
- **`parse_basic_auth` requires exactly `"Basic "`, case-sensitively**
  (`src/ropc.rs`). An interop nit against RFC 7235's case-insensitive scheme
  token, not a security issue — the failure mode is a `401`.
- **`forward_to_nexus` falls back to `Method::GET`** on an unparseable
  method. `reqwest::Method::from_bytes` accepts any valid HTTP token and hyper
  rejects malformed methods upstream of this code, so the fallback is
  effectively unreachable.

## 6. Summary, split by what it takes to fix

### Documentation and deployment guidance — fixable in this pass

| § | Finding | Severity | Status |
|---|---|---|---|
| 2.1 | Network isolation of Nexus is a hard requirement, stated nowhere in the public repo | **high** | **fixed** — `README.md`, `ARCHITECTURE.md` |
| 2.2 | `CONTRIBUTING.md:55-58` claimed direct-to-Nexus access is already rejected — false | **high** | **fixed** — verified, then corrected |
| 2.6 | Reserved Nexus usernames (`admin`, `anonymous`) — collision guarantee is the operator's | medium | documented; Cambium-side guard added ([#5](https://github.com/Rhizomo/cambium/issues/5)) |
| 2.7 | `IDENTITY_CLAIM` uniqueness/immutability requirement unstated | medium (config-dependent) | documented here |
| 2.8 | Keycloak group-admin ⇒ Nexus admin — privilege coupling unstated | medium | documented here |
| 2.9 | ROPC listener reachability is a lockout-DoS decision, not just a guessing surface | medium | documented here |
| 2.4 | `oidc-proxy-pairing.md` mandated TLS-only (:146) and then shipped plaintext reference configs (:165, :199) | medium | **fixed** — configs corrected; startup validation added ([#4](https://github.com/Rhizomo/cambium/issues/4)) |
| 2.12 | Upstream error bodies logged verbatim | low | open |
| 2.13 | Base images unpinned; no CI `permissions:`; no audit gate | low | open |

### Code — needs a separate fix pass, deliberately not bundled here

| § | Finding | Severity | Issue |
|---|---|---|---|
| — | **Keycloak `enabled: false` is never honored** — see below | **medium-high** | [#1](https://github.com/Rhizomo/cambium/issues/1) |
| 2.5 | No HTTP timeouts on any `reqwest::Client` | medium | [#2](https://github.com/Rhizomo/cambium/issues/2) |
| 2.11 | `X-Forwarded-For` forwarded verbatim; real peer address never recorded | medium | [#3](https://github.com/Rhizomo/cambium/issues/3) |
| 2.4 | No startup validation of `NEXUS_UPSTREAM` / `KEYCLOAK_ISSUER` scheme | medium | **fixed** in [#4](https://github.com/Rhizomo/cambium/issues/4) |
| 2.6 | No reserved-username refusal in `sync` | medium | [#5](https://github.com/Rhizomo/cambium/issues/5) |
| 2.13 | No `USER` directive — containers run as root; base images unpinned | low | [#6](https://github.com/Rhizomo/cambium/issues/6) |
| 4 | No `cargo audit` gate in CI | low | [#7](https://github.com/Rhizomo/cambium/issues/7) |
| 2.14 | No `*_FILE` secret indirection | low | not filed |
| 2.5 | Cache entries never reaped | low | not filed |

### The one real behavioral bug

**A user disabled in Keycloak keeps their Nexus roles indefinitely, and is
created `active` if they don't yet exist.**

`KcUser.enabled` is deserialized (`src/keycloak.rs:50`) behind
`#[allow(dead_code)]`, and `merge_users` (`src/sync.rs:79`) discards it — only
`(id, username)` survives into the sync decision. No code path reads it.
`sync_one_user` then creates missing users with `status: "active"`
(`src/nexus.rs:116`).

Why this is not moot despite RutAuth being the only auth path:

- Cambium *does* revoke on group removal, and `docs/sync-semantics.md` treats
  stale grants as a security problem — but **disabling, the single most common
  offboarding action, produces zero revocation.** That is an expectation
  mismatch an operator will get wrong.
- The resulting Nexus account is `active` and role-bearing, so the standing
  authorization outlives the Keycloak deactivation and is directly exploitable
  the moment §2.1 or §2.2 bites.
- Defense-in-depth is gone: the only remaining control is Keycloak refusing to
  mint a token.

The dev realm contains no `enabled: false` user, so this path has never been
exercised. Fix: carry `enabled` through `merge_users` and treat `false` as
desired-roles-∅, and/or set Nexus `status: "disabled"`.
