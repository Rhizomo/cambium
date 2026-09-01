# Metabase as a second Cambium target — design note

Decided 2026-08-25: Cambium's identity shifts from "OIDC/Keycloak translator for Nexus 3 CE" to **"Keycloak translator for apps without OIDC."** Metabase OSS is the second target. Nothing in this note is implemented yet; it is the annotatable plan — mark up under each action line, and code follows the marked-up version.

Why Metabase needs this at all: Metabase OSS ships only Google Sign-In and LDAP; OIDC/SAML/JWT are Pro/Enterprise features. Unlike Nexus, Metabase has **no header-trust login** (no RutAuth equivalent), so the Nexus pattern (OIDC proxy injects header, app trusts it) does not transfer directly. What Metabase does have is a plain session API (`POST /api/session` with email + password → session cookie) and a full admin API for users and group memberships. Cambium can therefore own each user's Metabase password and mint sessions on their behalf after oauth2-proxy has already authenticated them against Keycloak. Metabase keeps believing in passwords; nobody ever types one.

Every Metabase API fact below was read from `metabase/metabase` `master` on 2026-08-25 (`src/metabase/session/api.clj`, `src/metabase/users_rest/api.clj`, `src/metabase/permissions_rest/api.clj`, `src/metabase/request/cookies.clj`, `docs/configuring-metabase/environment-variables.md`). `master` includes the unreleased `AuthIdentity` password refactor. **Pin the Metabase version this will run against and re-verify every endpoint shape against that version's `/api/docs` before writing code.** Section 8 lists exactly what is unverified.

---

## 0. Open decisions (mark up first — everything below assumes the recommended answer)

**D1 — who creates Metabase users, and do they get an invite email?**
`POST /api/user` goes through `invite-user!` → `create-and-invite-user!`. If Metabase has SMTP configured (likely for a BI tool with alerts), a first `cambium sync` pass against Metabase may email every synced Keycloak user a "you've been invited" link. Verify on the dev stack whether supplying `password` (and/or `source`, `invite_target`) suppresses the email. Two candidate resolutions:
- (a) **`sync` creates users with the derived password** (see 3.4). Full Nexus parity: users exist before first login, group membership is correct from minute one. Cost: `METABASE_PASSWORD_SEED` must be shared between the `sync` and `metabase-proxy` deployments.
- (b) **`metabase-proxy` provisions lazily on first login; `sync` only reconciles memberships of users that already exist.** No invite emails regardless of SMTP, no shared seed. Cost: `create_user` becomes a no-op for the Metabase target and never-logged-in users don't appear in Metabase — a semantic divergence from Nexus that must be documented.
- **Decided 2026-08-25 (FJK): (a).** Keycloak is the source of truth for who exists, so Cambium creates the users. The invite-email check in §8 still gates implementation — if it can't be suppressed via `password`/`source`, find a suppression mechanism rather than falling back to (b).

**D2 — auto-reactivate deactivated users?**
A Metabase admin deactivating someone (`DELETE /api/user/:id`) is an explicit human decision. Recommended: Cambium never reactivates; a deactivated user with Keycloak roles gets a 403 page from the proxy and a `warn` log line from `sync`. Reactivation stays manual (`PUT /api/user/:id/reactivate`). **Decided 2026-08-25 (FJK): yes.**

**D3 — may `ROLE_MAP` target the `Administrators` group?**
Mapping a Keycloak role onto Metabase `Administrators` toggles `is_superuser`. Recommended: allowed, but refused at startup unless `ALLOW_ADMIN_GROUP_MAPPING=true`, mirroring how dangerous the equivalent `nx-admin` mapping already is on Nexus. **Decided 2026-08-25 (FJK): yes.**

**D4 — logout semantics.**
Metabase's logout (`DELETE /api/session`) clears the Metabase cookie; the next request through the proxy silently mints a new session because oauth2-proxy still vouches for the user. Recommended: the proxy intercepts `DELETE /api/session`, forwards it upstream, then redirects to oauth2-proxy's `/oauth2/sign_out` so "log out" means what users expect. **Decided 2026-08-25 (FJK): yes** — mechanics per the §8 XHR check.

---

## 1. `RoleTarget` trait

### 1.1 The key fact that makes this cheap
Both targets expose a user's role set as a **whole-array replace**, not per-role assign/revoke:
- Nexus: `PUT /service/rest/v1/security/users/{userId}` with full `ApiUser`, `roles` replaced (already documented in `src/nexus.rs`).
- Metabase: `PUT /api/user/:id` with `user_group_memberships: [{id: <group_id>}, ...]` → `maybe-set-user-group-memberships!` replaces the set.

So `reconcile_roles`, `ReconcileInput`, `ReconcileOutcome`, and the manifest's "remember what we granted" mechanism (`docs/sync-semantics.md` §3) carry over **unchanged**. Only the client behind them becomes pluggable.

### 1.2 Trait shape (`src/target.rs`, new)
```rust
#[async_trait]
pub trait RoleTarget: Send + Sync {
    fn kind(&self) -> &'static str;
    async fn begin_pass(&self) -> CambiumResult<()>;
    fn resolve_role(&self, role_map_value: &str) -> CambiumResult<String>;
    fn identity_for(&self, kc_username: &str, fallback_email_domain: &str) -> String;
    async fn get_user(&self, identity: &str) -> CambiumResult<Option<TargetUser>>;
    async fn create_user(&self, user: NewTargetUser) -> CambiumResult<()>;
    async fn set_user_roles(&self, current: &TargetUser, desired: Vec<String>) -> CambiumResult<()>;
}

pub struct TargetUser {
    pub identity: String,
    pub roles: HashSet<String>,
    pub active: bool,
    pub handle: TargetHandle,
}

pub struct NewTargetUser {
    pub identity: String,
    pub display_name: (String, String),
    pub email: String,
    pub password: Option<String>,
    pub roles: Vec<String>,
}
```
- `begin_pass` runs once per reconciliation pass. Nexus: no-op. Metabase: `GET /api/permissions/group` (names → ids) and `GET /api/permissions/membership` (one call returns every user's memberships as `{user_id: [{membership_id, group_id, is_group_manager}]}`), cached for the pass. Without this the Metabase target would be N+1 on every user.
- `resolve_role` translates a `ROLE_MAP` value into the identifier the target reconciles in. Nexus: identity function (role IDs are already the stable key). Metabase: group **name** in `ROLE_MAP` (human-stable, matches how Nexus `ROLE_MAP` reads) → group **id** from the `begin_pass` cache; unknown name is a startup/pass error, not a silent skip. **Reconciliation and the manifest operate in group-id space** so a group rename mid-pass can't desync them.
- `identity_for` is what the target keys users by. Nexus: Keycloak `preferred_username` (today's behaviour). Metabase: **email**, lower-cased — Metabase has no username concept; `resolve_email_address` from `sync.rs` is reused, so a Keycloak username that is already an email passes through and anything else gets `FALLBACK_EMAIL_DOMAIN`.
- `get_user`: Nexus `GET /users?userId=` (fuzzy, filtered exact — existing). Metabase `GET /api/user?query=<email>&status=all` (also fuzzy on name/email → filter exact, case-insensitive), then `GET /api/user/:id` for hydrated `user_group_memberships`. `active` comes from `is_active`; D2 decides what to do with `false`.
- `set_user_roles` — Nexus: existing `PUT` with full body. Metabase: `PUT /api/user/:id {user_group_memberships: [...]}`. `All Users` (magic group, every user is a member, cannot be removed) is excluded from both `current` and `desired` before reconciling so it never counts as foreign or managed.
- `TargetHandle` is an opaque per-target enum (`Nexus(NexusUser)` / `Metabase { id: i64, .. }`) so `set_user_roles` has what it needs for the `PUT` body without leaking either API's shape into `sync.rs`.

### 1.3 What moves where
- `src/nexus.rs` → keeps its client; gains `impl RoleTarget for NexusClient` (thin — mostly delegation).
- `src/metabase.rs` (new) → `MetabaseClient` authenticated with `X-API-Key`, plus `impl RoleTarget`.
- `src/sync.rs` → `run_pass`/`sync_one_user` take `&dyn RoleTarget` instead of `&NexusClient`; `resolve_email_address` / `random_placeholder_password` move into the Nexus impl (Nexus needs a placeholder password on create; Metabase's is decided by D1).
- `src/manifest.rs` → unchanged. Manifest key stays `{realm}/{username}` (Keycloak-side identity, not target identity), which is why one manifest per target is required (section 4).

---

## 2. Config namespace rework — zero-change compatibility invariant

**Invariant: an existing Nexus deployment with no env changes behaves byte-identically** — same subcommands, same defaults, same log fields. Every new variable has a default that selects today's behaviour.

### 2.1 `cambium sync`
- New: `TARGET_KIND` ∈ {`nexus`, `metabase`}, **default `nexus`**.
- `TARGET_KIND=nexus` reads exactly today's vars: `NEXUS_URL`, `NEXUS_USERNAME`, `NEXUS_PASSWORD`. Unchanged names, unchanged required-ness.
- `TARGET_KIND=metabase` reads: `METABASE_URL`, `METABASE_API_KEY` (an API key created in Metabase admin and assigned to the `Administrators` group — user/password/membership writes all require superuser). Never a personal admin's session. Plus `METABASE_PASSWORD_SEED`, required iff D1(a) (sync creates users with the derived password), absent otherwise.
- `ROLE_MAP` keeps its `kc-role:target-role` syntax; the value's meaning is per target (Nexus role ID / Metabase group name). Documented in the var's own description, not a new var.
- `KEYCLOAK_*`, `POLL_INTERVAL_SECONDS`, `FALLBACK_EMAIL_DOMAIN`: shared, unchanged.
- `STATE_FILE`, `LOCK_FILE`: see section 4 for defaults.
- Code shape: `Config { keycloak: KeycloakConfig, target: TargetConfig, sync: SyncConfig }` with `enum TargetConfig { Nexus { url, username, password }, Metabase { url, api_key } }`. `from_env()` branches once on `TARGET_KIND`; a var belonging to the *other* target being set is a startup `warn`, not an error.

### 2.2 `cambium ropc-proxy`
- Nexus-only by nature (RutAuth header injection). No `TARGET_KIND`.
- `NEXUS_UPSTREAM` stays accepted. New canonical name `UPSTREAM_URL`; if only `NEXUS_UPSTREAM` is set it is used with a one-line `warn` at startup ("deprecated alias, still supported"). If both are set and differ: startup error. Not removed in this change.
- `RUTAUTH_HEADER`, `IDENTITY_CLAIM`, `CACHE_TTL_SECONDS`, `LISTEN_ADDR`, `KEYCLOAK_ISSUER`, `KEYCLOAK_ROPC_CLIENT_*`: unchanged.

### 2.3 `cambium metabase-proxy` (new subcommand, own `MetabaseProxyConfig`, same "separate struct per subcommand" rule as today)
| var | default | notes |
|---|---|---|
| `LISTEN_ADDR` | `0.0.0.0:8091` | 8090 stays the ropc-proxy default so both can run in one pod |
| `UPSTREAM_URL` | required | Metabase base URL |
| `METABASE_API_KEY` | required | Administrators-group API key (provisioning + password self-heal) |
| `METABASE_PASSWORD_SEED` | required | HMAC key for derived passwords, ≥32 bytes, see 3.4 |
| `IDENTITY_HEADER` | `X-Forwarded-Email` | **not** `X-Forwarded-User` — that carries the OIDC `sub` (see `[[oauth2-proxy-x-forwarded-user-is-sub-not-username]]`); Metabase keys by email so `X-Forwarded-Email` is the natural choice |
| `NAME_HEADER` | `X-Forwarded-Preferred-Username` | display name source at provisioning |
| `DEFAULT_GROUPS` | empty | Metabase group names a freshly provisioned user joins immediately, before `sync`'s next pass (only relevant under D1(b)) |
| `SESSION_CACHE_TTL_SECONDS` | `3600` | must stay well below Metabase `MAX_SESSION_AGE` (minutes, default 20160 = 14 d) |
| `SELF_HEAL_COOLDOWN_SECONDS` | `300` | at most one admin password reset per identity per window (3.5) |
| `SIGN_OUT_REDIRECT` | `/oauth2/sign_out` | D4 |

### 2.4 Default subcommand
`cambium` with no subcommand keeps meaning `sync` (existing deployments invoke it bare).

---

## 3. `cambium metabase-proxy` design

Mirrors `src/ropc.rs`: axum router, `Arc<State>`, `TokenExchanger`-style trait around the upstream login so tests never hit a live Metabase, `Clock` trait for cache TTL, allow-listed header forwarding, graceful shutdown. Differences from ropc-proxy are the interesting part.

### 3.1 Position in the request path
```
browser ──► oauth2-proxy (Keycloak auth-code flow) ──► cambium metabase-proxy ──► Metabase
                 sets X-Forwarded-Email                  mints/caches session,
                                                         injects/sets metabase.SESSION
```
Same trust assumption as Nexus RutAuth today: **metabase-proxy must be reachable only from oauth2-proxy** (NetworkPolicy / same-pod localhost). Anyone who can reach it directly with a forged `X-Forwarded-Email` is that user. This is a deployment requirement, stated in the doc and in the startup log, not something the proxy can enforce itself.

### 3.2 Per-request flow
1. Read `IDENTITY_HEADER`; absent → `401` (oauth2-proxy misconfigured, never fall through to Metabase's own login page).
2. Request carries a `metabase.SESSION` cookie **and its value equals the cached session key for the header identity** → forward as-is, no Metabase API calls. This is the steady-state hot path. The identity check is not optional: a browser can hold a still-valid Metabase cookie for user A (sessions live up to 14 days and never `401`) while oauth2-proxy now vouches for user B — shared machine, or B logged into Keycloak after A signed out. Forwarding on cookie presence alone would let B browse as A indefinitely. Cost of the check: after a proxy restart the cache is cold, so each identity re-mints once — acceptable.
3. No cookie, cookie ≠ cached key for this identity, or upstream answered `401` on an `/api/*` path → obtain a session for the **header** identity (3.3), retry the original request once with `Cookie: metabase.SESSION=<key>` replacing whatever the client sent, and copy Metabase's own `Set-Cookie` headers (from the login response) onto the client response so the browser's cookie is overwritten.
4. `GET /auth/login*` (where Metabase's SPA sends unauthenticated users) → obtain session, respond `302 /` with the cookies set. This is what makes the login page disappear for users.
5. `DELETE /api/session` → forward upstream, then respond `302 SIGN_OUT_REDIRECT` (D4).
6. Everything else: forward with `Cookie` untouched; strip `Authorization`/`X-API-Key` from client requests so nobody can borrow the proxy as an API-key oracle (the proxy's own admin calls use a separate client that never sees client headers).

Cookies are **forwarded verbatim from Metabase's `POST /api/session` response, never constructed**: Metabase sets `metabase.SESSION` (HttpOnly, `Path=/`, `SameSite` from `MB_SESSION_COOKIE_SAMESITE` default `lax`, `Secure` iff the login request looked HTTPS) plus the companion `metabase.TIMEOUT` cookie. For `Secure` to be set correctly the proxy must forward `X-Forwarded-Proto` (and `X-Forwarded-For`, see 3.6) on the login call.

### 3.3 Session acquisition for an identity (`SessionMinter` trait)
```
lookup identity in cache ── hit, not expired ──► use it
        │ miss
        ▼
POST /api/session {username: email, password: derive(email)}
        │ 200 {id}  ──► cache (identity → key, expires now+TTL), use it
        │ 401       ──► self-heal (3.5) then retry once
        │ 4xx other ──► user unknown/deactivated → provision (D1) or 403 page (D2)
```
Cache key is the identity, not (identity, password) as in ropc-proxy — there is no per-request secret here. Cache entry is invalidated on any upstream `401` for that identity.

### 3.4 Password ownership — deterministic derivation, no storage
`password(email) = base64url(HMAC-SHA256(METABASE_PASSWORD_SEED, lowercase(email)))` + fixed suffix that guarantees every class `MB_PASSWORD_COMPLEXITY=strong` can demand (upper, lower, digit, symbol) regardless of what the HMAC output happens to contain.
- Nothing secret is written to disk besides the seed the operator already manages. The manifest never learns passwords.
- Rotation = rotate the seed → every next login fails once → self-heal resets it. No migration.
- Any two proxy replicas derive the same password, so **`metabase-proxy` is safe at `replicas > 1`** — unlike `sync`, it has no manifest and self-heal is idempotent. Stated explicitly because "run exactly one instance" is otherwise Cambium's rule.

### 3.5 Self-heal on `401`
Trigger: login returns `401` for a user that exists and is active (they changed their password in the UI, used "forgot password", or the seed was rotated).
- `PUT /api/user/:id/password {password: derive(email)}` with the Administrators API key — admins are exempt from `old_password` (`users_rest/api.clj` `check-self-or-superuser` + `*is-superuser?*` branch), then retry login once.
- **Hard cap: one reset per identity per `SELF_HEAL_COOLDOWN_SECONDS`.** Metabase throttles `POST /api/session` per lower-cased username and per client IP (`login-throttlers`, `throttle.core`); an unbounded retry loop on a mis-derived password would lock the real human out. After the cap: `503` with a log line, no further Metabase calls for that identity until the window passes.
- Users can still trigger "forgot password" emails; harmless (next login heals) but noisy — document that disabling password resets is a Metabase-side choice, not Cambium's.

### 3.6 Provisioning on first login (only under D1(b), or as a fallback if `sync` hasn't run yet under D1(a))
`POST /api/user {email, first_name, last_name, password: derive(email), user_group_memberships: DEFAULT_GROUPS ids}`. Group name → id via `GET /api/permissions/group`, cached with its own TTL. A user who exists but is deactivated is **not** reactivated (D2).

### 3.7 Throttling correctness
Forward `X-Forwarded-For` on the login call and set Metabase `MB_SOURCE_ADDRESS_HEADER=X-Forwarded-For` (its default) so the per-IP throttler sees real clients rather than the proxy's pod IP; otherwise a handful of legitimate first-logins in one minute trip the shared IP bucket (`attempts-threshold 50` on master).

### 3.8 What the proxy explicitly does not do
- Does not disable Metabase's password login. In OSS `enable-password-login` only honours an explicit `false` when SSO is configured, i.e. never. The login form stays reachable at the Metabase layer; it's unreachable through the proxy because 3.2 step 4 intercepts it, and the derived passwords are 256-bit so the form is not a weakness.
- Does not touch data permissions, collections, or the permission graph. Group membership is the whole scope, exactly as Nexus roles are.
- Does not verify anything about the identity beyond "oauth2-proxy put it in the header" — same trust model as RutAuth.

---

## 4. Per-target lock and state files

Same rule as today — one `flock`'d lock per manifest, taken at `sync` startup, held for the process lifetime — namespaced so a Nexus sync and a Metabase sync can share a volume without fighting.

| | `TARGET_KIND=nexus` | `TARGET_KIND=metabase` |
|---|---|---|
| `STATE_FILE` default | `/var/lib/cambium/state.json` (legacy, unchanged) | `/var/lib/cambium/metabase-state.json` |
| `LOCK_FILE` default | `/var/lib/cambium/cambium.lock` (legacy, unchanged) | `/var/lib/cambium/metabase.lock` |

- Explicit env always wins over defaults, as now.
- **One manifest per target, never shared.** Manifest keys are Keycloak-side (`{realm}/{username}`) and values are target-side role identifiers; a shared file would mix Nexus role IDs with Metabase group ids under the same keys. `sync` writes a `target_kind` field into the manifest on save and refuses to start if an existing manifest's `target_kind` disagrees with the configured one — protects against the obvious "copied the Nexus deployment, changed `TARGET_KIND`, forgot `STATE_FILE`" mistake. Legacy manifests without the field are treated as `nexus`.
- `metabase-proxy` takes **no lock** (stateless apart from the in-memory session cache), identical to `ropc-proxy` today, and is the one Cambium process that may scale horizontally (3.4).
- The `LockError::AlreadyLocked` message mentions `docs/sync-semantics.md`; it should also name the target kind so two syncs colliding on a misconfigured shared path is diagnosable from the one log line.

---

## 5. Framing delta — literal replacement text

Apply mechanically once the note is approved. Nothing here is code.

### 5.1 `README.md` — first paragraph, replace with:
> Cambium is a Keycloak translator for applications that have no OIDC support of their own. It authenticates users once against Keycloak (through a standard OIDC proxy such as `oauth2-proxy`), hands the resulting identity to the target application in whatever form that application can trust, and keeps the application's native user/role model in sync with Keycloak group membership. It never touches the target's code — no plugins, no jar patching, no forks.
>
> Supported targets: **Sonatype Nexus Repository 3 CE** (via its built-in `RutAuthRealm` header trust + a ROPC shim for CLI tools) and **Metabase OSS** (via its session API, since Metabase OSS has no header trust and reserves OIDC/SAML for paid tiers).

### 5.2 `README.md` — "Subcommands", replace with:
> `cambium` is one binary with four subcommands:
> - `cambium sync` (default with no subcommand) — role-sync daemon; `TARGET_KIND` selects `nexus` (default) or `metabase`.
> - `cambium ropc-proxy` — Basic-auth → RutAuth header shim for CLI tools in front of Nexus.
> - `cambium metabase-proxy` — identity header → Metabase session shim, sits behind oauth2-proxy in front of Metabase. See `docs/metabase-target.md`.

Keep the "Run exactly one instance" callout but scope it: "applies to `cambium sync` (per target); `ropc-proxy` and `metabase-proxy` are stateless and may run more than one replica."

### 5.3 `ARCHITECTURE.md`
- "What this is" — replace the first paragraph with the README 5.1 text.
- Keep "Why not a custom Realm plugin" and "The actual mechanism" as-is but retitle them **"Target: Nexus 3 CE"** with sub-headings; the ASCII diagram stays.
- Add **"Target: Metabase OSS"** after it, containing the 3.1 diagram and one paragraph: Metabase has no header trust; Cambium owns per-user derived passwords and mints sessions via `POST /api/session`; group membership synced via `PUT /api/user/:id user_group_memberships`. Link to this doc.
- Add a **"Target abstraction"** section: one paragraph on `RoleTarget` and the whole-array-replace observation from 1.1 that lets `reconcile_roles` and the manifest stay target-agnostic.
- "Non-goals" — replace `Not a general SSO gateway — scoped specifically to Nexus.` with:
  > Not an identity provider and not an OIDC proxy — Keycloak stays the IdP, `oauth2-proxy` (or equivalent) does browser authentication. Cambium only translates an already-authenticated identity into what each target can consume, and syncs authorization. Adding a target means adding a `RoleTarget` impl and, if the target has no header trust, a session shim; never patching the target.
- "Tech stack" — unchanged.

### 5.4 `Cargo.toml`
`description = "Keycloak translator for apps without OIDC: syncs Keycloak group membership into Nexus 3 CE and Metabase OSS, and bridges their logins to Keycloak"`

### 5.5 `src/main.rs` clap `about`
`Cambium: a Keycloak translator for apps without OIDC (Nexus 3 CE, Metabase OSS). See ARCHITECTURE.md.`

### 5.6 GitHub repo description / topics
Mirror 5.4; add topics `metabase`, `keycloak`, `nexus3`, `oidc`, `oauth2-proxy`.

### 5.7 Not changed
`docs/oidc-proxy-pairing.md`, `docs/sync-semantics.md`, `docs/operations.md`, `docs/cutover-plan.md`, `docs/load-test-results.md` remain Nexus-specific and get one line at the top saying so. The dev `docker-compose.yml` gains a `metabase` service + `cambium-metabase-sync` + `cambium-metabase-proxy` behind an `oauth2-proxy` service, so the Metabase path is exercisable on a laptop the way the Nexus path already is.

---

## 6. Implementation order (after mark-up)
1. `src/target.rs` + `impl RoleTarget for NexusClient`; `sync.rs` generic over `&dyn RoleTarget`. **Existing tests must pass unchanged** — this step has no observable behaviour change.
2. `Config` split with `TARGET_KIND` default `nexus`; `UPSTREAM_URL` alias. Existing compose file runs with zero edits.
3. `src/metabase.rs` client + `RoleTarget` impl; per-target lock/state defaults; manifest `target_kind` guard.
4. `src/metabase_proxy.rs`; dev compose additions; unit tests with fake `SessionMinter`/`Clock` in the ropc.rs style.
5. Framing delta (section 5).
6. Live validation against a disposable Metabase container in the dev stack, then the section-8 checklist.

---

## 7. Sequencing relative to Nexus
Nothing here touches the running `nexus-green` deployment or blue. Step 1–2 is a refactor that should be deployed to `nexus-green` first and observed for a couple of passes (same log lines, same manifest content) before any Metabase code lands — it is the cheapest possible proof of the zero-change invariant.

---

## 8. Unverified — check on the dev stack before code
- [ ] Does `POST /api/user` send an invite email when `password` is supplied? (drives D1)
- [ ] Does `maybe-set-user-group-memberships!` tolerate omitting `All Users` from `user_group_memberships`, or must it always be present? Does including/excluding `Administrators` toggle `is_superuser` as expected?
- [ ] Does an API key assigned to `Administrators` pass `check-superuser` on `PUT /api/user/:id/password` and `DELETE /api/user/:id`? (API keys act as their group; confirm superuser semantics, not just group permissions.)
- [ ] Derived password + suffix satisfies `MB_PASSWORD_COMPLEXITY=strong` and any `MB_PASSWORD_LENGTH` in use.
- [ ] Are Metabase group names unique? (Backs the `ROLE_MAP` name → id resolution; if not, fall back to ids in `ROLE_MAP`.)
- [ ] Exact `POST /api/session` failure codes for: unknown email, deactivated user, wrong password — the proxy branches on them (3.3).
- [ ] Which Metabase version is actually deployed, and does its `/api/docs` match the shapes above (`user_group_memberships` on `PUT /api/user/:id`, `GET /api/permissions/membership` shape, `old_password` exemption for admins).
- [ ] Logout mechanics for D4: the Metabase SPA issues `DELETE /api/session` as XHR, so a `302` from the proxy will not navigate the browser; the SPA then redirects itself to `/auth/login`, which step 4 of 3.2 turns straight into a fresh session. Check whether a `200` body the SPA honours, or intercepting the follow-up `/auth/login` when the previous request was a logout, is what actually makes "log out" work.
- [ ] `login-throttlers` thresholds on the deployed version (master: per-username default, per-IP 50) — sets `SELF_HEAL_COOLDOWN_SECONDS` floor.

## Progress log
- **2026-08-25**: design note drafted. D1–D4 decided (D1 = (a): Cambium creates Metabase users, Keycloak is source of truth). No code, no edits to README/ARCHITECTURE, nothing deployed.
- **2026-08-25**: **PARKED** by FJK (busy). Resume point: §8 checklist on the dev stack, starting with the invite-email question, then implementation order §6 step 1.
