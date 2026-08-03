# Contributing to Cambium

## Build

```
cargo build
```

Release build (what the Dockerfile produces):

```
cargo build --release
```

## Test

```
cargo test
```

Every network-touching component (`KeycloakClient`, `NexusClient`, the ROPC
`TokenExchanger`) is abstracted behind a trait specifically so the test suite
never needs a live Keycloak/Nexus — see `src/sync.rs`'s pure `reconcile_roles`
and `src/ropc.rs`'s `FakeClock`/`CountingExchanger` for the pattern. Keep new
logic testable the same way: push the actual HTTP call behind a thin trait,
test the surrounding decision logic against a fake.

## Run the local dev stack

`docker-compose.yml` at the repo root brings up a full, disposable
Keycloak + vanilla Nexus3 CE + both Cambium subcommands, wired together end
to end:

```
docker compose up --build
```

This seeds a Keycloak realm (`dev/keycloak/realm-export.json`: a test user
`alice` / `alice-password` in a group mapped to a `nexus-admin` realm role),
enables Nexus's `rutauth` capability via its REST API
(`dev/nexus-init/init.sh`), and starts `cambium sync` and
`cambium ropc-proxy` pointed at both. Once `nexus-init` has exited
successfully and `cambium-sync` has logged its first reconciliation pass,
try the whole path in one shot:

```
curl -u alice:alice-password http://localhost:8090/service/rest/v1/security/users
```

That request flows: ROPC proxy (`localhost:8090`) → Keycloak password-grant
exchange → `preferred_username` claim extracted → injected as
`X-Forwarded-User` → forwarded to Nexus (`localhost:8081`) → Nexus's
`RutAuthRealm` trusts the header → authorization checked against the Nexus
`User` record Cambium's sync daemon created moments earlier from `alice`'s
Keycloak group membership. A request to the same URL with no credentials,
or straight to `localhost:8081` bypassing the proxy, gets a `401` — RutAuth
only trusts the header when a proxy that's supposed to authenticate first,
authenticated first.

Tear down (including the Nexus/Keycloak data volumes — start clean next
time):

```
docker compose down -v
```

All credentials in `docker-compose.yml` and `dev/` are fixed, throwaway
dev-only values. Never reuse them, and don't add anything containing a real
secret to this stack.

## Code style

- Run `cargo clippy --all-targets -- -D warnings` before committing. Zero
  warnings required — same bar as `grafter`, this project's sibling.
- No comments that just restate what the code does. Comments earn their
  place by explaining *why* — a non-obvious API constraint, a security
  invariant, a decision that looks wrong until you know the reason (see
  nearly every comment in `src/ropc.rs` and `src/sync.rs` for the standard
  this project holds itself to).
- Keep network I/O behind a trait (`TokenExchanger`, `KeycloakClient`,
  `NexusClient`) so pure logic stays unit-testable without a live server.

## Filing issues / PRs

- Open an issue describing the problem or proposed change before a large
  PR — this is a small, focused project and design discussions belong in
  the issue, not buried in a diff.
- PRs: explain *why*, not just *what*. Link to the relevant section of
  `ARCHITECTURE.md`, `docs/sync-semantics.md`, or
  `docs/oidc-proxy-pairing.md` if the change touches a documented design
  decision — if it contradicts one, say so explicitly and update the doc in
  the same PR rather than leaving it stale.
- `cargo test` and `cargo clippy --all-targets -- -D warnings` must both be
  clean before requesting review.

## Design principles

- **Clean-room, always.** Cambium is built only against Nexus's and
  Keycloak's own public REST APIs. No Sonatype source code, patched jar, or
  derivative of either — ever, in any form, regardless of how small the
  shortcut looks. See ARCHITECTURE.md's "Why not a custom Realm plugin" for
  why this line matters here specifically (Nexus CE's license and the fate
  of the one prior community plugin that didn't respect it).
- **Verify against the real thing, don't guess.** Every non-obvious claim in
  this codebase's docs is backed by either a live call against a disposable
  local container (see `docs/sync-semantics.md` section 1) or a citation to
  the vendor's own docs/issue tracker (see `docs/oidc-proxy-pairing.md`
  throughout). When you add a new integration point, hold your own change to
  the same bar — a comment asserting API behavior should be traceable to
  where that behavior was actually confirmed.
- **State the limits plainly.** `docs/oidc-proxy-pairing.md`'s "honest gap"
  section says outright that ROPC is a deprecated grant type this project
  can only mitigate, not fix. `docs/sync-semantics.md` flags its
  effective-role computation as "verified-by-documentation, not
  verified-by-live-call" where that's true. Follow the same pattern: when
  something is untested, assumed, or a known tradeoff, write that down next
  to the code or in the relevant doc instead of letting the implementation
  imply more confidence than was actually earned.
