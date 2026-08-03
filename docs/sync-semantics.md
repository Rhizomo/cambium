# Sync semantics

This document answers the three open design questions from `ARCHITECTURE.md`'s
"Role-sync daemon" section, based on live testing against Keycloak's public
Admin REST API documentation and a disposable local `sonatype/nexus3:latest`
container (never against any Smartech-internal system).

## 1. Nexus user/role API shape (verified against a local Nexus 3 container)

Tested directly against `/service/rest/v1/security/*` on a throwaway
`sonatype/nexus3:latest` container (torn down after testing, never a
Smartech-managed instance):

- **User creation and role assignment happen in one call.** `POST
  /v1/security/users` takes an `ApiCreateUser` body that includes a `roles:
  string[]` field — role IDs are assigned at creation time, no separate call
  needed.
- **There is no per-role assign/revoke endpoint.** The only way to change a
  user's roles after creation is `PUT /v1/security/users/{userId}` with a
  *complete* `ApiUser` body (all required fields: `userId`, `firstName`,
  `lastName`, `emailAddress`, `source`, `status`, plus `roles`). The `roles`
  array is a full replace, not a patch/add/remove. Confirmed by live test:
  omitting `source` on PUT fails with `400 {"id":"PARAMETER source","message":"must
  not be blank"}`; a correct PUT returns `204 No Content` and the new `roles`
  array is exactly what was sent, silently dropping anything not listed.
- **There is no `GET /users/{userId}` single-resource endpoint.** Only `GET
  /v1/security/users?userId=<substring>` (a fuzzy search, not an exact-match
  filter — the caller must filter the returned list for an exact `userId`
  match).
- **Creating a user with a role ID that doesn't exist fails validation
  cleanly**: `400 [{"id":"roles","message":"Unable to locate roleId:
  <name>"}]`.
- **Creating a duplicate `userId` does not return a clean 409.** It throws a
  raw Java exception surfaced as `500`, body: `ERROR: (ID <uuid>)
  org.sonatype.nexus.security.user.DuplicateUserException: User <id> already
  exists.` — plain text, not JSON. Cambium's Nexus client treats this as a
  signal to fall back to update (PUT) rather than parsing it as a generic
  server error, since there is no reliable structured field to key off.
- `DELETE /v1/security/users/{userId}` returns `204`.
- Roles themselves (`/v1/security/roles`) are a separate resource with their
  own privilege lists; Cambium does not create or manage Nexus roles — it
  only assigns/revokes *existing* role IDs that a Nexus admin has already
  defined (e.g. `nx-admin`, or custom roles an admin created for
  repository-scoped privileges). Role provisioning is out of scope for v1;
  the mapping from Keycloak group name to Nexus role ID is operator-supplied
  config (see `Config` in `src/main.rs`).

**Consequence for the reconciliation loop**: because Nexus only exposes a
whole-array replace, Cambium can never compute "the roles to add" and "the
roles to remove" as independent operations against Nexus's API — it always
has to compute the *complete desired role set* and PUT it in full. That
single fact is what makes clobber-avoidance (question 3, below) load-bearing:
if Cambium always overwrote `roles` with only what Keycloak says, it would
silently strip any role a Nexus admin had added by hand outside of Cambium.

## 2. Keycloak effective role mappings (verified against Keycloak's official Admin REST API docs)

- `GET /admin/realms/{realm}/groups` — list a realm's groups (supports
  `briefRepresentation` and pagination; Cambium requests full representation
  since it needs group `id`/`path`).
- `GET /admin/realms/{realm}/groups/{id}/members` — list a group's direct
  members (paginated via `first`/`max`).
- `GET /admin/realms/{realm}/users/{id}/role-mappings/realm` — the user's
  **direct** realm role mappings only (roles assigned straight to the user,
  not through group membership, not composite-expanded).
- `GET /admin/realms/{realm}/users/{id}/role-mappings/realm/composite` —
  Keycloak's own "effective realm role mappings" endpoint. Verified this
  expands **composite role hierarchies** (a role that has other roles nested
  inside it) applied to the user's *direct* assignments. It does **not**
  pull in roles the user only has via group membership — this is a
  documented (if easy to miss) Keycloak behavior, not a Cambium
  interpretation: Keycloak's `role-mappings/.../composite` endpoints operate
  on whatever role set they're rooted at (user-direct, or group-direct), and
  do not themselves walk the user's group memberships.
- Groups have the parallel endpoint `GET
  /admin/realms/{realm}/groups/{id}/role-mappings/realm/composite` — a
  group's own effective (composite-expanded) realm roles.

**Cambium's effective-role computation**, implemented in `src/keycloak.rs`
(`KeycloakClient::effective_realm_roles`):

```
effective_roles(user) =
    composite(user.direct_realm_roles)
    ∪ ⋃_{g in user.groups} composite(g.direct_realm_roles)
```

i.e. Cambium fetches the user's own composite-expanded direct roles, fetches
the user's group memberships (`GET /users/{id}/groups`), then fetches each
group's composite-expanded direct roles, and unions the results. This is the
only combination of documented endpoints that actually answers "what roles
does this user effectively have, direct or via group" — no single Keycloak
endpoint does it in one call.

This was not tested against a live Keycloak server (none was reachable/in
scope to stand up for this task) — it is derived from Keycloak's official
REST API reference and corroborated by community reports of the same
"composite endpoint doesn't expand groups" gap. It should be treated as
verified-by-documentation, not verified-by-live-call, and is flagged as the
one open item in the final report.

## 3. Avoiding clobbering manually-assigned Nexus roles

**Decision: Cambium maintains its own sync manifest (a local, on-disk JSON
state file) recording exactly which Nexus role IDs it last granted to each
user, and diffs against that manifest — not against Nexus's current live
state — to decide what to add or remove.**

### Why not the alternatives

- **Naming-convention scoping** ("Cambium only touches roles matching
  `cambium-*`") was considered and rejected as the *sole* mechanism: it
  would force every Keycloak-driven role in Nexus to be a dedicated
  Cambium-owned role, which conflicts with the realistic case of reusing
  Nexus's built-in roles (`nx-admin`, `nx-anonymous`) or roles an admin
  already created for repository-scoped privileges — Cambium's whole job is
  to assign *existing* Nexus roles based on Keycloak group membership, per
  ARCHITECTURE.md's `Non-goals` (it doesn't manage Nexus role definitions).
  A naming convention says nothing about *provenance* of an assignment on a
  role Cambium doesn't own the name of.
- **Diffing against live Nexus state on every run** (compute
  `desired = keycloak_roles`, PUT that verbatim) is the naive approach and is
  exactly the clobbering bug this question exists to prevent — confirmed
  live: Nexus's `roles` field is a full replace with no memory of who put
  what there.

### The mechanism

On each reconciliation pass, per user:

```
desired_now      = effective_realm_roles_from_keycloak(user)   -- mapped to Nexus role IDs
last_synced      = manifest.get(user.username)                  -- what Cambium itself granted last time
current_in_nexus = nexus.get_user(user.username).roles           -- ground truth right now

foreign_roles    = current_in_nexus - last_synced   -- roles Cambium didn't put there
new_roles        = foreign_roles ∪ desired_now

if new_roles != current_in_nexus:
    nexus.put_user(user.username, roles = new_roles)

manifest.set(user.username, desired_now)   -- record what *Cambium* granted, not the full new_roles
manifest.persist()
```

- A role present in `current_in_nexus` but absent from `last_synced` is
  assumed to be a manual admin grant (or a grant from some other tool) and is
  always preserved verbatim — Cambium unions it back in every pass.
- A role Cambium itself granted last time (`last_synced`) that Keycloak no
  longer justifies is dropped (see question 2's revocation answer below) —
  that's the "destructive but deliberate" behavior the manifest makes safe,
  because Cambium only ever removes roles it can prove it added.
- The manifest is keyed by username and stores a plain set of Nexus role
  IDs, persisted as JSON (`--state-file`, default
  `/var/lib/cambium/state.json`). It is intentionally not derived from
  Nexus's live state at read time, because live state can't distinguish
  provenance — only Cambium's own memory can.
- First-run / manifest-loss failure mode: if the manifest is empty or
  missing (fresh install, or the state file was deleted), `last_synced` is
  treated as the empty set for every user, so **all** of that user's
  existing Nexus roles are treated as foreign and preserved, and Cambium
  only adds what Keycloak now grants. This trades a slower "catch-up" for
  safety: a lost manifest never causes an unexpected mass revocation, it
  just means Cambium temporarily can't clean up roles it granted before the
  manifest was lost, until they're re-synced. This is the deliberate
  fail-safe direction (fail open on revocation, never fail open on grants
  the config no longer justifies would be added anyway on the next pass
  regardless of manifest state).

### Revocation policy (question 2)

Cambium **does** revoke: when a user's Keycloak group membership no longer
grants a Nexus role Cambium previously assigned (per the manifest), Cambium
removes it on the next poll. This is deliberate, not a "stop granting new
ones and let it go stale" approach, because stale grants are themselves a
security problem (ARCHITECTURE.md frames Cambium as the *authorization*
half of the RutAuth setup — stale roles mean Keycloak group removal doesn't
actually revoke access, which defeats the point). The manifest is what makes
this safe to do automatically: Cambium can prove which roles are its own to
take back.

### Multi-realm note (question 4)

The manifest key is `(keycloak_realm, username)`, not bare `username`, even
though v1 config only points at one realm — this keeps the state file shape
extensible to multi-realm without a migration.

### Durability: manifest is saved after every user, not once per batch

`src/sync.rs::run_pass` persists the manifest (`Manifest::save`) immediately
after each user is successfully reconciled, inside the per-user loop — not
once at the end of the whole batch. This matters because a manifest entry is
only trustworthy once it's on disk: if Cambium applied a role change to
Nexus but the process died before the manifest recorded that it did so
(OOM-kill, node preemption, anything), the next pass would see that role in
Nexus with no corresponding manifest entry and treat it as a foreign
(manually-assigned) role forever — meaning Cambium could never prove it
granted that role and could never revoke it again, even after the
underlying Keycloak group membership was removed. That's a silent,
permanent hole in exactly the revocation guarantee this document exists to
provide. Saving per-user bounds the exposure to "the single user currently
being processed when the process dies," not "everyone processed since the
last save." See
`sync::tests::crash_after_user_n_before_final_save_does_not_lose_track_of_granted_roles`
for a test that models a mid-batch crash and confirms the manifest still
converges correctly on the next pass.

### Single-instance-only (v1 hard requirement)

The manifest is a single JSON file read-modified-written wholesale, with no
transactions, no optimistic concurrency, no partial-write protection. Two
Cambium processes reconciling against the same manifest — two replicas, or
one slow pass overlapping the start of the next poll interval — would race
on that file: a later writer's full rewrite can silently discard the
other's in-flight changes, which is the same "lost provenance, can never
revoke again" failure mode as the crash case above, except continuous
instead of one-time.

**v1 does not support running more than one instance against a given
manifest.** This is enforced, not just documented: `src/lock.rs` takes an
OS-level exclusive `flock` on a dedicated lock file (`LOCK_FILE`, default
`/var/lib/cambium/cambium.lock`) for the lifetime of the process, acquired
once at startup before the first reconciliation pass. A second instance
pointed at the same lock file fails fast at startup with a clear error
(`LockError::AlreadyLocked`) instead of silently corrupting shared state.
Deployers must keep `replicas: 1` (or equivalent) for this workload; the
lock only prevents *silent* violation of that constraint, it doesn't make
multi-replica operation supported or safe to rely on for HA — a v2 wanting
real multi-instance operation would need to replace the manifest with
something that has actual concurrency control (e.g. a database row per
user with compare-and-swap), not just add more locking around the same JSON
file.
