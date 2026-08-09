# Cambium local dev stack

`docker-compose.yml` (repo root) + this directory spin up a disposable
Keycloak + Nexus3 CE + both Cambium subcommands, entirely local. Nothing
here talks to any private/production system.

## Realm shape (`keycloak/realm-export.json`)

Deliberately mirrors the *shape* of a realistic Keycloak/Nexus RBAC setup
(multiple groups, subgroup inheritance, a composite role, users with no
group membership at all) without copying any real org's group/user names —
everything is synthetic (`team-alpha`, `role-viewer`, `svc-direct-1`, ...).

- **7 realm roles**, one composite: `role-superuser` = `role-viewer` +
  `role-ops` + `role-billing`. Plus the original `nexus-admin` role.
- **6 groups**, each mapped 1:1 to a realm role (the group -> bridge-role ->
  `ROLE_MAP` -> Nexus-role chain):
  - `/nexus-admins` -> `nexus-admin` (original single-user case, kept)
  - `/team-alpha` -> `role-viewer`
  - `/team-beta` -> `role-editor`
  - `/team-gamma` -> `role-publisher`, with a **subgroup** `/team-gamma/team-gamma-leads` (no role mapping of its own — exercises Keycloak's group-hierarchy role inheritance)
  - `/team-delta` -> `role-auditor`
  - `/team-epsilon` -> `role-superuser` (composite, exercises composite-role expansion via group mapping)
- **23 users** total:
  - 15 via direct group membership (`team-alpha`/`team-beta`/`team-delta` x3 each, `team-gamma` direct x2, `team-epsilon` x2), plus `alice` in `/nexus-admins`.
  - 2 (`user-gamma-lead-1`, `user-gamma-lead-2`) belong **only** to the `team-gamma-leads` subgroup — no direct membership in `team-gamma` itself.
  - 4 (`svc-direct-1..4`) have realm roles assigned **directly on the user**, with **zero group membership** — the case Cambium's v1 scoping (`src/sync.rs` doc comment on `run_pass`) explicitly excludes today.

## Nexus roles

`dev/nexus-init/init.sh` now also creates the custom Nexus roles the
`ROLE_MAP` in `docker-compose.yml` targets (`nx-viewer`, `nx-editor`,
`nx-publisher`, `nx-auditor`, `nx-ops`, `nx-billing`, `nx-superuser`), with
empty privilege lists — sufficient for Cambium's user/role sync path, which
never checks privilege contents. `nx-admin` remains Nexus's own built-in
role.

## Running it

```bash
docker compose up --build -d
docker compose logs -f cambium-sync
```

Wait for `nexus-init` to exit 0 (`docker compose logs nexus-init`, look for
the trailing `done.` line) before expecting `cambium-sync` to have anything
to reconcile against.

## Verifying a pass

```bash
curl -s -u admin:admin123 http://localhost:8081/service/rest/v1/security/users \
  | jq -r '.[] | select(.source=="default") | [.userId, (.roles|join("|"))] | @tsv' | sort
```

Expected (as of the last verified run, see repo session notes):
- `user-alpha-*` -> `nx-viewer`, `user-beta-*` -> `nx-editor`, `user-delta-*` -> `nx-auditor`, `user-gamma-1`/`user-gamma-2` -> `nx-publisher`, `alice` -> `nx-admin`.
- `user-epsilon-*` -> all four of `nx-viewer`/`nx-ops`/`nx-billing`/`nx-superuser` (composite expansion).
- `user-gamma-lead-1`/`user-gamma-lead-2`: **do not appear at all**, in any pass. Root cause: `KeycloakClient::list_groups` (`src/keycloak.rs`) only calls `GET /admin/realms/{realm}/groups`, which (verified live against Keycloak 26.0) returns top-level groups with a `subGroupCount` but an **empty** `subGroups` array — subgroups require a separate `GET /groups/{id}/children` call that Cambium never makes. `run_pass` (`src/sync.rs`) then only ever calls `group_members` on what `list_groups` returned, so a user who belongs *only* to a subgroup is never added to the discovery set at all — not mis-synced, just invisible, no warning. This is a real gap, not a config problem in this dev stack. (The role-inheritance math itself is fine: a direct query of the subgroup's own `role-mappings/realm/composite` correctly returns the parent group's mapped role — verified live. The bug is purely in *discovering* the subgroup exists.)
- `svc-direct-1..4`: as of the last run, **synced correctly** (`nx-ops`, `nx-billing`, `nx-viewer`, and — for the one with the composite role assigned directly — all four of `nx-viewer`/`nx-ops`/`nx-billing`/`nx-superuser`). This validates the parallel `src/sync.rs`/`src/keycloak.rs` fix (`users_with_direct_realm_role`, `GET /roles/{role-name}/users`) once it landed.

## Teardown

```bash
docker compose down -v
```

Removes the Nexus/Keycloak data volumes too — the next `up` starts from a
clean realm import and a fresh Nexus first-boot.
