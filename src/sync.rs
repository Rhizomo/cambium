//! The reconciliation loop: Keycloak effective realm roles -> Nexus
//! User/Role assignments, applying the clobber-avoidance semantics
//! documented in `docs/sync-semantics.md`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use async_trait::async_trait;
use tracing::{info, warn};

use crate::error::{CambiumError, CambiumResult};
use crate::keycloak::{KcGroup, KcUser, KeycloakClient};
use crate::manifest::Manifest;
use crate::nexus::{NewNexusUser, NexusClient};

/// Pure input to the diffing algorithm — deliberately network-free so it's
/// exhaustively unit-testable (see the `tests` module below).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileInput {
    /// The Nexus role IDs Keycloak justifies *right now*, already mapped
    /// through `ROLE_MAP`.
    pub desired_managed_roles: HashSet<String>,
    /// What Cambium itself granted on the last successful pass, per the
    /// manifest.
    pub last_synced_roles: HashSet<String>,
    /// The user's actual `roles` array in Nexus right now (empty if the
    /// user doesn't exist yet in Nexus).
    pub current_nexus_roles: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// The complete role set Nexus should end up with.
    pub new_roles: HashSet<String>,
    /// Whether `new_roles` differs from `current_nexus_roles` (i.e.
    /// whether a Nexus API call is actually needed).
    pub changed: bool,
}

/// The core diff: preserve anything in Nexus that Cambium didn't itself put
/// there last time (`current - last_synced`), then union in whatever
/// Keycloak justifies now. This is what makes a `PUT` (whole-array replace)
/// safe to issue without clobbering manual admin grants — see
/// `docs/sync-semantics.md` question 3.
pub fn reconcile_roles(input: &ReconcileInput) -> ReconcileOutcome {
    let foreign: HashSet<String> = input
        .current_nexus_roles
        .difference(&input.last_synced_roles)
        .cloned()
        .collect();

    let mut new_roles = foreign;
    new_roles.extend(input.desired_managed_roles.iter().cloned());

    let changed = new_roles != input.current_nexus_roles;

    ReconcileOutcome { new_roles, changed }
}

/// Whether Cambium must refuse to touch this Nexus `userId`.
///
/// Nexus ships built-in local accounts (`admin`, `anonymous`), and
/// `RutAuthRealm` maps a header value straight onto a `userId` with no
/// verification — so a Keycloak user named `admin` authenticates as Nexus's
/// built-in superuser regardless of anything in `ROLE_MAP`. Cambium cannot
/// close that (it is a property of RutAuth, see THREAT_MODEL.md 2.6), but it
/// must not make it worse by provisioning or re-roling those accounts itself.
///
/// Case-insensitive: Nexus resolves `userId` case-insensitively, so `Admin`
/// reaches the same account as `admin`.
pub fn is_reserved_username(username: &str, reserved: &HashSet<String>) -> bool {
    reserved.contains(&username.to_lowercase())
}

/// Maps a set of effective Keycloak realm role names through `role_map`
/// (Keycloak realm role name -> Nexus role ID) to the subset that Cambium
/// knows how to translate. Roles with no configured mapping are silently
/// ignored — Cambium only ever grants Nexus roles an operator has
/// explicitly wired up via config, never invents one.
pub fn map_to_nexus_roles(
    effective_kc_roles: &HashSet<String>,
    role_map: &HashMap<String, String>,
) -> HashSet<String> {
    effective_kc_roles
        .iter()
        .filter_map(|kc_role| role_map.get(kc_role))
        .cloned()
        .collect()
}

/// A user discovered by either source, carrying everything the
/// reconciliation decision needs. `enabled` is load-bearing: a user disabled
/// in Keycloak must have their Cambium-granted Nexus roles revoked, so the
/// flag has to survive discovery rather than being dropped here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredUser {
    pub username: String,
    pub enabled: bool,
}

/// Folds a batch of `KcUser`s into the running discovery set, keyed by
/// Keycloak user id so a user found via both group membership and a direct
/// role assignment is one entry, not two.
///
/// A `KcUser` with no `enabled` field at all is treated as enabled. Keycloak
/// always sends it on a `UserRepresentation`, so this only covers a response
/// shape Keycloak doesn't currently produce — and defaulting the other way
/// would mass-revoke every user in the realm the first time an upgrade
/// changed that. Only an explicit `"enabled": false` revokes.
fn merge_users(members: &mut HashMap<String, DiscoveredUser>, users: Vec<KcUser>) {
    for u in users {
        members.insert(
            u.id,
            DiscoveredUser {
                username: u.username,
                enabled: u.enabled.unwrap_or(true),
            },
        );
    }
}

/// Abstracts the two group-tree calls `discover_group_tree_members` needs,
/// so the recursive-traversal logic can be unit tested against an in-memory
/// fake tree instead of a live Keycloak server — same pattern as
/// `ropc::TokenExchanger`.
#[async_trait]
trait GroupTreeSource: Send + Sync {
    async fn children(&self, group_id: &str) -> CambiumResult<Vec<KcGroup>>;
    async fn members(&self, group_id: &str) -> CambiumResult<Vec<KcUser>>;
}

struct LiveGroupTree<'a> {
    kc: &'a KeycloakClient,
    realm: &'a str,
}

#[async_trait]
impl GroupTreeSource for LiveGroupTree<'_> {
    async fn children(&self, group_id: &str) -> CambiumResult<Vec<KcGroup>> {
        self.kc.group_children(self.realm, group_id).await
    }

    async fn members(&self, group_id: &str) -> CambiumResult<Vec<KcUser>> {
        self.kc.group_members(self.realm, group_id).await
    }
}

/// Breadth-first walk of every top-level group and all of its descendant
/// subgroups, to arbitrary nesting depth, unioning every group's and
/// subgroup's direct members into one discovery set via `merge_users`.
/// Keycloak's `GET /groups/{id}/children` (see `KeycloakClient::group_children`)
/// only returns *immediate* children, so nested subgroups-of-subgroups need
/// repeated calls — this is that repetition.
///
/// `seen` guards against revisiting a group id: Keycloak's own group model
/// doesn't allow a group to be its own ancestor, so a cycle should never
/// occur in practice, but nothing here should hang forever on a malformed or
/// unexpected response, so each group is fetched at most once regardless.
async fn discover_group_tree_members<S: GroupTreeSource>(
    source: &S,
    top_level_groups: &[KcGroup],
) -> CambiumResult<HashMap<String, DiscoveredUser>> {
    let mut members = HashMap::new();
    let mut seen = HashSet::new();
    let mut queue: VecDeque<KcGroup> = top_level_groups.iter().cloned().collect();

    while let Some(group) = queue.pop_front() {
        if !seen.insert(group.id.clone()) {
            continue;
        }

        let group_members = source.members(&group.id).await?;
        merge_users(&mut members, group_members);

        let children = source.children(&group.id).await?;
        queue.extend(children);
    }

    Ok(members)
}

/// One full reconciliation pass: Keycloak groups (recursively, including all
/// nested subgroups) -> members, unioned with Keycloak roles -> direct role
/// assignees -> effective roles -> Nexus.
///
/// User discovery draws on two complementary Keycloak sources rather than a
/// full-realm user dump: every group's and subgroup's membership, walked to
/// arbitrary nesting depth by `discover_group_tree_members`
/// (`list_groups` + recursive `group_children` + `group_members`), and, for
/// every Keycloak role name Cambium has a mapping for in `role_map`,
/// everyone with that role assigned directly
/// (`users_with_direct_realm_role`). The second source exists because
/// group-membership traversal alone misses users with a realm role assigned
/// straight to them and no group membership at all — the classic case is a
/// service account created with a direct role grant and never put in a
/// group — see `docs/sync-semantics.md` section 2. The recursive part of the
/// first source exists because `GET /groups` only returns top-level groups
/// with an always-empty `subGroups` array — a user belonging only to a
/// subgroup (at any nesting depth) is otherwise invisible to discovery, even
/// though `effective_realm_roles` would resolve their inherited role
/// correctly if they were ever found — see `docs/sync-semantics.md` section
/// 2. Once a user is discovered by either path,
/// `effective_realm_roles` below recomputes their full direct-or-inherited
/// role set anyway, so which path found them doesn't affect the outcome.
#[allow(clippy::too_many_arguments)]
pub async fn run_pass(
    kc: &KeycloakClient,
    nexus: &NexusClient,
    kc_realm: &str,
    role_map: &HashMap<String, String>,
    manifest: &mut Manifest,
    fallback_email_domain: &str,
    reserved_usernames: &HashSet<String>,
    state_file: &Path,
) -> CambiumResult<()> {
    let groups = kc.list_groups(kc_realm).await?;
    info!(count = groups.len(), "fetched top-level Keycloak groups");

    let tree = LiveGroupTree {
        kc,
        realm: kc_realm,
    };
    let mut members = discover_group_tree_members(&tree, &groups).await?;
    info!(
        count = members.len(),
        "distinct users across all groups and subgroups"
    );

    for role_name in role_map.keys() {
        match kc.users_with_direct_realm_role(kc_realm, role_name).await {
            Ok(direct_users) => merge_users(&mut members, direct_users),
            // Operator typo'd ROLE_MAP, or the role was deleted in Keycloak
            // after ROLE_MAP was written — neither invalidates the rest of
            // this pass, so treat it as "nobody has this role directly" and
            // keep going, same fail-soft posture as the per-user loop below.
            Err(CambiumError::NotFound) => {
                warn!(role_name, "keycloak realm role from ROLE_MAP does not exist; skipping direct-assignment lookup for it");
            }
            Err(e) => {
                warn!(role_name, error = %e, "failed to fetch direct role assignees, continuing with next role");
            }
        }
    }
    info!(
        count = members.len(),
        "distinct users across groups and direct role assignments"
    );

    for (user_id, user) in members {
        let username = user.username.as_str();
        if is_reserved_username(username, reserved_usernames) {
            warn!(
                username,
                "keycloak username collides with a reserved Nexus account; refusing to sync it \
                 (anyone authenticating under this name via RutAuth reaches Nexus's own local \
                 account — see THREAT_MODEL.md 2.6)"
            );
            continue;
        }
        match sync_one_user(
            kc,
            nexus,
            kc_realm,
            &user_id,
            username,
            user.enabled,
            role_map,
            manifest,
            fallback_email_domain,
        )
        .await
        {
            Err(e) => {
                warn!(username, error = %e, "failed to sync user, continuing with next");
                // sync_one_user only updates `manifest` in memory after a
                // successful Nexus write, so a failure here left the
                // in-memory manifest untouched for this user — nothing to
                // persist, nothing lost.
                continue;
            }
            Ok(()) => {
                // Persist after *every* user, not once at the end of the
                // batch. If the process dies partway through a large batch
                // (OOM-kill, node preemption, etc.), every grant already
                // applied to Nexus up to this point is durably recorded,
                // so a future pass can still prove Cambium granted it and
                // revoke it once Keycloak access goes away. Saving once at
                // the end would mean a mid-batch crash permanently loses
                // that provenance for every user processed since the last
                // save — see docs/sync-semantics.md and
                // `sync::tests::crash_after_user_n_before_final_save_does_not_lose_track_of_granted_roles`.
                if let Err(e) = manifest.save(state_file) {
                    warn!(username, error = %e, "failed to persist manifest after syncing user");
                }
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn sync_one_user(
    kc: &KeycloakClient,
    nexus: &NexusClient,
    kc_realm: &str,
    kc_user_id: &str,
    username: &str,
    enabled: bool,
    role_map: &HashMap<String, String>,
    manifest: &mut Manifest,
    fallback_email_domain: &str,
) -> CambiumResult<()> {
    // A user disabled in Keycloak justifies nothing. Resolving to an empty
    // desired set (rather than skipping the user) is what makes this a
    // *revocation*: `reconcile_roles` below removes exactly the roles Cambium
    // granted last pass and leaves anything an admin assigned by hand alone,
    // the same clobber-avoidance contract every other path here honors.
    //
    // Deliberately does not force Nexus's `status` to `disabled`: Cambium
    // only ever undoes what Cambium did, and the account may predate it or be
    // shared with another realm. See docs/sync-semantics.md.
    let desired_managed_roles = if enabled {
        let effective = kc.effective_realm_roles(kc_realm, kc_user_id).await?;
        map_to_nexus_roles(&effective, role_map)
    } else {
        HashSet::new()
    };
    let last_synced_roles = manifest.last_synced(kc_realm, username);

    let existing = nexus.get_user(username).await?;

    match existing {
        None => {
            if desired_managed_roles.is_empty() {
                // Nothing to grant, and the user doesn't exist in Nexus
                // yet — no reason to create an empty account.
                return Ok(());
            }
            info!(username, roles = ?desired_managed_roles, "creating new Nexus user");
            let create_result = nexus
                .create_user(NewNexusUser {
                    user_id: username.to_string(),
                    first_name: username.to_string(),
                    last_name: "(cambium)".to_string(),
                    email_address: resolve_email_address(username, fallback_email_domain),
                    // RutAuth means Nexus's own local password is never
                    // actually used to authenticate — Keycloak (via the
                    // OIDC proxy) is the real authentication path. This is
                    // just a placeholder Nexus requires at creation time.
                    password: random_placeholder_password(),
                    roles: desired_managed_roles.iter().cloned().collect(),
                })
                .await;

            match create_result {
                Ok(_) => {}
                // Lost a race with something else creating the same user
                // between our GET and our POST — fall through and let the
                // next pass reconcile it via the update path.
                Err(CambiumError::NexusUserAlreadyExists(_)) => {}
                Err(other) => return Err(other),
            }
        }
        Some(current) => {
            let current_nexus_roles: HashSet<String> = current.roles.iter().cloned().collect();
            if !enabled && !last_synced_roles.is_empty() {
                info!(
                    username,
                    revoking = ?last_synced_roles,
                    "user is disabled in Keycloak, revoking the roles Cambium granted"
                );
            }
            let outcome = reconcile_roles(&ReconcileInput {
                desired_managed_roles: desired_managed_roles.clone(),
                last_synced_roles,
                current_nexus_roles,
            });

            if outcome.changed {
                info!(username, roles = ?outcome.new_roles, "updating Nexus user roles");
                nexus
                    .set_user_roles(&current, outcome.new_roles.into_iter().collect())
                    .await?;
            }
        }
    }

    manifest.set_synced(kc_realm, username, &desired_managed_roles);
    Ok(())
}

/// Keycloak usernames are operator-configured and, on at least one real
/// deployment observed, are already the user's full email address (not a
/// bare handle) — confirmed live: `FALLBACK_EMAIL_DOMAIN` blindly appended
/// to a username like `alice@example.com` produced `alice@example.com@cambium.invalid`,
/// which Nexus's `POST /v1/security/users` rejects outright
/// (`PARAMETER emailAddress: must be a well-formed email address`), so this
/// isn't a cosmetic issue — it silently failed every single user on a realm
/// where usernames are emails. If `username` already looks like an email
/// (contains exactly one `@` with non-empty text on both sides), use it
/// as-is; only synthesize `{username}@{fallback_email_domain}` for realms
/// where usernames are bare handles, matching the local dev stack's
/// `user-alpha-1`-style names.
fn resolve_email_address(username: &str, fallback_email_domain: &str) -> String {
    match username.split_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => username.to_string(),
        _ => format!("{username}@{fallback_email_domain}"),
    }
}

/// A placeholder Nexus local-account password, generated only because
/// `POST /v1/security/users` requires *some* value in the field. RutAuth is
/// the actual authentication path (see `ARCHITECTURE.md`) — this password is
/// never meant to authenticate anyone. It's still a credential that ends up
/// stored in Nexus's database, though, so it's drawn from a real CSPRNG
/// (`rand::rngs::OsRng` via `rand::thread_rng()`) rather than time+pid,
/// which would be guessable by anything that could observe roughly when
/// Cambium ran.
fn random_placeholder_password() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// Real-realm regression: confirmed live against a Keycloak realm where
    /// usernames are full emails — appending a fallback domain must not
    /// happen when the username is already a well-formed email.
    #[test]
    fn resolve_email_address_uses_username_as_is_when_already_an_email() {
        assert_eq!(
            resolve_email_address("alice@example.com", "cambium.invalid"),
            "alice@example.com"
        );
    }

    #[test]
    fn resolve_email_address_appends_fallback_domain_for_bare_usernames() {
        assert_eq!(
            resolve_email_address("user-alpha-1", "cambium.invalid"),
            "user-alpha-1@cambium.invalid"
        );
    }

    #[test]
    fn resolve_email_address_treats_leading_or_trailing_at_as_not_an_email() {
        // "@example.com" and "alice@" are not valid emails either way — fall
        // back rather than producing something equally malformed.
        assert_eq!(
            resolve_email_address("@example.com", "cambium.invalid"),
            "@example.com@cambium.invalid"
        );
        assert_eq!(
            resolve_email_address("alice@", "cambium.invalid"),
            "alice@@cambium.invalid"
        );
    }

    #[test]
    fn fresh_user_gets_exactly_what_keycloak_grants() {
        let outcome = reconcile_roles(&ReconcileInput {
            desired_managed_roles: set(&["nx-developer"]),
            last_synced_roles: set(&[]),
            current_nexus_roles: set(&[]),
        });
        assert_eq!(outcome.new_roles, set(&["nx-developer"]));
        assert!(outcome.changed);
    }

    #[test]
    fn no_op_when_nothing_changed() {
        let outcome = reconcile_roles(&ReconcileInput {
            desired_managed_roles: set(&["nx-developer"]),
            last_synced_roles: set(&["nx-developer"]),
            current_nexus_roles: set(&["nx-developer"]),
        });
        assert_eq!(outcome.new_roles, set(&["nx-developer"]));
        assert!(!outcome.changed);
    }

    /// The core clobber-avoidance case: an admin manually granted a role
    /// Cambium never touched. Reconciling with an unrelated Keycloak change
    /// must not remove it.
    #[test]
    fn foreign_role_is_preserved_across_a_reconcile() {
        let outcome = reconcile_roles(&ReconcileInput {
            desired_managed_roles: set(&["nx-developer"]),
            last_synced_roles: set(&["nx-developer"]),
            current_nexus_roles: set(&["nx-developer", "cambium-manual-role"]),
        });
        assert_eq!(
            outcome.new_roles,
            set(&["nx-developer", "cambium-manual-role"])
        );
        // roles array is unchanged in content but let's be precise: no
        // Nexus roles were dropped, and nothing new was added either.
        assert!(!outcome.changed);
    }

    #[test]
    fn foreign_role_survives_even_when_cambium_role_also_changes() {
        // Keycloak group membership moved this user from role A to role B.
        // A manually-added foreign role must still make it through.
        let outcome = reconcile_roles(&ReconcileInput {
            desired_managed_roles: set(&["nx-role-b"]),
            last_synced_roles: set(&["nx-role-a"]),
            current_nexus_roles: set(&["nx-role-a", "cambium-manual-role"]),
        });
        assert_eq!(
            outcome.new_roles,
            set(&["nx-role-b", "cambium-manual-role"])
        );
        assert!(outcome.changed);
    }

    #[test]
    fn cambium_managed_role_is_revoked_when_no_longer_justified() {
        let outcome = reconcile_roles(&ReconcileInput {
            desired_managed_roles: set(&[]),
            last_synced_roles: set(&["nx-developer"]),
            current_nexus_roles: set(&["nx-developer"]),
        });
        assert_eq!(outcome.new_roles, set(&[]));
        assert!(outcome.changed);
    }

    #[test]
    fn revocation_never_touches_a_foreign_role() {
        let outcome = reconcile_roles(&ReconcileInput {
            desired_managed_roles: set(&[]),
            last_synced_roles: set(&["nx-developer"]),
            current_nexus_roles: set(&["nx-developer", "cambium-manual-role"]),
        });
        assert_eq!(outcome.new_roles, set(&["cambium-manual-role"]));
        assert!(outcome.changed);
    }

    /// Manifest-loss failure mode from docs/sync-semantics.md: an empty
    /// `last_synced_roles` (missing/fresh manifest) must treat every
    /// existing Nexus role as foreign and preserve it, never mass-revoke.
    #[test]
    fn missing_manifest_preserves_all_existing_roles_and_only_adds() {
        let outcome = reconcile_roles(&ReconcileInput {
            desired_managed_roles: set(&["nx-new-role"]),
            last_synced_roles: set(&[]), // manifest lost / first run
            current_nexus_roles: set(&["nx-old-role-cambium-granted-before"]),
        });
        assert_eq!(
            outcome.new_roles,
            set(&["nx-new-role", "nx-old-role-cambium-granted-before"])
        );
        assert!(outcome.changed);
    }

    #[test]
    fn adding_and_removing_in_the_same_pass() {
        let outcome = reconcile_roles(&ReconcileInput {
            desired_managed_roles: set(&["nx-role-b", "nx-role-c"]),
            last_synced_roles: set(&["nx-role-a", "nx-role-b"]),
            current_nexus_roles: set(&["nx-role-a", "nx-role-b", "cambium-manual-role"]),
        });
        assert_eq!(
            outcome.new_roles,
            set(&["nx-role-b", "nx-role-c", "cambium-manual-role"])
        );
        assert!(outcome.changed);
    }

    #[test]
    fn map_to_nexus_roles_drops_unmapped_and_keeps_mapped() {
        let mut role_map = HashMap::new();
        role_map.insert("kc-developers".to_string(), "nx-developer".to_string());
        role_map.insert("kc-admins".to_string(), "nx-admin".to_string());

        let effective = set(&["kc-developers", "some-unrelated-realm-role"]);
        let mapped = map_to_nexus_roles(&effective, &role_map);
        assert_eq!(mapped, set(&["nx-developer"]));
    }

    #[test]
    fn map_to_nexus_roles_handles_empty_input() {
        let role_map = HashMap::new();
        let mapped = map_to_nexus_roles(&set(&[]), &role_map);
        assert!(mapped.is_empty());
    }

    fn kc_user(id: &str, username: &str) -> KcUser {
        KcUser {
            id: id.to_string(),
            username: username.to_string(),
            email: None,
            enabled: Some(true),
        }
    }

    fn kc_user_disabled(id: &str, username: &str) -> KcUser {
        KcUser {
            enabled: Some(false),
            ..kc_user(id, username)
        }
    }

    fn username_of(members: &HashMap<String, DiscoveredUser>, id: &str) -> Option<String> {
        members.get(id).map(|u| u.username.clone())
    }

    fn kc_group(id: &str, path: &str) -> KcGroup {
        KcGroup {
            id: id.to_string(),
            name: path.trim_start_matches('/').to_string(),
            path: path.to_string(),
        }
    }

    /// In-memory `GroupTreeSource` fake keyed by group id, so
    /// `discover_group_tree_members` can be exercised without a live
    /// Keycloak server — same style as `ropc`'s fake `TokenExchanger`.
    #[derive(Default)]
    struct FakeGroupTree {
        children: HashMap<String, Vec<KcGroup>>,
        members: HashMap<String, Vec<KcUser>>,
    }

    #[async_trait]
    impl GroupTreeSource for FakeGroupTree {
        async fn children(&self, group_id: &str) -> CambiumResult<Vec<KcGroup>> {
            Ok(self.children.get(group_id).cloned().unwrap_or_default())
        }

        async fn members(&self, group_id: &str) -> CambiumResult<Vec<KcUser>> {
            Ok(self.members.get(group_id).cloned().unwrap_or_default())
        }
    }

    /// The subgroup-discovery fix: a user who belongs only to a subgroup
    /// (never the parent directly) must still show up once the parent is
    /// walked recursively — this is exactly the `/team-gamma/team-gamma-leads`
    /// case from the dev stack (`dev/keycloak/realm-export.json`).
    #[tokio::test]
    async fn discover_group_tree_members_finds_a_user_in_a_direct_subgroup() {
        let mut tree = FakeGroupTree::default();
        tree.children.insert(
            "team-gamma".to_string(),
            vec![kc_group("team-gamma-leads", "/team-gamma/team-gamma-leads")],
        );
        tree.members.insert(
            "team-gamma-leads".to_string(),
            vec![kc_user("u1", "user-gamma-lead-1")],
        );

        let top_level = vec![kc_group("team-gamma", "/team-gamma")];
        let members = discover_group_tree_members(&tree, &top_level)
            .await
            .expect("traversal must not fail against a well-formed fake tree");

        assert_eq!(
            username_of(&members, "u1").as_deref(),
            Some("user-gamma-lead-1")
        );
    }

    /// Keycloak allows arbitrary nesting, not just one level of subgroups —
    /// this must keep walking past a grandchild.
    #[tokio::test]
    async fn discover_group_tree_members_walks_multiple_nesting_levels() {
        let mut tree = FakeGroupTree::default();
        tree.children.insert(
            "root".to_string(),
            vec![kc_group("child", "/root/child")],
        );
        tree.children.insert(
            "child".to_string(),
            vec![kc_group("grandchild", "/root/child/grandchild")],
        );
        tree.members.insert(
            "grandchild".to_string(),
            vec![kc_user("u1", "deeply-nested-user")],
        );

        let top_level = vec![kc_group("root", "/root")];
        let members = discover_group_tree_members(&tree, &top_level)
            .await
            .expect("traversal must not fail against a well-formed fake tree");

        assert_eq!(
            username_of(&members, "u1").as_deref(),
            Some("deeply-nested-user")
        );
    }

    /// A user in both a parent and one of its subgroups must be deduplicated
    /// to a single entry, same guarantee `merge_users` already gives the
    /// group/direct-role overlap case.
    #[tokio::test]
    async fn discover_group_tree_members_deduplicates_across_parent_and_subgroup() {
        let mut tree = FakeGroupTree::default();
        tree.children.insert(
            "parent".to_string(),
            vec![kc_group("child", "/parent/child")],
        );
        tree.members
            .insert("parent".to_string(), vec![kc_user("u1", "alice")]);
        tree.members
            .insert("child".to_string(), vec![kc_user("u1", "alice")]);

        let top_level = vec![kc_group("parent", "/parent")];
        let members = discover_group_tree_members(&tree, &top_level)
            .await
            .expect("traversal must not fail against a well-formed fake tree");

        assert_eq!(members.len(), 1);
        assert_eq!(username_of(&members, "u1").as_deref(), Some("alice"));
    }

    /// Defensive cycle guard: Keycloak shouldn't ever hand back a group that
    /// lists itself (or an ancestor) as a child, but the traversal must
    /// terminate instead of looping forever if it ever did.
    #[tokio::test]
    async fn discover_group_tree_members_terminates_on_a_self_referential_cycle() {
        let mut tree = FakeGroupTree::default();
        tree.children.insert(
            "cyclic".to_string(),
            vec![kc_group("cyclic", "/cyclic")],
        );
        tree.members
            .insert("cyclic".to_string(), vec![kc_user("u1", "alice")]);

        let top_level = vec![kc_group("cyclic", "/cyclic")];
        let members = discover_group_tree_members(&tree, &top_level)
            .await
            .expect("traversal must not fail against a well-formed fake tree");

        assert_eq!(members.len(), 1);
    }

    /// The direct-role-only discovery fix: a user found only via
    /// `users_with_direct_realm_role` (no group membership at all) must end
    /// up in the same discovery set `run_pass` reconciles, not a
    /// second-class one.
    #[test]
    fn merge_users_adds_a_user_with_no_group_membership() {
        let mut members = HashMap::new();
        merge_users(&mut members, vec![kc_user("g1", "alice")]);
        merge_users(&mut members, vec![kc_user("r1", "svc-example")]);

        assert_eq!(username_of(&members, "g1").as_deref(), Some("alice"));
        assert_eq!(username_of(&members, "r1").as_deref(), Some("svc-example"));
        assert_eq!(members.len(), 2);
    }

    /// A user who is both a group member *and* has a role assigned directly
    /// must be deduplicated to one entry, keyed by Keycloak user id — the
    /// two discovery sources are meant to overlap for most users, not
    /// double-process them.
    #[test]
    fn merge_users_deduplicates_overlap_between_group_and_direct_role_discovery() {
        let mut members = HashMap::new();
        merge_users(&mut members, vec![kc_user("u1", "bob")]);
        merge_users(&mut members, vec![kc_user("u1", "bob")]);

        assert_eq!(members.len(), 1);
        assert_eq!(username_of(&members, "u1").as_deref(), Some("bob"));
    }

    #[test]
    fn merge_users_handles_empty_batch() {
        let mut members: HashMap<String, DiscoveredUser> = HashMap::new();
        merge_users(&mut members, vec![]);
        assert!(members.is_empty());
    }

    /// The `enabled` flag has to survive discovery — it used to be parsed off
    /// the wire and then dropped here, which is what let a user disabled in
    /// Keycloak keep their Nexus roles indefinitely.
    #[test]
    fn merge_users_carries_the_disabled_flag_through_discovery() {
        let mut members = HashMap::new();
        merge_users(
            &mut members,
            vec![kc_user("u1", "alice"), kc_user_disabled("u2", "bob")],
        );

        assert!(members.get("u1").unwrap().enabled);
        assert!(!members.get("u2").unwrap().enabled);
    }

    /// A missing `enabled` field means enabled. Defaulting the other way
    /// would mass-revoke the entire realm the first time a Keycloak upgrade
    /// changed the response shape.
    #[test]
    fn merge_users_treats_a_missing_enabled_field_as_enabled() {
        let mut members = HashMap::new();
        merge_users(
            &mut members,
            vec![KcUser {
                enabled: None,
                ..kc_user("u1", "alice")
            }],
        );

        assert!(members.get("u1").unwrap().enabled);
    }

    /// The guard exists because RutAuth maps a header value straight onto a
    /// Nexus `userId`, so a Keycloak user named `admin` reaches Nexus's own
    /// built-in superuser. Cambium can't stop that, but it must not provision
    /// or re-role the account itself.
    #[test]
    fn reserved_usernames_are_matched_case_insensitively() {
        let reserved = crate::config::parse_reserved_usernames(
            crate::config::DEFAULT_RESERVED_USERNAMES,
        );

        assert!(is_reserved_username("admin", &reserved));
        assert!(is_reserved_username("Admin", &reserved));
        assert!(is_reserved_username("ADMIN", &reserved));
        assert!(is_reserved_username("anonymous", &reserved));
    }

    #[test]
    fn ordinary_usernames_are_not_reserved() {
        let reserved = crate::config::parse_reserved_usernames(
            crate::config::DEFAULT_RESERVED_USERNAMES,
        );

        assert!(!is_reserved_username("alice", &reserved));
        // Substring of a reserved name, not a match.
        assert!(!is_reserved_username("admin-tools", &reserved));
        assert!(!is_reserved_username("alice@example.com", &reserved));
    }

    /// An empty `RESERVED_USERNAMES` is a deliberate opt-out, not a default
    /// that silently protects nothing.
    #[test]
    fn an_empty_reserved_set_matches_nothing() {
        let reserved = crate::config::parse_reserved_usernames("");
        assert!(!is_reserved_username("admin", &reserved));
    }

    /// The revocation half of the disabled-user fix: resolving a disabled
    /// user to an empty desired set must remove exactly what Cambium granted
    /// and leave a manually-assigned role untouched, same contract as every
    /// other path.
    #[test]
    fn disabled_user_resolves_to_revoking_only_cambium_granted_roles() {
        let outcome = reconcile_roles(&ReconcileInput {
            desired_managed_roles: HashSet::new(),
            last_synced_roles: ["nx-developer".to_string()].into(),
            current_nexus_roles: ["nx-developer".to_string(), "nx-manual".to_string()].into(),
        });

        assert!(outcome.changed);
        assert_eq!(outcome.new_roles, ["nx-manual".to_string()].into());
    }

    /// Regression test for the "batch dies mid-loop" bug: `run_pass` used to
    /// call `manifest.save()` exactly once, after every user in the batch
    /// had been processed. If the process crashed between user N and the
    /// final save, every grant Cambium had already applied to Nexus since
    /// the last save was never recorded — on the next pass those roles
    /// would look "foreign" (no manifest record), so Cambium could never
    /// prove it granted them and could never auto-revoke them again, even
    /// after real Keycloak access was removed. That's the exact guarantee
    /// docs/sync-semantics.md promises ("Cambium does revoke... stale
    /// grants are themselves a security problem").
    ///
    /// The fix (now in `run_pass`) persists the manifest after *each* user,
    /// not once at the end. This test models that per-user save/crash
    /// sequence directly against `Manifest` + `reconcile_roles` (the two
    /// pieces `run_pass` actually calls), without needing to mock the
    /// Keycloak/Nexus HTTP clients themselves.
    #[test]
    fn crash_after_user_n_before_final_save_does_not_lose_track_of_granted_roles() {
        use crate::manifest::Manifest;

        let dir = std::env::temp_dir().join(format!(
            "cambium-sync-crash-test-{}-{}",
            std::process::id(),
            "crash_after_user_n"
        ));
        let state_file = dir.join("state.json");
        let _ = std::fs::remove_dir_all(&dir);

        let mut manifest = Manifest::load(&state_file).expect("fresh manifest load");

        // --- pass 1, user "alice": processed and saved (the fixed behavior) ---
        let alice_desired = set(&["nx-dev"]);
        let alice_outcome = reconcile_roles(&ReconcileInput {
            desired_managed_roles: alice_desired.clone(),
            last_synced_roles: manifest.last_synced("realm", "alice"),
            current_nexus_roles: set(&[]),
        });
        assert!(alice_outcome.changed);
        // (this stands in for the real `nexus.create_user`/`set_user_roles`
        // call in `sync_one_user`, which by this point in the real flow has
        // already succeeded against Nexus)
        manifest.set_synced("realm", "alice", &alice_desired);
        manifest
            .save(&state_file)
            .expect("save after alice must succeed — this is the fix");

        // --- "crash" simulated here: the process dies before "bob" (the
        // next user in the batch) is processed or saved at all. We drop the
        // in-memory manifest and reload from disk exactly like a restarted
        // process would. ---
        drop(manifest);
        let manifest_after_crash = Manifest::load(&state_file).expect("reload after crash");

        // alice's grant survived the crash even though the batch never
        // reached bob.
        assert_eq!(
            manifest_after_crash.last_synced("realm", "alice"),
            alice_desired,
            "alice's grant must be durable even though the batch crashed before finishing"
        );
        // bob was never reached, so there's nothing to lose for him — that's
        // "not yet synced", not "corrupted"; the next full pass simply
        // processes him like any first-run user.
        assert!(manifest_after_crash.last_synced("realm", "bob").is_empty());

        // --- pass 2 (post-restart): alice's Keycloak access has since been
        // revoked. Nexus still shows the role granted before the crash. ---
        let mut manifest2 = manifest_after_crash;
        let alice_revoke_outcome = reconcile_roles(&ReconcileInput {
            desired_managed_roles: set(&[]),
            last_synced_roles: manifest2.last_synced("realm", "alice"),
            current_nexus_roles: set(&["nx-dev"]),
        });

        // Because the manifest recorded alice's grant durably before the
        // crash, Cambium can still prove it granted nx-dev and safely
        // revoke it now — the exact property that would have been lost if
        // the save had only happened once at the end of the whole batch.
        assert!(alice_revoke_outcome.changed);
        assert_eq!(alice_revoke_outcome.new_roles, set(&[]));

        manifest2.set_synced("realm", "alice", &set(&[]));
        manifest2
            .save(&state_file)
            .expect("save after revoking alice must succeed");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
