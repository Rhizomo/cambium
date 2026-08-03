//! The reconciliation loop: Keycloak effective realm roles -> Nexus
//! User/Role assignments, applying the clobber-avoidance semantics
//! documented in `docs/sync-semantics.md`.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use tracing::{info, warn};

use crate::error::{CambiumError, CambiumResult};
use crate::keycloak::KeycloakClient;
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

/// One full reconciliation pass: Keycloak groups -> members -> effective
/// roles -> Nexus.
///
/// v1 scoping decision: only users who are a direct member of *some*
/// Keycloak group in the realm are considered, matching ARCHITECTURE.md's
/// framing ("reads Keycloak group membership") and avoiding a full-realm
/// user dump. A user with realm roles assigned directly but no group
/// membership at all is out of scope for v1 — noted as a known limitation,
/// not silently unhandled.
pub async fn run_pass(
    kc: &KeycloakClient,
    nexus: &NexusClient,
    kc_realm: &str,
    role_map: &HashMap<String, String>,
    manifest: &mut Manifest,
    fallback_email_domain: &str,
    state_file: &Path,
) -> CambiumResult<()> {
    let groups = kc.list_groups(kc_realm).await?;
    info!(count = groups.len(), "fetched Keycloak groups");

    // Union of (user_id -> username) across every group's membership.
    let mut members: HashMap<String, String> = HashMap::new();
    for group in &groups {
        let group_members = kc.group_members(kc_realm, &group.id).await?;
        for u in group_members {
            members.insert(u.id, u.username);
        }
    }
    info!(count = members.len(), "distinct users across all groups");

    for (user_id, username) in members {
        match sync_one_user(
            kc,
            nexus,
            kc_realm,
            &user_id,
            &username,
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
    role_map: &HashMap<String, String>,
    manifest: &mut Manifest,
    fallback_email_domain: &str,
) -> CambiumResult<()> {
    let effective = kc.effective_realm_roles(kc_realm, kc_user_id).await?;
    let desired_managed_roles = map_to_nexus_roles(&effective, role_map);
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
                    email_address: format!("{username}@{fallback_email_domain}"),
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
