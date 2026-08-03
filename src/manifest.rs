//! Cambium's own sync manifest: a record of which Nexus role IDs Cambium
//! itself granted to each user on the last successful reconciliation pass.
//!
//! This is the mechanism `docs/sync-semantics.md` (question 3) settles on
//! for avoiding clobbering roles a Nexus admin assigned by hand: Nexus's
//! REST API only exposes a whole-array replace for a user's `roles`, so the
//! only way to know which entries in that array are "ours" to remove is to
//! remember what we put there ourselves, rather than re-deriving it from
//! Nexus's live state (which can't distinguish provenance) or from a naming
//! convention (which doesn't work for reuse of pre-existing Nexus roles
//! like `nx-admin`).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{CambiumError, CambiumResult};

/// Keyed by `"{realm}/{username}"` rather than bare username, so the shape
/// survives a future move to multi-realm support without a migration (see
/// ARCHITECTURE.md's "multi-realm" open question).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Manifest {
    entries: HashMap<String, BTreeSet<String>>,
}

fn key(realm: &str, username: &str) -> String {
    format!("{realm}/{username}")
}

impl Manifest {
    pub fn load(path: &Path) -> CambiumResult<Self> {
        match std::fs::read_to_string(path) {
            Ok(contents) => Ok(serde_json::from_str(&contents)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(CambiumError::ManifestIo {
                path: path.display().to_string(),
                source: e,
            }),
        }
    }

    pub fn save(&self, path: &Path) -> CambiumResult<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| CambiumError::ManifestIo {
                    path: path.display().to_string(),
                    source: e,
                })?;
            }
        }
        let contents = serde_json::to_string_pretty(self)?;
        std::fs::write(path, contents).map_err(|e| CambiumError::ManifestIo {
            path: path.display().to_string(),
            source: e,
        })
    }

    /// What Cambium itself granted this user last time. Empty (not an
    /// error) if there's no prior record — see `docs/sync-semantics.md`'s
    /// "first-run / manifest-loss failure mode" for why that's the safe
    /// direction to fail in.
    pub fn last_synced(&self, realm: &str, username: &str) -> HashSet<String> {
        self.entries
            .get(&key(realm, username))
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn set_synced(&mut self, realm: &str, username: &str, roles: &HashSet<String>) {
        self.entries
            .insert(key(realm, username), roles.iter().cloned().collect());
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_manifest_yields_empty_last_synced() {
        let m = Manifest::default();
        assert!(m.last_synced("myrealm", "alice").is_empty());
    }

    #[test]
    fn set_then_get_round_trips() {
        let mut m = Manifest::default();
        let roles: HashSet<String> = ["nx-developer".to_string(), "nx-admin".to_string()].into();
        m.set_synced("myrealm", "alice", &roles);
        assert_eq!(m.last_synced("myrealm", "alice"), roles);
        // A different realm/user is unaffected.
        assert!(m.last_synced("myrealm", "bob").is_empty());
        assert!(m.last_synced("otherrealm", "alice").is_empty());
    }

    #[test]
    fn save_and_load_round_trip_via_tempfile() {
        let mut m = Manifest::default();
        let roles: HashSet<String> = ["nx-developer".to_string()].into();
        m.set_synced("myrealm", "alice", &roles);

        let dir = std::env::temp_dir().join(format!("cambium-manifest-test-{}", std::process::id()));
        let path = dir.join("state.json");
        m.save(&path).expect("save should succeed, creating parent dirs");

        let loaded = Manifest::load(&path).expect("load should succeed");
        assert_eq!(loaded.last_synced("myrealm", "alice"), roles);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
