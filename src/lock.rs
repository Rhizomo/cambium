//! Single-instance enforcement.
//!
//! Cambium's manifest (`src/manifest.rs`) is a plain JSON file with no
//! internal locking or transactional guarantees — it's read fully, mutated
//! in memory, and rewritten fully. Two Cambium processes (two replicas, or
//! an overlapping slow pass) racing on reads/writes to the same file would
//! silently corrupt state: a lost update could make a granted role
//! permanently "invisible" to the manifest (same failure mode as the
//! mid-batch crash bug, just self-inflicted and continuous instead of a
//! one-time event).
//!
//! v1 is explicitly single-instance-only (see `docs/sync-semantics.md` and
//! `README.md`). This module makes that a hard failure instead of a
//! documentation-only promise: on startup, Cambium takes an exclusive
//! `flock` on a dedicated lock file and holds it for the lifetime of the
//! process. A second instance pointed at the same lock file fails fast and
//! loudly at startup rather than silently corrupting the manifest.

use std::fs::{File, OpenOptions};
use std::path::Path;

use fs2::FileExt;

/// Holds the OS-level exclusive lock for as long as this guard is alive.
/// The lock is released automatically when the `File` is dropped (process
/// exit, including a crash, releases it too — this is `flock`, not a
/// pidfile that can go stale).
pub struct SingletonGuard {
    _file: File,
}

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("could not open/create lock file {path}: {source}")]
    Open {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "another Cambium instance already holds the lock at {path} — \
         Cambium v1 must run as exactly one instance against a given manifest \
         (see docs/sync-semantics.md); refusing to start a second one"
    )]
    AlreadyLocked { path: String },
}

pub fn acquire(lock_file: &Path) -> Result<SingletonGuard, LockError> {
    if let Some(parent) = lock_file.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        // Explicitly not truncating: this file's only purpose is to be an
        // flock target, its contents (there are none) don't matter, but an
        // implicit choice here is exactly the kind of thing worth pinning
        // down rather than leaving to the platform default.
        .truncate(false)
        .open(lock_file)
        .map_err(|e| LockError::Open {
            path: lock_file.display().to_string(),
            source: e,
        })?;

    file.try_lock_exclusive().map_err(|_| LockError::AlreadyLocked {
        path: lock_file.display().to_string(),
    })?;

    Ok(SingletonGuard { _file: file })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_acquire_on_the_same_path_fails_fast() {
        let dir = std::env::temp_dir().join(format!(
            "cambium-lock-test-{}-{}",
            std::process::id(),
            "second_acquire_fails"
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let lock_path = dir.join("cambium.lock");

        let first = acquire(&lock_path).expect("first acquire should succeed");
        let second = acquire(&lock_path);

        assert!(
            matches!(second, Err(LockError::AlreadyLocked { .. })),
            "a second instance must fail fast instead of silently racing on the manifest"
        );

        drop(first);
        // Releasing the first lock must let a subsequent instance in.
        let third = acquire(&lock_path);
        assert!(third.is_ok(), "lock must be released when the guard is dropped");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
