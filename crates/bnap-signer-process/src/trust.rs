//! Who can change what a socket path leads to.
//!
//! A Unix socket is found by its path, so whoever can write the socket's
//! directory can put their own socket there: remove the real one (or wait
//! until the signer is down and the path is free) and listen in its place.
//! A sticky directory such as `/tmp` does not help, since the path is free
//! whenever the signer is not running. Both sides therefore require a
//! directory that neither the group nor others can write, owned by root or
//! by a user they trust; the client also checks who serves the socket it
//! reached ([`crate::ProcessSigner::with_signer_uid`]).

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The directory a socket at `path` lives in: `.` for a bare file name.
pub(crate) fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_owned(),
        _ => PathBuf::from("."),
    }
}

/// A directory's permission bits and owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirInfo {
    /// The permission bits, sticky bit included (`mode & 0o7777`).
    pub(crate) mode: u32,
    /// The owner's user ID.
    pub(crate) owner: u32,
}

impl DirInfo {
    /// Reads `dir`'s metadata, following a symbolic link to the directory
    /// it names.
    pub(crate) fn of(dir: &Path) -> std::io::Result<Self> {
        let m = std::fs::metadata(dir)?;
        Ok(Self {
            mode: m.permissions().mode() & 0o7777,
            owner: m.uid(),
        })
    }

    /// The group or others may create, remove or rename entries. The
    /// sticky bit does not change the answer: it stops others removing the
    /// signer's socket, not binding the path while it is free.
    pub(crate) fn writable_by_others(self) -> bool {
        self.mode & 0o022 != 0
    }

    /// Root or one of `trusted` owns it.
    pub(crate) fn owned_by(self, trusted: &[u32]) -> bool {
        self.owner == 0 || trusted.contains(&self.owner)
    }
}

/// Whether the signer serves a connection whose peer runs as `uid`: the
/// socket's `owner` (the signer's own user) or one of `allowed`. Root is not
/// admitted unless it is listed. The file mode of the socket only decides
/// who can reach it; this is the access control.
pub(crate) fn peer_allowed(uid: u32, owner: u32, allowed: &[u32]) -> bool {
    uid == owner || allowed.contains(&uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_or_other_write_is_unsafe_with_or_without_the_sticky_bit() {
        for mode in [0o1777, 0o1770, 0o1702, 0o777, 0o770, 0o720, 0o702] {
            assert!(DirInfo { mode, owner: 1 }.writable_by_others(), "{mode:o}");
        }
        for mode in [0o700, 0o750, 0o755, 0o711, 0o1755, 0o500] {
            assert!(!DirInfo { mode, owner: 1 }.writable_by_others(), "{mode:o}");
        }
    }

    #[test]
    fn only_root_and_trusted_users_may_own_it() {
        let d = |owner| DirInfo { mode: 0o700, owner };
        assert!(d(0).owned_by(&[]));
        assert!(d(7).owned_by(&[3, 7]));
        assert!(!d(8).owned_by(&[3, 7]));
        assert!(!d(8).owned_by(&[]));
    }

    #[test]
    fn only_the_owner_and_allowed_users_are_served() {
        assert!(peer_allowed(501, 501, &[]));
        assert!(peer_allowed(502, 501, &[502, 503]));
        assert!(peer_allowed(503, 501, &[502, 503]));
        assert!(!peer_allowed(504, 501, &[502, 503]));
        assert!(!peer_allowed(502, 501, &[]));
        assert!(
            !peer_allowed(0, 501, &[]),
            "root is not admitted unless listed"
        );
        assert!(peer_allowed(0, 501, &[0]));
    }

    #[test]
    fn reads_a_real_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o1750)).unwrap();
        let info = DirInfo::of(dir.path()).unwrap();
        assert_eq!(info.mode, 0o1750);
        assert_eq!(parent_dir(Path::new("s.sock")), PathBuf::from("."));
        assert_eq!(parent_dir(&dir.path().join("s.sock")), dir.path());
    }
}
