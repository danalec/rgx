// SPDX-License-Identifier: Apache-2.0

//! The temporary directory the tests write into.
//!
//! Every integration test needs a tree of its own, and the *name* of that
//! tree is load-bearing: two tests that agree on a name agree on a
//! directory, and then one of them reads the other's file, or deletes the
//! tree the other was searching.
//!
//! **The name carries a counter, and not the clock.** The old name was the
//! process id and the wall clock in nanoseconds, and two tests that asked
//! for a directory inside the same tick got the *same* path: the CI's
//! windows job read a file the test had not written, and the CJK test found
//! the needle it was told must not be found, because the message it read
//! was the other test's, which declared a charset.
//!
//! The counter makes the name unique inside the process, and `create_dir`
//! makes the directory one this run created: a name that is taken is not
//! reused, it is moved past. `create_dir_all` would be wrong here -- it
//! reuses a directory that is already there, silently, and a directory
//! left behind by a killed run would be adopted as if it were fresh.
//!
//! **This rule lives in one place because it used to live in nineteen.**
//! The house had already fixed it in `tests/cache.rs` and never carried
//! the fix to the others, and the copy that drifted is the copy that
//! breaks.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// A temporary directory of this run's own making.
///
/// The tag names the caller, so two test binaries never write into the
/// same tree even when the operating system hands them the same process
/// id at the same time.
pub fn scratch(tag: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let base = std::env::temp_dir();
    for _ in 0..4096 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = base.join(format!("rgx-{tag}-{}-{n}", std::process::id()));
        match std::fs::create_dir(&dir) {
            Ok(()) => return dir,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("cannot create {}: {e}", dir.display()),
        }
    }
    panic!("no free temporary directory name for {tag}");
}
