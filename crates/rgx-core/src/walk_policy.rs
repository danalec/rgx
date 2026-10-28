// SPDX-License-Identifier: Apache-2.0

//! What the walk leaves out whatever the hidden-file policy says.
//!
//! **A repository's own state is not part of the corpus.** The hidden
//! files are read by default -- a format that keeps its metadata in a
//! dotfile (a Zarr array's `.zarray`, a `.zattrs`, a `.gitignore`) is
//! invisible otherwise -- but a version-control system's state directory
//! is not a hidden file in that sense. It is a directory of compressed
//! objects and a binary index, it is routinely larger than the working
//! tree it describes, and nothing in it is content anybody meant to
//! search.
//!
//! **The rule is a directory rule.** A `.gitignore` is a file, and the
//! hidden-file policy governs it like any other file: it is read, and
//! the rules in it are applied -- including the ones in
//! `.git/info/exclude`, which is read as a rule file even though the
//! directory holding it is skipped. Only the directory that holds the
//! repository's state is skipped, and only when it is a directory: a
//! `.git` *file* is what a worktree or a submodule has instead of the
//! directory, and that one is a small pointer worth reading.

/// The directories a version-control system keeps its own state in.
///
/// Git, Mercurial, Subversion and Jujutsu each keep one, and each is
/// named the way the tool names it.
pub fn is_vcs_dir(name: &str) -> bool {
    matches!(name, ".git" | ".hg" | ".svn" | ".jj")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_directories_are_the_ones_the_tools_name() {
        for name in [".git", ".hg", ".svn", ".jj"] {
            assert!(is_vcs_dir(name), "{name}");
        }
    }

    #[test]
    fn a_dotfile_that_is_not_a_state_directory_is_not_one() {
        // The `.gitignore` is a file, and it is governed by the
        // hidden-file policy: naming it here would take the rules out of
        // every repository.
        for name in [".gitignore", ".gitmodules", ".gitattributes", ".jjignore"] {
            assert!(!is_vcs_dir(name), "{name}");
        }
    }

    #[test]
    fn an_ordinary_name_is_not_a_state_directory() {
        for name in ["git", "gitignore", "a.git", ".github", "sub.git"] {
            assert!(!is_vcs_dir(name), "{name}");
        }
    }
}
