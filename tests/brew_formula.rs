// SPDX-License-Identifier: Apache-2.0
//
//! The brew formula against the release it names.
//!
//! The formula is release data: the URLs name the macOS archives Homebrew
//! downloads and the digests under them are the digests of the files those
//! URLs fetch. `scripts/push-github.sh` rewrites all five of those lines --
//! the two URLs, the two digests and the version -- when it publishes the
//! archives, and it rewrites them with an `awk` that prints the lines it
//! does not recognise as it found them.
//!
//! That is the shape of a silent half-rewrite. A formula whose version
//! moved and whose URLs did not installs the release before this one; a
//! formula whose digest did not move refuses its own archive with
//! "SHA256 mismatch" at the user's machine and not here. Nothing held the
//! five lines to each other, so the rewrite could half-apply without a
//! word -- and the formula is the one file a user runs on a machine that
//! is not this one.
//!
//! The check is internal on purpose. The formula names the release it
//! installs, and that release is the one the last publish made -- so
//! between the version bump in `Cargo.toml` and the publish that follows
//! it, the formula is a version behind and still right. Comparing it with
//! `Cargo.toml` would fail the gate of the release that is about to fix
//! it.
//!
//! The digest of a published archive is not checked here: that is the
//! archive's own, and the archive is built by the CI on the tag. What is
//! checked is that the digest under a URL is a digest and not a
//! placeholder, and that the URL, the digest and the version all name
//! the same release.

use std::path::Path;

fn formula() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Formula/rgx.rb");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("Formula/rgx.rb is there: {e}"))
}

/// The values of the `key "value"` lines of the formula.
fn fields(text: &str, key: &str) -> Vec<String> {
    let prefix = format!("{key} \"");
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix(prefix.as_str()) else {
            continue;
        };
        let Some(end) = rest.find('"') else {
            continue;
        };
        out.push(rest[..end].to_string());
    }
    out
}

#[test]
fn the_formula_names_one_release_and_the_digests_of_it() {
    let text = formula();

    let versions = fields(&text, "version");
    assert_eq!(
        versions.len(),
        1,
        "the formula names one version: {versions:?}"
    );
    let tag = format!("rgx-v{}", versions[0]);

    let urls = fields(&text, "url");
    assert_eq!(
        urls.len(),
        2,
        "the formula names one archive per architecture: {urls:?}"
    );
    for url in &urls {
        assert!(
            url.starts_with(&format!(
                "https://github.com/danalec/rgx/releases/download/{tag}/"
            )),
            "the url {url} does not name the release the formula declares ({tag})"
        );
    }
    assert!(
        urls.iter().any(|u| u.ends_with("-aarch64-macos.tar.gz")),
        "the formula names no archive for Apple Silicon: {urls:?}"
    );
    assert!(
        urls.iter().any(|u| u.ends_with("-x86_64-macos.tar.gz")),
        "the formula names no archive for Intel: {urls:?}"
    );

    let digests = fields(&text, "sha256");
    assert_eq!(
        digests.len(),
        2,
        "the formula carries one digest per archive: {digests:?}"
    );
    for digest in &digests {
        assert_eq!(digest.len(), 64, "the digest {digest} is not a sha256");
        assert!(
            digest
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "the digest {digest} is not lowercase hex"
        );
        // Sixty-four zeros are the shape of a digest and are not one: that
        // is what a formula is written with before its release exists.
        assert!(
            !digest.chars().all(|c| c == '0'),
            "the digest {digest} is a placeholder and not the digest of a file"
        );
    }
}
