// SPDX-License-Identifier: Apache-2.0
//
//! The winget manifests against the release they name.
//!
//! The manifests are release data: the version, the URL of the archive the
//! installer downloads, the digest under it, the date of the release and the
//! path of the executable inside the archive all name one release, and the
//! path inside the archive is the one the two builders of that archive do
//! not agree on -- `build-release.ps1` packs the contents and
//! `release-all.sh` packs the directory, and the published asset is the
//! directory.
//!
//! That is the shape of a silent half-rewrite. The publisher rewrites the
//! version, the URL, the digest and the date with a `sed` that matches a
//! line that begins with the key, and the path inside the archive is a list
//! item -- "  - RelativeFilePath: ..." -- so the pattern that matched the
//! other four did not match it: the path kept the number of the release
//! before, and a manifest that names a file the archive does not hold
//! installs nothing and says nothing about why.
//!
//! The check is internal on purpose. The manifests name the release they
//! install, and that release is the one the last publish made -- so between
//! the version bump in `Cargo.toml` and the publish that follows it, the
//! manifests are a version behind and still right. Comparing them with
//! `Cargo.toml` would fail the gate of the release that is about to fix
//! them.
//!
//! The digest of a published archive is not checked here: that is the
//! archive's own, and the archive is built by the release. What is checked
//! is that every field names the same release, and that the path inside
//! the archive is the path the published archive holds.

use std::path::Path;

fn manifest(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".winget")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!(".winget/{name} is there: {e}"))
}

/// The value of a `key: value` line.
///
/// A list item is a line that begins with a dash, and the key of a list
/// item is the key after the dash: the path inside the archive is one, and
/// a field that only read the lines that begin with the key would not see
/// it.
fn field(text: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}: ");
    for line in text.lines() {
        let trimmed = line.trim();
        let trimmed = trimmed.strip_prefix("- ").unwrap_or(trimmed);
        if let Some(rest) = trimmed.strip_prefix(prefix.as_str()) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

#[test]
fn the_manifests_name_one_release_and_the_path_inside_its_archive() {
    let version_manifest = manifest("danalec.rgx.yaml");
    let installer = manifest("danalec.rgx.installer.yaml");
    let locale = manifest("danalec.rgx.locale.en-US.yaml");

    let version =
        field(&version_manifest, "PackageVersion").expect("the version manifest names a version");
    assert_eq!(
        field(&installer, "PackageVersion").as_deref(),
        Some(version.as_str()),
        "the installer names another version than the version manifest: {version}"
    );
    assert_eq!(
        field(&locale, "PackageVersion").as_deref(),
        Some(version.as_str()),
        "the locale names another version than the version manifest: {version}"
    );

    let tag = format!("rgx-v{version}");

    // The path of the executable inside the archive. It is the path the
    // published archive holds, and the archive holds a directory named
    // after it -- so the path is the directory and the executable in it.
    let path = field(&installer, "RelativeFilePath")
        .expect("the installer names the file inside the archive");
    assert_eq!(
        path,
        format!("{tag}-x86_64-windows/rgx.exe"),
        "the installer names {path}, which is not the path the archive {tag}-x86_64-windows.zip holds"
    );

    // The URL of the archive. The host is the one the publish named -- the
    // forgejo while the release is being cut, the GitHub mirror after it
    // -- so what is held here is the release the URL names.
    let url = field(&installer, "InstallerUrl").expect("the installer names the archive");
    assert!(
        url.ends_with(&format!("releases/download/{tag}/{tag}-x86_64-windows.zip")),
        "the installer downloads {url}, which is not the archive of {tag}"
    );

    let notes = field(&locale, "ReleaseNotesUrl").expect("the locale names the release notes");
    assert!(
        notes.ends_with(&format!("releases/tag/{tag}")),
        "the locale names the release notes at {notes}, which is not the release {tag}"
    );
}
