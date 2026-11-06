// SPDX-License-Identifier: Apache-2.0

//! Every crate README must say what the crate actually claims.
//!
//! A README that lists an extension no adapter claims is a promise the
//! binary cannot keep: the reader follows the table, types the extension,
//! and gets the raw passthrough. A README that omits one hides a format
//! the user can search today. Both directions are drift, and drift is
//! silent -- nothing in the build notices a table that stopped matching
//! the code.
//!
//! So the table is compared with the registry the adapter crates expose,
//! **in the same order**: the order is the contract, because the registry
//! resolves by extension and the first available adapter wins. A row moved
//! to the bottom is not a cosmetic change, it is a different chain.
//!
//! The comparison is against `crate::adapters()`, not against a list
//! written here: a copy of the list in the test would drift exactly the
//! way the README does, and two wrong copies agreeing would look like a
//! pass.
//!
//! Sections that are prose rather than a table -- the PDF crate documents
//! one adapter and the internals of the format -- are checked the only
//! way that makes sense for them: every adapter of the crate must be
//! named in the section.

use std::path::PathBuf;

/// One row of a claim table: the adapter's name and the extensions it
/// claims, in registry order.
type Row = (String, Vec<String>);

/// The claim table of a crate README, or the prose that replaces it.
fn claims_section(readme: &str) -> &str {
    let start = readme
        .find("## What it claims")
        .expect("the README has no '## What it claims' section");
    let rest = &readme[start..];
    // the section ends at the next level-2 heading
    match rest[3..].find("\n## ") {
        Some(i) => &rest[..i + 3],
        None => rest,
    }
}

/// Strips the markdown decoration a table cell carries.
fn undecorate(cell: &str) -> &str {
    cell.trim().trim_matches('`').trim()
}

/// Expands the one shorthand the tables use: `1–9` stands for the nine
/// single-digit extensions `markup` claims one by one. The dash is the
/// en dash, not the hyphen, so an extension that really contains a
/// hyphen is never mistaken for a range.
fn expand(cell: &str) -> Vec<String> {
    let cell = undecorate(cell);
    if let Some((lo, hi)) = cell.split_once('\u{2013}') {
        if let (Ok(lo), Ok(hi)) = (lo.parse::<u32>(), hi.parse::<u32>()) {
            return (lo..=hi).map(|n| n.to_string()).collect();
        }
    }
    vec![cell.to_string()]
}

/// The rows of the first table in a section, in the order they appear.
fn parse_table(section: &str) -> Vec<Row> {
    let mut rows = Vec::new();
    for line in section.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() < 2 {
            continue;
        }
        // the header row and the `|---|---|` separator are not claims
        if cells[0] == "adapter" {
            continue;
        }
        if cells.iter().all(|c| c.trim_start_matches('-').is_empty()) {
            continue;
        }
        let name = undecorate(cells[0]).to_string();
        // the em dash is the claim itself: the adapter claims no extension
        // and is reached by its magic, not by its name.
        let cell = undecorate(cells[1]);
        let extensions = if cell == "\u{2014}" {
            Vec::new()
        } else {
            cell.split(',')
                .flat_map(expand)
                .filter(|e| !e.is_empty())
                .collect()
        };
        rows.push((name, extensions));
    }
    rows
}

/// The registry of a crate, as rows: the adapter's name and the
/// extensions it claims, in registration order.
macro_rules! registry {
    ($adapters:expr) => {
        $adapters
            .iter()
            .map(|a| {
                (
                    a.name().to_string(),
                    a.extensions().iter().map(|e| e.to_string()).collect(),
                )
            })
            .collect::<Vec<_>>()
    };
}

/// Compares a crate's README with the crate's registry.
fn check(crate_name: &str, registry: Vec<Row>) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("crates")
        .join(crate_name)
        .join("README.md");
    let readme =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let section = claims_section(&readme);
    let table = parse_table(section);
    if table.is_empty() {
        // a prose section: every adapter must be named in it
        for (name, _) in &registry {
            assert!(
                section.contains(name.as_str()),
                "{crate_name}: the README's claim section does not mention the adapter \
                 `{name}`"
            );
        }
        return;
    }
    assert_eq!(
        table, registry,
        "{crate_name}: the README's claim table does not match the registry. The order \
         matters as much as the contents: the registry resolves by extension and the first \
         available adapter wins."
    );
}

#[test]
#[cfg(feature = "adapters-archive")]
fn the_archive_readme_claims_what_the_archive_crate_claims() {
    check(
        "rgx-adapters-archive",
        registry!(rgx_adapters_archive::adapters()),
    );
}

#[test]
#[cfg(feature = "adapters-office")]
fn the_office_readme_claims_what_the_office_crate_claims() {
    check(
        "rgx-adapters-office",
        registry!(rgx_adapters_office::adapters()),
    );
}

#[test]
#[cfg(feature = "adapters-threed")]
fn the_threed_readme_claims_what_the_threed_crate_claims() {
    check(
        "rgx-adapters-threed",
        registry!(rgx_adapters_threed::adapters()),
    );
}

#[test]
#[cfg(feature = "adapters-llm")]
fn the_llm_readme_claims_what_the_llm_crate_claims() {
    check("rgx-adapters-llm", registry!(rgx_adapters_llm::adapters()));
}

#[test]
#[cfg(feature = "adapters-media")]
fn the_media_readme_claims_what_the_media_crate_claims() {
    check(
        "rgx-adapters-media",
        registry!(rgx_adapters_media::adapters()),
    );
}

#[test]
#[cfg(feature = "adapters-tabular")]
fn the_tabular_readme_claims_what_the_tabular_crate_claims() {
    check(
        "rgx-adapters-tabular",
        registry!(rgx_adapters_tabular::adapters()),
    );
}

#[test]
#[cfg(feature = "adapters-docs")]
fn the_docs_readme_claims_what_the_docs_crate_claims() {
    check(
        "rgx-adapters-docs",
        registry!(rgx_adapters_docs::adapters()),
    );
}

#[test]
#[cfg(feature = "adapters-mail")]
fn the_mail_readme_claims_what_the_mail_crate_claims() {
    check(
        "rgx-adapters-mail",
        registry!(rgx_adapters_mail::adapters()),
    );
}

#[test]
#[cfg(feature = "adapters-inspect")]
fn the_inspect_readme_claims_what_the_inspect_crate_claims() {
    check(
        "rgx-adapters-inspect",
        registry!(rgx_adapters_inspect::adapters()),
    );
}

#[test]
#[cfg(feature = "adapters-pdf")]
fn the_pdf_readme_claims_what_the_pdf_crate_claims() {
    check("rgx-adapters-pdf", registry!(rgx_adapters_pdf::adapters()));
}
