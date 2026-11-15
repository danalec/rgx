// SPDX-License-Identifier: Apache-2.0

//! Empirical panic sweep over the FULL registry, driven by real fixtures.
//!
//! The point is cross-feeding: a real `.dif`, `.wk4` or `.mdb` is offered to
//! EVERY claiming adapter, not only the one its extension names. A parser that
//! trusts its own magic still has to survive the other 180-odd extensions'
//! bytes, and a bounds check that only fires on its real header never fires at
//! all if the only corpus is that header.
//!
//! `rgx_core::fuzzkit::assert_never_panics` stops at the first panic. This
//! sweep collects them all, so one run reports the whole shape of the problem.
//!
//! Panics are caught with `catch_unwind` and reported, never propagated: the
//! test fails with the collected list at the end rather than dying on round 1.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use rgx_core::{Ctx, Registry};

/// The adapter vector the registry is built from.
fn adapters() -> Vec<Box<dyn rgx_core::Adapter>> {
    let mut v: Vec<Box<dyn rgx_core::Adapter>> = Vec::new();
    v.extend(rgx_adapters_archive::adapters());
    v.extend(rgx_adapters_office::adapters());
    v.extend(rgx_adapters_threed::adapters());
    v.extend(rgx_adapters_llm::adapters());
    v.extend(rgx_adapters_media::adapters());
    v.extend(rgx_adapters_tabular::adapters());
    v.extend(rgx_adapters_docs::adapters());
    v.extend(rgx_adapters_mail::adapters());
    v.extend(rgx_adapters_inspect::adapters());
    v.extend(rgx_adapters_pdf::adapters());
    v
}

/// The registry and the extension list, built from ONE adapter vector.
///
/// The extension list used to be a hand-written copy, with a doc that said
/// it was kept in sync with the fuzz target's list. Two copies of a list
/// drift exactly the way a README's copy drifts, and the fuzz target's own
/// list stopped being a copy at all: it is derived now, and so is this one.
fn parts() -> &'static (Registry, Vec<&'static str>) {
    static PARTS: std::sync::OnceLock<(Registry, Vec<&'static str>)> = std::sync::OnceLock::new();
    PARTS.get_or_init(|| {
        let v = adapters();
        let mut exts: Vec<&'static str> = v
            .iter()
            .flat_map(|a| a.extensions().iter().copied())
            .collect();
        exts.sort_unstable();
        exts.dedup();
        (Registry::new(v), exts)
    })
}

fn registry() -> &'static Registry {
    &parts().0
}

/// Every extension a claiming adapter registers.
fn extensions() -> &'static [&'static str] {
    &parts().1
}

fn corpus_dir() -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("legacy-formats");
    if p.exists() {
        Some(p)
    } else {
        None
    }
}

fn collect_files(dir: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_files(&p, out);
        } else if let Ok(md) = e.metadata() {
            if md.len() > 0 && md.len() < 4 << 20 {
                out.push((p.display().to_string(), p));
            }
        }
    }
}

#[test]
fn no_adapter_panics_on_any_real_fixture_or_mutation_of_it() {
    let Some(dir) = corpus_dir() else {
        // Same rule as tests/legacy_formats.rs: a missing corpus fails the
        // test. Skipping here would make this file a green light that
        // verified nothing, which is the exact defect it exists to catch.
        panic!(
            "tests/fixtures/legacy-formats/ is absent -- run scripts/fetch-legacy-corpus.sh \
             (or fetch-legacy-corpus.ps1 on Windows); panic_sweep has nothing to sweep without it"
        );
    };
    let mut files = Vec::new();
    collect_files(&dir, &mut files);
    files.sort();
    assert!(!files.is_empty(), "corpus dir present but empty");

    let ctx = Ctx {
        max_depth: 4,
        max_members: 256,
        max_file_size: 1 << 20,
        filter: None,
        facts_sink: None,
    };
    let reg = registry();

    // (fixture name, extension fed to the registry, input size, panic text)
    let mut findings: Vec<(String, String, usize, String)> = Vec::new();
    let mut rng = rgx_core::fuzzkit::Rng::new(0xDEAD_BEEF_CAFE_1234);
    let mut inputs_run: u64 = 0;

    for (label, path) in &files {
        let Ok(real) = std::fs::read(path) else {
            continue;
        };
        let short = label
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(label)
            .to_string();

        // one mutation per extension: real bytes, then mutated, all parsers
        for ext in extensions() {
            let name = format!("sweep/sample.{ext}");
            let mut variants: Vec<Vec<u8>> = vec![real.clone()];
            for _ in 0..2 {
                variants.push(rgx_core::fuzzkit::mutate(&mut rng, &real));
            }
            for input in &variants {
                let mut out = Vec::new();
                let owned = name.clone();
                let ctx2 = Ctx {
                    max_depth: ctx.max_depth,
                    max_members: ctx.max_members,
                    max_file_size: ctx.max_file_size,
                    filter: None,
                    facts_sink: None,
                };
                let res = catch_unwind(AssertUnwindSafe(|| {
                    rgx_core::process(reg, &owned, input, 0, &ctx2, &mut out);
                }));
                inputs_run += 1;
                if let Err(e) = res {
                    let msg = if let Some(s) = e.downcast_ref::<&str>() {
                        s.to_string()
                    } else if let Some(s) = e.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "<non-string panic payload>".to_string()
                    };
                    findings.push((short.clone(), ext.to_string(), input.len(), msg));
                }
            }
        }
    }

    println!(
        "panic_sweep: {} inputs through {} extensions",
        inputs_run,
        extensions().len()
    );
    if findings.is_empty() {
        println!("panic_sweep: no panic found");
        return;
    }
    // group so a repeat is one line, not hundreds
    findings.sort();
    let mut report = String::new();
    let mut last: Option<(String, String, String)> = None;
    let mut count = 0usize;
    for (file, ext, _len, msg) in &findings {
        let key = (file.clone(), ext.to_string(), msg.clone());
        if Some(&key) != last.as_ref() {
            if count > 0 {
                report.push_str(&format!("{count}x {}\n", last.as_ref().unwrap().2));
            }
            count = 0;
            report.push_str(&format!("{file} as .{ext}: {msg}\n"));
            last = Some(key);
        }
        count += 1;
    }
    if count > 0 {
        report.push_str(&format!("{count}x {}\n", last.as_ref().unwrap().2));
    }
    panic!("{} panics:\n{}", findings.len(), report);
}
