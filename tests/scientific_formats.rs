// SPDX-License-Identifier: Apache-2.0

//! The HDF5-based scientific formats, checked against the real binary.
//!
//! **What this pins.** A netCDF-4 file and a MATLAB v7.3 file are HDF5 files,
//! and both used to reach nobody. The reader looked for the HDF5 signature
//! at offset 0 only, while MATLAB writes 512 bytes of its own descriptive
//! header first and starts the HDF5 file at 512; and no adapter claimed
//! `.nc` or `.mat` for HDF5 at all. The `.mat` was worse than unreadable:
//! the v5 reader sees the `IM` endian marker at byte 126 in a v7.3 file
//! too, so it walked HDF5 bytes as v5 tags and printed nonsense.
//!
//! **Every row checks the adapter that answered, and the answer has to carry
//! a name in the format's own vocabulary** -- a netCDF variable, a MATLAB
//! variable -- because "the file was read" is a claim the raw bytes could
//! satisfy by accident.
//!
//! **The last two rows keep the fix honest.** A netCDF-3 `.nc` and a MATLAB
//! v5 `.mat` are the very extensions the HDF5 reader now claims, and they
//! must still go to the readers that understand them: the HDF5 reader
//! declines them, not the other way round.
//!
//! **The fixtures are real files**, taken from the reference implementations
//! (netcdf-c and matio) and kept in the crate's `testdata` directory, with
//! their provenance in the README next to them.

use std::path::{Path, PathBuf};
use std::process::Command;

/// One file: the adapter that must answer for it, and a pattern the answer
/// must carry.
struct Case {
    /// What the file is, in the words of the format.
    format: &'static str,
    /// The fixture, relative to the repository root.
    fixture: &'static str,
    /// The adapter that must answer for the file.
    adapter: &'static str,
    /// A pattern the answer must carry: a variable name, a dimension.
    carries: &'static str,
}

const CASES: &[Case] = &[
    Case {
        format: "netCDF-4 (names in a fractal heap)",
        fixture: "crates/rgx-adapters-tabular/testdata/netcdf4-fractal-heap.nc",
        adapter: "hdf5",
        carries: "link: Dr: dimension scale: float32",
    },
    Case {
        format: "netCDF-4 (names in a continuation chunk)",
        fixture: "crates/rgx-adapters-tabular/testdata/netcdf4-irish-rover.nc",
        adapter: "hdf5",
        carries: "link: cargo: committed datatype: enum",
    },
    Case {
        format: "netCDF-4 (the values of the variables)",
        fixture: "crates/rgx-adapters-tabular/testdata/netcdf4-compact-links.nc",
        adapter: "hdf5",
        carries: r"value: var\[0\] = \{x: 1, y: -2\}",
    },
    Case {
        format: "netCDF-4 (a group and a dimension)",
        fixture: "crates/rgx-adapters-tabular/testdata/netcdf4-provenance.nc",
        adapter: "hdf5",
        carries: "link: subgroup: group",
    },
    Case {
        format: "netCDF-4 (names in the object header)",
        fixture: "crates/rgx-adapters-tabular/testdata/netcdf4-compact-links.nc",
        adapter: "hdf5",
        carries: "link: var: dataset: compound",
    },
    Case {
        format: "netCDF-4 (the file's own attributes)",
        fixture: "crates/rgx-adapters-tabular/testdata/netcdf4-fractal-heap.nc",
        adapter: "hdf5",
        carries: "attribute: <root>: Gb = -128, 127",
    },
    Case {
        format: "netCDF-4 (the attribute of a member)",
        fixture: "crates/rgx-adapters-tabular/testdata/netcdf4-provenance.nc",
        adapter: "hdf5",
        carries: "attribute: int_var: int_attr = 17",
    },
    Case {
        format: "netCDF-4 (the attribute that marks a dimension)",
        fixture: "crates/rgx-adapters-tabular/testdata/netcdf4-irish-rover.nc",
        adapter: "hdf5",
        carries: "attribute: dim: CLASS = DIMENSION_SCALE",
    },
    Case {
        format: "netCDF-4 (the members of an enumeration)",
        fixture: "crates/rgx-adapters-tabular/testdata/netcdf4-irish-rover.nc",
        adapter: "hdf5",
        carries: "member: cargo: dogs = 5000000",
    },
    Case {
        format: "netCDF-4 (the members of a compound)",
        fixture: "crates/rgx-adapters-tabular/testdata/netcdf4-compact-links.nc",
        adapter: "hdf5",
        carries: "member: cmp_t: y = float64",
    },
    Case {
        format: "MATLAB v7.3",
        fixture: "crates/rgx-adapters-tabular/testdata/matlab-v7.mat",
        adapter: "hdf5",
        carries: "user block: MATLAB 7.3 MAT-file",
    },
    Case {
        format: "MATLAB v7.0 with an HDF5 payload",
        fixture: "crates/rgx-adapters-tabular/testdata/matlab-v70-hdf5.mat",
        adapter: "hdf5",
        carries: "link: testdouble: dataset: float64",
    },
    Case {
        format: "MATLAB v7.3 (little-endian, schema 1.00)",
        fixture: "crates/rgx-adapters-tabular/testdata/matlab-v73.mat",
        adapter: "hdf5",
        carries: "link: d: dataset: float64",
    },
    // The two that must NOT go to the HDF5 reader.
    Case {
        format: "netCDF classic",
        fixture: "crates/rgx-adapters-tabular/testdata/netcdf3-360-day.nc",
        adapter: "netcdf",
        carries: "dim time = 2300",
    },
    Case {
        format: "netCDF classic (the values of the variables)",
        fixture: "crates/rgx-adapters-tabular/testdata/netcdf3-360-day.nc",
        adapter: "netcdf",
        carries: r"value time\[2299\] = 2299",
    },
    Case {
        format: "MATLAB v5",
        fixture: "crates/rgx-adapters-tabular/testdata/matlab-v5.mat",
        adapter: "mat",
        carries: "easy: struct",
    },
];

/// The repository root: the directory the manifest sits in.
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `--json` match line of a run, as `(adapter, text)`.
///
/// `-a` because one row searches a file that reaches the raw passthrough:
/// a binary file is skipped without it, and the row that checks the raw
/// answer would then pass for the wrong reason (no answer at all).
fn matches(pattern: &str, file: &Path) -> Vec<(String, String)> {
    let out = Command::new(env!("CARGO_BIN_EXE_rgx"))
        .args(["--json", "-a", pattern])
        .arg(file)
        .output()
        .expect("rgx runs");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut found = Vec::new();
    for line in text.lines().filter(|l| l.contains("\"type\":\"match\"")) {
        let take = |key: &str| -> Option<String> {
            let at = line.find(key)?;
            let rest = &line[at + key.len()..];
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        };
        if let (Some(a), Some(t)) = (take("\"adapter\":\""), take("\"text\":\"")) {
            found.push((a, t));
        }
    }
    found
}

#[test]
fn every_hdf5_based_format_reaches_the_reader_that_understands_it() {
    for case in CASES {
        let file = repo_root().join(case.fixture);
        assert!(file.is_file(), "{} is missing", case.fixture);
        let hits = matches(case.carries, &file);
        assert!(
            !hits.is_empty(),
            "{}: the pattern {:?} was not found at all",
            case.format,
            case.carries
        );
        let adapters: Vec<&str> = hits.iter().map(|(a, _)| a.as_str()).collect();
        assert!(
            adapters.contains(&case.adapter),
            "{}: expected {:?} to answer, got {adapters:?}",
            case.format,
            case.adapter
        );
    }
}

/// The `.nc` and `.mat` extensions are claimed by two readers each now, and
/// the HDF5 one has to be the one that declines what is not HDF5. A v5 file
/// whose name says `.h5` is asked of the HDF5 reader and refused by it, and
/// the file stays searchable as its own bytes: rgx is a superset of ripgrep,
/// and a reader that declines does not take the file away.
#[test]
fn the_hdf5_reader_is_the_one_that_declines() {
    let root = repo_root();
    std::fs::create_dir_all(root.join("target")).unwrap();
    let v73 = root.join("crates/rgx-adapters-tabular/testdata/matlab-v7.mat");
    let v5 = root.join("crates/rgx-adapters-tabular/testdata/matlab-v5.mat");

    // the v7.3 bytes under a .h5 name: the HDF5 reader answers
    let v73_as_h5 = root.join("target").join("rgx-scientific-probe.h5");
    std::fs::write(&v73_as_h5, std::fs::read(&v73).unwrap()).unwrap();
    let adapters: Vec<String> = matches("MATLAB", &v73_as_h5)
        .into_iter()
        .map(|(a, _)| a)
        .collect();
    assert!(
        adapters.iter().any(|a| a == "hdf5"),
        "the v7.3 bytes under a .h5 name must reach the HDF5 reader, got {adapters:?}"
    );

    // the v5 bytes under the same name: the HDF5 reader declines them, and
    // the file answers as its own bytes
    let v5_as_h5 = root.join("target").join("rgx-scientific-probe-v5.h5");
    std::fs::write(&v5_as_h5, std::fs::read(&v5).unwrap()).unwrap();
    let adapters: Vec<String> = matches("MATLAB", &v5_as_h5)
        .into_iter()
        .map(|(a, _)| a)
        .collect();
    assert!(
        !adapters.iter().any(|a| a == "hdf5"),
        "the HDF5 reader answered a file that is not HDF5: {adapters:?}"
    );
    assert!(
        adapters.iter().any(|a| a == "raw"),
        "the file must stay searchable as its own bytes, got {adapters:?}"
    );
}
