// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for the disk-image family: run the real `rgx` binary
//! over images built here at runtime.
//!
//! Two claims are under test, and they are different in kind. An ISO 9660
//! image has a catalogue, so the adapter hands the pipeline its files as
//! members and a hit has to come back with a path *inside* the image. A VHD
//! is a block container whose contents would need a mount, so what the
//! adapter can honestly report is the container's own metadata — and the
//! test asserts exactly that, at the level of the whole pipeline rather
//! than the adapter in isolation.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;

fn rgx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rgx"))
}

///
/// The directory is one of this run's own: `common::scratch` owns the rule
/// its name follows, and the rule is written down there.
fn scratch(name: &str) -> PathBuf {
    common::scratch(&format!("images-test-{name}"))
}

fn both_endian16(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
    buf[at + 2..at + 4].copy_from_slice(&v.to_be_bytes());
}

fn both_endian32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    buf[at + 4..at + 8].copy_from_slice(&v.to_be_bytes());
}

/// A structurally valid ISO 9660: PVD at sector 16, a root directory at
/// sector 18 holding one file whose extent is sector 19.
fn iso_with(body: &[u8], name: &str) -> Vec<u8> {
    const SECTOR: usize = 2048;
    let mut img = vec![0u8; SECTOR * 20];

    let pvd = 16 * SECTOR;
    img[pvd] = 1;
    img[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
    img[pvd + 6] = 1;
    both_endian16(&mut img, pvd + 128, SECTOR as u16);
    both_endian32(&mut img, pvd + 80, 20);
    let label = b"RGX_FIXTURE";
    img[pvd + 40..pvd + 40 + label.len()].copy_from_slice(label);
    let root = pvd + 156;
    img[root] = 34;
    both_endian32(&mut img, root + 2, 18);
    both_endian32(&mut img, root + 10, SECTOR as u32);

    let dir = 18 * SECTOR;
    for (at, marker) in [(dir, 0u8), (dir + 34, 1u8)] {
        img[at] = 34;
        both_endian32(&mut img, at + 2, 18);
        both_endian32(&mut img, at + 10, SECTOR as u32);
        img[at + 25] = 0x02;
        img[at + 32] = 1;
        img[at + 33] = marker;
    }

    let id = format!("{name};1").into_bytes();
    let at = dir + 68;
    img[at] = (33 + id.len() + 1) as u8;
    both_endian32(&mut img, at + 2, 19);
    both_endian32(&mut img, at + 10, body.len() as u32);
    img[at + 32] = id.len() as u8;
    img[at + 33..at + 33 + id.len()].copy_from_slice(&id);
    img[19 * SECTOR..19 * SECTOR + body.len()].copy_from_slice(body);
    img
}

fn run(dir: &Path, args: &[&str]) -> (String, bool) {
    let out = rgx().args(args).arg(dir).output().unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.success(),
    )
}

#[test]
fn a_search_reaches_a_file_inside_an_iso_image() {
    let dir = scratch("iso");
    let disc = dir.join("disc.iso");
    std::fs::write(&disc, iso_with(b"invoice total 42\n", "README.TXT")).unwrap();

    let (stdout, _) = run(&dir, &["invoice"]);
    assert!(
        stdout.contains("disc.iso!README.TXT"),
        "the hit must name the member inside the image, got: {stdout}"
    );
    assert!(stdout.contains("invoice total 42"), "{stdout}");

    // `-l` names the container, not the member: the file the user passed
    // is what has a path on disk.
    let (stdout, _) = run(&dir, &["invoice", "-l"]);
    assert!(stdout.contains("disc.iso"), "{stdout}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_volume_label_of_an_iso_is_searchable() {
    let dir = scratch("isovol");
    std::fs::write(dir.join("disc.iso"), iso_with(b"x\n", "A.TXT")).unwrap();
    let (stdout, _) = run(&dir, &["RGX_FIXTURE"]);
    assert!(stdout.contains("RGX_FIXTURE"), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_vhd_reports_its_own_metadata_and_nothing_else() {
    let dir = scratch("vhd");
    let mut disk = vec![0u8; 8192];
    disk[..8].copy_from_slice(b"conectix");
    disk[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    disk[28..32].copy_from_slice(b"win ");
    disk[36..40].copy_from_slice(b"Wi2k");
    disk[40..48].copy_from_slice(&1_000_000u64.to_be_bytes());
    disk[48..56].copy_from_slice(&1_000_000u64.to_be_bytes());
    disk[60..64].copy_from_slice(&2u32.to_be_bytes()); // fixed
    disk[68..84].copy_from_slice(&[0x11; 16]);
    // A fixed VHD is a block container: reading its bytes would need a
    // mount, so only the footer is searchable, and it says who made it.
    disk[600..604].copy_from_slice(b"BLOB");
    std::fs::write(dir.join("disk.vhd"), &disk).unwrap();

    let (stdout, _) = run(&dir, &["Wi2k"]);
    assert!(
        stdout.contains("Wi2k"),
        "the creator must be searchable: {stdout}"
    );
    assert!(stdout.contains("disk.vhd"), "{stdout}");

    let (stdout, _) = run(&dir, &["BLOB"]);
    assert!(
        stdout.is_empty(),
        "the payload of a block container is not searched: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_qcow2_names_its_backing_file() {
    let dir = scratch("qcow2");
    let mut disk = vec![0u8; 4096];
    disk[0..4].copy_from_slice(&0x5146_49FBu32.to_le_bytes());
    disk[4..8].copy_from_slice(&2u32.to_le_bytes());
    disk[8..16].copy_from_slice(&512u64.to_le_bytes());
    disk[16..20].copy_from_slice(&10u32.to_le_bytes());
    disk[20..24].copy_from_slice(&16u32.to_le_bytes());
    disk[24..32].copy_from_slice(&(4u64 << 30).to_le_bytes());
    disk[512..522].copy_from_slice(b"base.qcow2");
    std::fs::write(dir.join("disk.qcow2"), &disk).unwrap();
    let (stdout, _) = run(&dir, &["base.qcow2"]);
    assert!(stdout.contains("disk.qcow2"), "{stdout}");
    let _ = std::fs::remove_dir_all(&dir);
}
