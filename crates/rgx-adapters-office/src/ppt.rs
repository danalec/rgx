// SPDX-License-Identifier: Apache-2.0

//! Binary PowerPoint (.ppt, PowerPoint 97-2003) text extraction.
//!
//! The file is an OLE CFB with two streams: `Current User` (points at the
//! newest `UserEditAtom`) and `PowerPoint Document` (a flat sequence of
//! [MS-PPT] records). The structured path walks
//! `UserEditAtom` → `PersistDirectoryAtom`(s) → persisted record trees and
//! harvests `TextCharsAtom` (UTF-16LE) / `TextBytesAtom` (cp1252) /
//! `CStringAtom` leaves. If the edit chain is broken (quirky producers,
//! truncated files), a validated linear scan over the stream recovers the
//! same atoms at the cost of document order.
//!
//! A reduced port of the PPT reader of the `io` project by Dan Gohman,
//! whose work is used here under Apache-2.0: the structured atoms with
//! their offsets/kinds and provenance flags are what this reader walks, and
//! it flattens them to text. See `NOTICE`.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use rgx_core::cfb::Cfb;
use rgx_core::Outcome;
use rgx_core::{decline, Context, Result};

#[cfg(test)]
#[allow(unused_imports)]
use alloc::string::ToString;
#[cfg(test)]
#[allow(unused_imports)]
use core::iter;

const RT_TEXT_CHARS: u16 = 0x0FA0;
const RT_TEXT_BYTES: u16 = 0x0FA8;
const RT_CSTRING: u16 = 0x0FBA;
const RT_USER_EDIT: u16 = 0x0FF5;
const RT_CURRENT_USER: u16 = 0x0F66;
const RT_PERSIST_DIR: u16 = 0x1772;
const RT_PERSIST_PTR: u16 = 0x1773;
const MAX_TEXT: usize = 16 << 20;

/// Decode UTF-16LE into `out` via `char::decode_utf16`, skipping the
/// intermediate `Vec<u16>` the `from_utf16_lossy` chain used to allocate.
/// Replacement characters (U+FFFD) stand in for malformed surrogate
/// pairs, matching the prior `from_utf16_lossy` behaviour.
fn push_utf16_le(payload: &[u8], out: &mut String) {
    let units = payload
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]));
    for c in core::char::decode_utf16(units).flatten() {
        out.push(c);
    }
}

pub struct Ppt;

impl rgx_core::Adapter for Ppt {
    fn name(&self) -> &'static str {
        "ppt"
    }
    fn extensions(&self) -> &'static [&'static str] {
        &["ppt", "pot", "pps"]
    }
    fn extract(&self, data: &[u8], _path: &str) -> Result<Outcome> {
        let text = extract_text(data)?;
        Ok(Outcome::Text(text.into_bytes()))
    }
}

pub fn extract_text(data: &[u8]) -> Result<String> {
    let cfb = Cfb::parse(data)?;
    let ppt = cfb
        .stream("PowerPoint Document")
        .decline_context("no PowerPoint Document stream")?;
    let mut out = String::new();

    if let Some(user) = cfb.stream("Current User") {
        walk_edit_chain(&user, &ppt, &mut out);
    }
    if out.trim().is_empty() {
        linear_scan(&ppt, &mut out);
    }
    if out.trim().is_empty() {
        decline!("no text atoms in PowerPoint Document stream");
    }
    if out.len() > MAX_TEXT {
        out.truncate(MAX_TEXT);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// record header helpers (8 bytes: u16 verInst, u16 recType, u32 recLen)
// ---------------------------------------------------------------------------

fn rec_type(d: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*d.get(off + 2)?, *d.get(off + 3)?]))
}

fn rec_len(d: &[u8], off: usize) -> usize {
    let b = d.get(off + 4..off + 8);
    match b {
        Some(b) if b.len() == 4 => u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize,
        _ => usize::MAX,
    }
}

/// End of the record starting at `off`, clamped to the stream.
fn rec_end(d: &[u8], off: usize) -> usize {
    let len = rec_len(d, off);
    len.saturating_add(off + 8).min(d.len())
}

fn is_container(d: &[u8], off: usize) -> bool {
    match d.get(off) {
        Some(b) => b & 0x0F == 0x0F,
        None => false,
    }
}

// ---------------------------------------------------------------------------
// structured path: UserEditAtom chain → persist directories → record trees
// ---------------------------------------------------------------------------

fn walk_edit_chain(user: &[u8], ppt: &[u8], out: &mut String) {
    // Current User Atom: header(8) + size(4) + headerToken(4) + offsetToCurrentEdit(4)
    if user.len() < 20 || rec_type(user, 0) != Some(RT_CURRENT_USER) {
        return;
    }
    let mut edit = u32::from_le_bytes([user[16], user[17], user[18], user[19]]) as usize;
    let mut persist_dirs: Vec<usize> = Vec::new();
    let mut seen = 0usize;
    while seen < 1000 && rec_type(ppt, edit) == Some(RT_USER_EDIT) {
        seen += 1;
        let body_end = rec_end(ppt, edit);
        if body_end <= edit + 8 {
            break;
        }
        // UserEditAtom body: lastSlideIdRef(4) version(4) minor(2) major(2)
        //                   offsetLastEdit(4) offsetPersistDirectory(4) ...
        let read = |at: usize| -> u32 {
            u32::from_le_bytes([
                *ppt.get(at).unwrap_or(&0),
                *ppt.get(at + 1).unwrap_or(&0),
                *ppt.get(at + 2).unwrap_or(&0),
                *ppt.get(at + 3).unwrap_or(&0),
            ])
        };
        let mut last = read(edit + 20) as usize;
        let mut dir = read(edit + 24) as usize;
        // tolerate the all-u32 field variant: offsets at +24/+28
        if !valid_dir(ppt, dir) && valid_dir(ppt, read(edit + 28) as usize) {
            last = read(edit + 24) as usize;
            dir = read(edit + 28) as usize;
        }
        if valid_dir(ppt, dir) {
            persist_dirs.push(dir);
        }
        if last == edit || last == 0 {
            break;
        }
        edit = last;
    }
    if persist_dirs.is_empty() {
        return;
    }

    // newest section first: first occurrence of a persist id wins
    let mut offsets: BTreeMap<u32, usize> = BTreeMap::new();
    for &dir in &persist_dirs {
        collect_persist_dir(ppt, dir, &mut offsets);
    }

    let mut visited = BTreeSet::new();
    for (_, &off) in offsets.iter().take(100_000) {
        if visited.insert(off) {
            walk_records(ppt, off, 0, out);
            if out.len() > MAX_TEXT {
                break;
            }
        }
    }
}

fn valid_dir(ppt: &[u8], off: usize) -> bool {
    matches!(
        rec_type(ppt, off),
        Some(RT_PERSIST_DIR) | Some(RT_PERSIST_PTR)
    )
}

/// PersistPtrEntry: u32 persistIdSlot (persistId = slot >> 12, count = slot
/// & 0xFFF) followed by `count` u32 offsets.
fn collect_persist_dir(ppt: &[u8], dir: usize, offsets: &mut BTreeMap<u32, usize>) {
    let end = rec_end(ppt, dir);
    let mut p = dir + 8;
    while p + 4 <= end {
        let slot = u32::from_le_bytes([ppt[p], ppt[p + 1], ppt[p + 2], ppt[p + 3]]);
        let id = slot >> 12;
        let count = (slot & 0xFFF) as usize;
        p += 4;
        if count == 0 || count > 4096 || p + count * 4 > end {
            break;
        }
        for k in 0..count {
            let off = u32::from_le_bytes([ppt[p], ppt[p + 1], ppt[p + 2], ppt[p + 3]]) as usize;
            p += 4;
            if off + 8 <= ppt.len() && !offsets.contains_key(&(id + k as u32)) {
                offsets.insert(id + k as u32, off);
            }
        }
    }
}

fn walk_records(ppt: &[u8], off: usize, depth: usize, out: &mut String) {
    if depth > 32 || off + 8 > ppt.len() || out.len() > MAX_TEXT {
        return;
    }
    let end = rec_end(ppt, off);
    if end <= off + 8 {
        return;
    }
    let ty = match rec_type(ppt, off) {
        Some(t) => t,
        None => return,
    };
    if is_container(ppt, off) {
        let mut child = off + 8;
        while child + 8 <= end {
            let next = rec_end(ppt, child);
            if next <= child + 8 {
                break;
            }
            walk_records(ppt, child, depth + 1, out);
            child = next;
        }
        return;
    }
    let payload = &ppt[off + 8..end];
    match ty {
        RT_TEXT_CHARS => push_utf16_text(payload, out),
        RT_CSTRING => push_utf16_text(payload, out),
        RT_TEXT_BYTES => {
            let s: String = payload.iter().map(|&b| cp1252(b)).collect();
            push_text(&s, out);
        }
        _ => {}
    }
}

/// UTF-16LE text payload: stream-decoded into a transient String
/// and pushed through the same `push_text` filter (trim-empty,
/// trailing newline) the cp1252 path uses.
fn push_utf16_text(payload: &[u8], out: &mut String) {
    if !payload.len().is_multiple_of(2) {
        return;
    }
    let mut tmp = String::new();
    push_utf16_le(payload, &mut tmp);
    push_text(&tmp, out);
}

fn push_text(s: &str, out: &mut String) {
    if s.trim().is_empty() {
        return;
    }
    out.push_str(s);
    if !s.ends_with(['\n', '\r']) {
        out.push('\n');
    }
}

// ---------------------------------------------------------------------------
// fallback: validated linear scan for text atoms
// ---------------------------------------------------------------------------

fn linear_scan(ppt: &[u8], out: &mut String) {
    for (pat, utf16) in [
        (RT_TEXT_CHARS.to_le_bytes(), true),
        (RT_TEXT_BYTES.to_le_bytes(), false),
    ] {
        let mut from = 0usize;
        while let Some(r) = rgx_core::memchr::memmem::find(&ppt[from..], &pat) {
            let off = from + r;
            from = off + 2;
            if off < 2 || rec_type(ppt, off - 2) != Some(u16::from_le_bytes(pat)) {
                continue; // matched mid-payload, not a header
            }
            let head = off - 2;
            if *ppt.get(head).unwrap_or(&0xFF) & 0x0F != 0 {
                continue; // atoms are recVer 0
            }
            let end = rec_end(ppt, head);
            if end <= head + 8 || end - head - 8 > 1 << 20 {
                continue;
            }
            let payload = &ppt[head + 8..end];
            let s = if utf16 {
                if !payload.len().is_multiple_of(2) {
                    continue;
                }
                let mut tmp = String::new();
                push_utf16_le(payload, &mut tmp);
                tmp
            } else {
                payload.iter().map(|&b| cp1252(b)).collect()
            };
            if mostly_text(&s) {
                push_text(&s, out);
            }
        }
    }
}

fn mostly_text(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let ok = s
        .chars()
        .filter(|c| !c.is_control() || c.is_whitespace())
        .count();
    ok * 2 >= s.chars().count()
}

/// The character one byte stands for in cp1252 (0x80..=0x9F mapped, the
/// rest Latin-1).
///
/// The table is the shared one in `rgx-core`, generated from the reference
/// implementation: a hand-written copy of 32 characters is a transcription
/// error waiting to happen.
fn cp1252(b: u8) -> char {
    rgx_core::charset::windows_1252_char(b)
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn atom(ty: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + payload.len());
        v.extend_from_slice(&0x0000u16.to_le_bytes()); // verInst
        v.extend_from_slice(&ty.to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn container(ty: u16, children: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = children.concat();
        let mut v = Vec::with_capacity(8 + body.len());
        v.extend_from_slice(&0x000Fu16.to_le_bytes()); // ver 0xF = container
        v.extend_from_slice(&ty.to_le_bytes());
        v.extend_from_slice(&(body.len() as u32).to_le_bytes());
        v.extend_from_slice(&body);
        v
    }

    fn text_chars(s: &str) -> Vec<u8> {
        let units: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        atom(RT_TEXT_CHARS, &units)
    }

    fn text_bytes(s: &str) -> Vec<u8> {
        let bytes: Vec<u8> = s.chars().map(|c| c as u8).collect();
        atom(RT_TEXT_BYTES, &bytes)
    }

    /// Minimal CFB image with regular-sector streams only (every stream
    /// padded to ≥4096 bytes so the mini stream is never needed).
    fn cfb_image(streams: &[(&str, &[u8])]) -> Vec<u8> {
        const SS: usize = 512;
        let mut sectors: Vec<Vec<u8>> = Vec::new();
        let mut entries: Vec<(String, usize, u64)> = Vec::new(); // (name, start_sector, size)
        for (name, data) in streams {
            let start = sectors.len();
            let mut padded = data.to_vec();
            padded.resize(data.len().div_ceil(SS) * SS, 0);
            for chunk in padded.chunks(SS) {
                sectors.push(chunk.to_vec());
            }
            entries.push((name.to_string(), start, data.len() as u64));
        }
        let dir_sector = sectors.len();
        sectors.push(vec![0xFF; SS]); // filled below
        let fat_sector = sectors.len();
        sectors.push(vec![0; SS]);

        // FAT
        let mut fat = vec![0xFFFFFFFFu32; SS / 4];
        let mark_chain = |start: usize, count: usize, fat: &mut Vec<u32>| {
            for k in 0..count {
                fat[start + k] = if k + 1 < count {
                    (start + k + 1) as u32
                } else {
                    0xFFFFFFFE
                };
            }
        };
        let mut off = 0usize;
        for (_, start, size) in &entries {
            let count = (*size as usize).div_ceil(SS);
            mark_chain(*start, count, &mut fat);
            off += count;
        }
        let _ = off;
        fat[dir_sector] = 0xFFFFFFFE; // single directory sector
        sectors[fat_sector] = fat.iter().flat_map(|v| v.to_le_bytes()).collect();

        // directory sector: root + one entry per stream
        let mut dir = vec![0u8; SS];
        let write_entry =
            |buf: &mut [u8], idx: usize, name: &str, ty: u8, start: u32, size: u64| {
                let e = &mut buf[idx * 128..idx * 128 + 128];
                let wide: Vec<u16> = name.encode_utf16().chain(iter::once(0)).collect();
                for (i, u) in wide.iter().enumerate() {
                    e[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
                }
                e[64] = (wide.len() * 2) as u8; // name length incl. NUL, bytes
                e[66] = ty;
                e[68..72].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // left
                e[72..76].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // right
                e[116..120].copy_from_slice(&start.to_le_bytes());
                e[120..128].copy_from_slice(&size.to_le_bytes());
            };
        write_entry(&mut dir, 0, "Root Entry", 5, 0xFFFFFFFE, 0);
        for (i, (name, start, size)) in entries.iter().enumerate() {
            write_entry(&mut dir, i + 1, name, 2, *start as u32, *size);
        }
        sectors[dir_sector] = dir;

        // header
        let total = sectors.len();
        let mut img = Vec::with_capacity(512 + total * SS);
        let mut hdr = vec![0u8; 512];
        hdr[0..8].copy_from_slice(&0xD0CF11E0A1B11AE1u64.to_be_bytes());
        hdr[24..26].copy_from_slice(&0x003Eu16.to_le_bytes()); // minor
        hdr[26..28].copy_from_slice(&0x0003u16.to_le_bytes()); // major v3
        hdr[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes()); // byte order
        hdr[30..32].copy_from_slice(&9u16.to_le_bytes()); // sector shift
        hdr[32..34].copy_from_slice(&6u16.to_le_bytes()); // mini sector shift
        hdr[44..48].copy_from_slice(&(fat_sector as u32).to_le_bytes()); // num FAT
        hdr[48..52].copy_from_slice(&(dir_sector as u32).to_le_bytes()); // first dir
        hdr[56..60].copy_from_slice(&4096u32.to_le_bytes()); // mini cutoff
        hdr[60..64].copy_from_slice(&0xFFFFFFFEu32.to_le_bytes()); // first miniFAT
        hdr[64..68].copy_from_slice(&0u32.to_le_bytes());
        hdr[68..72].copy_from_slice(&0xFFFFFFFEu32.to_le_bytes()); // first DIFAT
        hdr[72..76].copy_from_slice(&0u32.to_le_bytes());
        hdr[76..80].copy_from_slice(&(fat_sector as u32).to_le_bytes()); // DIFAT[0]
        for k in 1..109 {
            hdr[76 + k * 4..80 + k * 4].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        }
        img.extend_from_slice(&hdr);
        for s in &sectors {
            img.extend_from_slice(s);
        }
        img
    }

    /// Build a synthetic .ppt: Current User → UserEditAtom →
    /// PersistDirectory → a Document container with two text atoms.
    fn sample_ppt() -> Vec<u8> {
        // PowerPoint Document stream layout (byte offsets are stable because
        // we assemble it in order):
        //   0: Document container
        //   then UserEditAtom, PersistDirectoryAtom
        let doc = container(
            0x03E8,
            &[
                text_chars("Título do slide"),
                text_bytes("corpo cp1252 simples"),
            ],
        );
        let doc_len = doc.len();

        let build_user_edit = |dir_off: u32| {
            atom(RT_USER_EDIT, &{
                let mut b = Vec::new();
                b.extend_from_slice(&0u32.to_le_bytes()); // lastSlideIdRef
                b.extend_from_slice(&0u32.to_le_bytes()); // version
                b.extend_from_slice(&0u16.to_le_bytes()); // minor
                b.extend_from_slice(&0u16.to_le_bytes()); // major
                b.extend_from_slice(&0u32.to_le_bytes()); // offsetLastEdit = 0
                b.extend_from_slice(&dir_off.to_le_bytes()); // offsetPersistDirectory
                b.extend_from_slice(&1u32.to_le_bytes()); // persistIdSeed
                b.extend_from_slice(&0u32.to_le_bytes()); // reserved
                b
            })
        };
        // persist atom follows the UserEditAtom; the atom's own length is
        // fixed regardless of the offset value, so measure then rebuild
        let user_edit_len = build_user_edit(0).len();
        let user_edit = build_user_edit((doc_len + user_edit_len) as u32);

        // persist directory pointing at persistId 0 → offset 0 (Document)
        let slot = 1u32; // persistId 0, count 1
        let persist = atom(
            RT_PERSIST_DIR,
            &[slot.to_le_bytes(), 0u32.to_le_bytes()].concat(),
        );

        let mut ppt_stream = Vec::new();
        ppt_stream.extend_from_slice(&doc);
        ppt_stream.extend_from_slice(&user_edit);
        ppt_stream.extend_from_slice(&persist);

        // Current User: header(0x0F66) + size + token + offsetToCurrentEdit
        let mut user = Vec::new();
        user.extend_from_slice(&0x0000u16.to_le_bytes());
        user.extend_from_slice(&RT_CURRENT_USER.to_le_bytes());
        user.extend_from_slice(&16u32.to_le_bytes());
        user.extend_from_slice(&16u32.to_le_bytes());
        user.extend_from_slice(&0u32.to_le_bytes());
        user.extend_from_slice(&(doc_len as u32).to_le_bytes());

        // pad both streams past the 4096 mini-stream cutoff
        let mut ppt_pad = ppt_stream;
        ppt_pad.resize(4096, 0);
        let mut user_pad = user;
        user_pad.resize(4096, 0);

        cfb_image(&[
            ("Current User", &user_pad),
            ("PowerPoint Document", &ppt_pad),
        ])
    }

    #[test]
    fn extracts_text_atoms() {
        let text = extract_text(&sample_ppt()).unwrap();
        assert!(text.contains("Título do slide"), "{text}");
        assert!(text.contains("corpo cp1252 simples"), "{text}");
    }

    #[test]
    fn linear_scan_recovers_without_chain() {
        // no Current User stream at all → fallback path
        let doc = container(0x03E8, &[text_chars("scan fallback text")]);
        let mut pad = doc;
        pad.resize(4096, 0);
        let img = cfb_image(&[("PowerPoint Document", &pad)]);
        let text = extract_text(&img).unwrap();
        assert!(text.contains("scan fallback text"), "{text}");
    }

    #[test]
    fn rejects_non_ppt() {
        assert!(extract_text(b"not a ppt").is_err());
    }

    #[test]
    fn never_panics_on_mutation() {
        rgx_core::fuzzkit::assert_never_panics(
            vec![("sample", sample_ppt()), ("empty", vec![])],
            2000,
            "ppt",
            |data| {
                let _ = extract_text(data);
            },
        );
    }
}
