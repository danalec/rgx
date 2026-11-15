# rgx-adapters-media/src/exif/makers

## Overview

MakerNote support for manufacturer-specific EXIF data: the per-vendor tag
tables and the MakerNote IFD parser for the camera makers whose MakerNote
*is* a plain TIFF directory. The MakerNote itself lives in the EXIF IFD at
tag `0x927C`; each manufacturer stamps it with its own signature and puts
its IFD at its own offset, so each gets its own case here.

The module is honest about what it does not decode, and that refusal is
part of its contract.

## Interface

- `pub enum Maker` — the supported vendors: `Canon`, `Nikon`, `Sony`,
  `Olympus`, `FujiFilm`, `Panasonic`, `Pentax`, `Ricoh`, `Samsung`,
  `Leica`, `Sigma`, `Apple`, `Unknown`.
  - `pub fn from_make(make: &str) -> Self` — picks the vendor from the
    camera's `Make` string (case-insensitively, by substring).
- `pub struct MakerNoteEntry` — one decoded MakerNote entry: `pub tag:
  u16`, `pub name: Option<String>`, `pub value: String`.
- `pub fn parse_makernote(data: &[u8], maker: Maker) -> Vec<MakerNoteEntry>`
  — parses the MakerNote IFD. Returns an **empty list** for a maker it
  cannot decode, and for blocks too short to hold one.
- `pub fn makernote_tag_name(maker: Maker, tag: u16) -> Option<&'static str>`
  — the tag's name, for the makers this module carries tables for.
- Per-vendor tag-identifier modules, each a set of `pub const TAG: u16`
  values: `canon`, `nikon`, `sony` and `fuji`.

## Invariants

- The vendor is chosen from the file's own `Make` string
  (`Maker::from_make`), not guessed from the payload's shape.
- **Value offsets inside a MakerNote IFD are relative to the start of the
  MakerNote block itself** — byte 0 of `data` — not to the TIFF header the
  parent module uses. A value of 4 bytes or fewer lives inline in the
  entry; anything larger is a pointer relative to that same base.
- Each vendor has its own signature and its own IFD offset, and the
  signature is checked before the offset is read:
  - **Canon** and **Samsung** put the IFD straight at offset 0, with no
    signature at all, little-endian.
  - **Nikon** — `"Nikon\0\x01\x00"` marks **type 1**, whose IFD is a plain
    directory at the little-endian offset 8. Type 2 (encrypted, 3DES) and
    type 3 (encrypted, serial-derived key) are **rejected** rather than
    decoded as if they were type 1.
  - **Sony** — `"SONY DSC \0\0\0"`, little-endian offset 12.
  - **Olympus** — `"OLYMPUS\0"`, little-endian offset 8.
  - **FujiFilm** — `"FUJIFILM"`, little-endian offset 8.
  - **Panasonic** is the odd one out: `"Panasonic\0\0\0"`, **big-endian**
    offset 12 and big-endian throughout.
  - **Pentax** — `"PENTAX \0"`, little-endian offset 8.
- **Ricoh** (encrypted variants), **Sigma** (encrypted), **Leica**
  (encrypted variants), **Apple** (no IFD at all) and an unknown make stay
  unsupported, and `parse_makernote` answers them with an empty list rather
  than with bytes it could not decode. A refusal that looks like an answer
  is worse than a refusal.
- `makernote_tag_name` answers only for the makers this module carries
  tables for — Canon, Nikon, Sony and FujiFilm — and returns `None` for the
  rest. The name of a tag is a fact about the vendor's vocabulary, so it
  does not depend on the payload, but a vendor with no table has no name to
  give.
- The parser reuses the crate's own TIFF machinery (`format_size`,
  `read_u16`, `read_u32`, `read_rational_array`, `read_string`) and its
  `ByteOrder`, so the byte-order handling of a MakerNote is the same as the
  rest of the EXIF walk — with Panasonic's big-endian case carried through
  the same path rather than special-cased.

## Side Effects

- None. Pure functions over `&[u8]`; the module allocates through `alloc`
  and touches nothing outside the process.

## Verification

- Run: `cargo test --release --locked --workspace`
