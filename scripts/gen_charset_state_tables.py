#!/usr/bin/env python3
"""Generate `crates/rgx-core/src/charset_state_table.rs` from Python's codecs.

    python scripts/gen_charset_state_tables.py

## What goes in the table

ISO-2022-JP and UTF-7 are not tables of bytes: what a byte means depends on
what came before it. What they have instead is a *structure*, and the
structure is a table:

- **JIS X 0208** (`ESC $ @` and `ESC $ B`): 94 rows of 94 cells. Flattened
  into one array and indexed by the lead byte and then by the trail byte, the
  same shape as the two-byte table of `charset_mb_table.rs`. A cell the
  standard does not use is zero, and the decoder turns that into U+FFFD.
- **JIS X 0212** (`ESC $ ( D`): the same shape, the supplementary set.
- **JIS X 0201 Roman** (`ESC ( J`): ASCII, except that the backslash is the
  yen sign and the tilde is the overline (RFC 1468 section 2).
- **JIS X 0201 katakana** (`ESC ( I`, and the `SO` shift): one byte each.
- **the base64 alphabet** of RFC 2152's set B: the RFC 2045 alphabet without
  the pad character.

## Why it is generated rather than vendored

The two JIS tables are 8,836 cells each, and a hand-typed one is a
transcription error waiting to happen. Python's codec module is the reference
implementation of every one of these encodings, so the table is what the
reference says it is -- the same argument the single-byte and the multi-byte
tables are built on.

## The oracles, one by one

- JIS X 0208: `iso2022_jp`, decoding `ESC $ B` and the pair. The generator
  checks that `ESC $ @` reads the same table, because RFC 1468 makes the two
  the same set of characters with the 1983 revision adding to the 1978 one.
- JIS X 0212: `iso2022_jp_2`, decoding `ESC $ ( D` and the pair. That codec
  also speaks GB2312 (`ESC $ A`), which this module refuses by name; only
  the `ESC $ ( D` designation is read here.
- JIS X 0201 Roman: `iso2022_jp`, decoding `ESC ( J` and the byte.
- JIS X 0201 katakana: `euc_jp`, decoding SS2 (0x8E) and the byte. That is
  the same JIS X 0201 katakana set, and it is the one place Python's codecs
  hands it out: no Python ISO-2022-JP codec accepts `ESC ( I`.
- the base64 alphabet: Python's own `base64` module.
"""

import base64
import pathlib
import sys

# The bytes a JIS X 0208 character is made of: 94 rows, 94 cells each.
JIS_LEAD_MIN = 0x21
JIS_LEAD_MAX = 0x7E
JIS_CELLS = 94

# The bytes a JIS X 0201 katakana character is: 0x21..=0x5F.
KATAKANA_MIN = 0x21
KATAKANA_MAX = 0x5F

# The bytes the escape and the shift controls occupy. They are not
# characters in any of these sets, and the decoder reads them before it
# looks at the table.
ESC = 0x1B
SI = 0x0F
SO = 0x0E

DEFAULT_OUT = pathlib.Path(__file__).resolve().parent.parent / (
    "crates/rgx-core/src/charset_state_table.rs"
)


def jis_table(codec: str, designation: bytes) -> list:
    """The two-byte table of a JIS set, row by row, flattened."""
    table = []
    for lead in range(JIS_LEAD_MIN, JIS_LEAD_MAX + 1):
        for cell in range(JIS_LEAD_MIN, JIS_LEAD_MAX + 1):
            try:
                text = (designation + bytes([lead, cell])).decode(codec)
            except UnicodeDecodeError:
                table.append(0)
                continue
            if len(text) != 1:
                raise SystemExit(f"{codec}: {lead:02X} {cell:02X} is not one character")
            cp = ord(text)
            if cp > 0xFFFF:
                raise SystemExit(f"{codec}: {lead:02X} {cell:02X} is not in the BMP")
            table.append(cp)
    return table


def roman_table() -> list:
    """The bytes of the "Roman" set, which is ASCII with two exceptions."""
    table = []
    for byte in range(0x80):
        if byte in (ESC, SI, SO):
            # The escape and the shift controls are not characters: the
            # decoder reads them before it looks at the table.
            table.append(0)
            continue
        text = (b"\x1b(J" + bytes([byte])).decode("iso2022_jp")
        if len(text) != 1:
            raise SystemExit(f"iso2022_jp: {byte:02X} is not one character")
        table.append(ord(text))
    return table


def katakana_table() -> list:
    """The half-width katakana, one byte each."""
    table = [0] * 0x60
    for byte in range(KATAKANA_MIN, KATAKANA_MAX + 1):
        # EUC-JP's SS2 (0x8E) is the one place Python's codecs hands out the
        # JIS X 0201 katakana set, which is the set `ESC ( I` designates.
        text = bytes([0x8E, 0xA1 + (byte - KATAKANA_MIN)]).decode("euc_jp")
        if len(text) != 1:
            raise SystemExit(f"euc_jp: {byte:02X} is not one character")
        table[byte] = ord(text)
    return table


def base64_table() -> list:
    """RFC 2152's set B: the RFC 2045 alphabet without the pad character."""
    alphabet = "".join(
        base64.b64encode(bytes([value << 2])).decode("ascii")[0] for value in range(64)
    )
    if alphabet != "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/":
        raise SystemExit(f"base64: the alphabet is not the RFC 2045 one: {alphabet}")
    table = [0xFF] * 0x80
    for value, char in enumerate(alphabet):
        table[ord(char)] = value
    return table


def emit(fh, name: str, rust_type: str, table: list, doc: str, last: bool) -> None:
    # Twelve per line: that is what `cargo fmt` packs them into at the
    # default width, so a regenerated file is one `cargo fmt --check` clean
    # instead of one the next person has to reformat. The blank line
    # separates two tables and the file does not end with one -- rustfmt
    # has an opinion about that too.
    fh.write(f"/// {doc}\n")
    fh.write(f"pub(crate) static {name}: [{rust_type}; {len(table)}] = [\n")
    for i in range(0, len(table), 12):
        row = ", ".join(f"0x{value:04X}" for value in table[i:i + 12])
        fh.write(f"    {row},\n")
    fh.write("];\n")
    if not last:
        fh.write("\n")


def main() -> int:
    out_path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    out_path.parent.mkdir(parents=True, exist_ok=True)

    x0208 = jis_table("iso2022_jp", b"\x1b$B")
    # RFC 1468 names two revisions of JIS X 0208 and one escape sequence for
    # each. The generator checks that the reference reads them with the same
    # table rather than assuming it: a pair the 1978 revision does not use is
    # still a pair the 1983 one does.
    differ = []
    for lead in range(JIS_LEAD_MIN, JIS_LEAD_MAX + 1):
        for cell in range(JIS_LEAD_MIN, JIS_LEAD_MAX + 1):
            at = (lead - JIS_LEAD_MIN) * JIS_CELLS + (cell - JIS_LEAD_MIN)
            try:
                old = (b"\x1b$@" + bytes([lead, cell])).decode("iso2022_jp")
            except UnicodeDecodeError:
                if x0208[at] != 0:
                    differ.append((lead, cell, x0208[at], 0))
                continue
            if len(old) != 1 or ord(old) != x0208[at]:
                differ.append((lead, cell, x0208[at], ord(old) if old else 0))

    x0212 = jis_table("iso2022_jp_2", b"\x1b$(D")

    with out_path.open("w", encoding="utf-8") as fh:
        # The default newline handling, not "\n": the working tree here is
        # CRLF (`core.autocrlf=true`), and a generated file that came out LF
        # would show up as modified the moment git touched it.
        fh.write("// SPDX-License-Identifier: Apache-2.0\n")
        fh.write("\n")
        fh.write("//! The tables of the encodings that declare themselves, generated.\n")
        fh.write("//!\n")
        fh.write("//! Do not edit: `python scripts/gen_charset_state_tables.py` writes\n")
        fh.write("//! this file. The source of truth is Python's own codec module,\n")
        fh.write("//! which is the reference implementation of these encodings.\n")
        fh.write("//!\n")
        fh.write("//! ISO-2022-JP and UTF-7 are not tables of bytes: what a byte\n")
        fh.write("//! means depends on what came before it. What they have is a\n")
        fh.write("//! structure, and the structure is a table.\n")
        fh.write("//!\n")
        fh.write("//! A cell the standard does not use is zero, and the decoder turns\n")
        fh.write("//! that into U+FFFD.\n\n")
        emit(
            fh,
            "JIS_X_0208",
            "u16",
            x0208,
            "JIS X 0208: the two-byte form of ISO-2022-JP, `ESC $ @` and `ESC $ B`.",
            last=False,
        )
        emit(
            fh,
            "JIS_X_0212",
            "u16",
            x0212,
            "JIS X 0212: the supplementary set of ISO-2022-JP, `ESC $ ( D`.",
            last=False,
        )
        emit(
            fh,
            "JIS_X_0201_ROMAN",
            "u16",
            roman_table(),
            "JIS X 0201 Roman (`ESC ( J`): ASCII with the yen sign and the overline.",
            last=False,
        )
        emit(
            fh,
            "JIS_X_0201_KATAKANA",
            "u16",
            katakana_table(),
            "JIS X 0201 katakana (`ESC ( I`, and the `SO` shift): one byte each.",
            last=False,
        )
        emit(
            fh,
            "UTF7_BASE64",
            "u8",
            base64_table(),
            "RFC 2152's set B: the base64 alphabet of RFC 2045 without the pad.",
            last=True,
        )
    print(f"wrote {out_path}")
    print(f"  JIS X 0208: {sum(1 for c in x0208 if c)} characters")
    print(f"  JIS X 0212: {sum(1 for c in x0212 if c)} characters")
    print(f"  ESC $ @ and ESC $ B differ in {len(differ)} cells")
    for lead, cell, new, old in differ[:10]:
        print(f"    {lead:02X} {cell:02X}: ESC $ B -> {new:04X}, ESC $ @ -> {old:04X}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
