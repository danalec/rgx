#!/usr/bin/env python3
"""Generate `crates/rgx-core/src/charset_table.rs` from Python's own codecs.

    python scripts/gen_charset_tables.py

## What goes in the table

The high half of the legacy single-byte encodings: bytes 0x80..=0xFF, one
`u16` codepoint each. The low half is ASCII in every one of them and is
left to the identity path, so a table is 128 entries rather than 256.

EBCDIC is the exception: cp037 puts its space at 0x40 and its punctuation
where ASCII has letters, so its low half is not ASCII and the identity
path would read it wrongly. Its table therefore carries every byte, all
256 of them, and the decoder looks the byte up in it. Every other IBM
EBCDIC page here is the same: the space stays at 0x40 and the low half
is not ASCII in any of them. IBM866 is not one of them -- it is the
Cyrillic code page of the PC, not an EBCDIC page, and its low half is
ASCII like every other single-byte encoding here.

A byte with no mapping becomes U+FFFD, which is the WHATWG encoding
standard's own rule and the one a browser follows.

## Why it is generated rather than vendored

These are 128-entry tables of the high half, and a hand-typed one is a
transcription error waiting to happen -- the CP1252 high half alone has 32
positions, five of which are the kind of detail that is checked by eye
against a table of Latin-1 and quietly wrong. Python's codec module is the
reference implementation of every one of these encodings, so the table is
what the reference says it is.

The five positions CP1252 leaves undefined (0x81, 0x8D, 0x8F, 0x90, 0x9D)
are the one place Python cannot be asked: its codec raises on them, and
what a browser does with them -- the corresponding C1 control character --
is a table of its own, so they are written out here.
"""

import pathlib
import sys

# (Rust constant name, Python codec name)
ENCODINGS = [
    ("ISO_8859_2", "iso8859_2"),   # Latin-2, Central European
    ("ISO_8859_5", "iso8859_5"),   # Cyrillic
    ("ISO_8859_7", "iso8859_7"),   # Greek
    ("ISO_8859_15", "iso8859_15"),  # Latin-9
    ("WINDOWS_1250", "cp1250"),    # Central European
    ("WINDOWS_1251", "cp1251"),    # Cyrillic
    ("WINDOWS_1252", "cp1252"),    # Western European
    ("WINDOWS_1253", "cp1253"),    # Greek
    ("WINDOWS_1254", "cp1254"),    # Turkish
    ("WINDOWS_1255", "cp1255"),    # Hebrew
    ("WINDOWS_1257", "cp1257"),    # Baltic
    ("WINDOWS_1258", "cp1258"),    # Vietnamese
    ("KOI8_R", "koi8_r"),          # Russian
    ("KOI8_U", "koi8_u"),          # Ukrainian
    # The IBM code pages. Every one of them but one puts its space at 0x40,
    # where ASCII has an `@`, so every one of them but one is a full table.
    ("EBCDIC_CP_US", "cp037"),     # EBCDIC, IBM code page 037
    ("EBCDIC_CP_500", "cp500"),    # EBCDIC, IBM code page 500
    ("EBCDIC_CP_1047", "cp1047"),  # EBCDIC, IBM code page 1047
    ("EBCDIC_CP_1140", "cp1140"),  # EBCDIC, IBM code page 1140 (037 with the euro)
    ("EBCDIC_CP_875", "cp875"),    # EBCDIC, IBM code page 875 (Greek)
    ("EBCDIC_CP_1026", "cp1026"),  # EBCDIC, IBM code page 1026 (Turkish)
    ("EBCDIC_CP_273", "cp273"),    # EBCDIC, IBM code page 273 (German)
    # IBM866 is the odd one out: it is not an EBCDIC page at all but the
    # Cyrillic code page of the PC, whose low half is ASCII like every
    # other single-byte encoding here. The registry's name for it is
    # "IBM866" and its aliases are "cp866" and "866".
    ("CP_866", "ibm866"),          # IBM code page 866 (Cyrillic)
]

# The encodings whose low half is not ASCII: their table carries every
# byte, not only the high half.
FULL_TABLES = {
    "EBCDIC_CP_US",
    "EBCDIC_CP_500",
    "EBCDIC_CP_1047",
    "EBCDIC_CP_1140",
    "EBCDIC_CP_875",
    "EBCDIC_CP_1026",
    "EBCDIC_CP_273",
}

# The five CP1252 positions Python leaves undefined, with the C1 control
# character the WHATWG table uses in their place.
CP1252_UNDEFINED = {
    0x81: 0x0081,
    0x8D: 0x008D,
    0x8F: 0x008F,
    0x90: 0x0090,
    0x9D: 0x009D,
}

REPLACEMENT = 0xFFFD

DEFAULT_OUT = pathlib.Path(__file__).resolve().parent.parent / (
    "crates/rgx-core/src/charset_table.rs"
)


def table_for(codec: str, name: str) -> list:
    out = []
    lo = 0x00 if name in FULL_TABLES else 0x80
    for byte in range(lo, 0x100):
        if name == "WINDOWS_1252" and byte in CP1252_UNDEFINED:
            out.append(CP1252_UNDEFINED[byte])
            continue
        try:
            ch = bytes([byte]).decode(codec)
        except UnicodeDecodeError:
            out.append(REPLACEMENT)
            continue
        if len(ch) != 1:
            out.append(REPLACEMENT)
            continue
        out.append(ord(ch))
    return out


def emit(fh, name: str, table: list, last: bool) -> None:
    # Twelve per line: that is what `cargo fmt` packs them into at the
    # default width, so a regenerated file is one `cargo fmt --check` clean
    # instead of one the next person has to reformat. The blank line
    # separates two tables and the file does not end with one -- rustfmt
    # has an opinion about that too.
    fh.write(f"pub(crate) static {name}: [u16; {len(table)}] = [\n")
    for i in range(0, len(table), 12):
        row = ", ".join(f"0x{cp:04X}" for cp in table[i:i + 12])
        fh.write(f"    {row},\n")
    fh.write("];\n")
    if not last:
        fh.write("\n")


def main() -> int:
    out_path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # The default newline handling, not "\n": the working tree here is CRLF
    # (`core.autocrlf=true`), and a generated file that came out LF would
    # show up as modified the moment git touched it.
    with out_path.open("w", encoding="utf-8") as fh:
        fh.write("// SPDX-License-Identifier: Apache-2.0\n")
        fh.write("\n")
        fh.write("//! Legacy single-byte charset tables, generated.\n")
        fh.write("//!\n")
        fh.write("//! Do not edit: `python scripts/gen_charset_tables.py` writes this file.\n")
        fh.write("//! The source of truth is Python's own codec module, which is the\n")
        fh.write("//! reference implementation of every one of these encodings.\n")
        fh.write("//!\n")
        fh.write("//! Each table covers bytes 0x80..=0xFF; the low half is ASCII in all\n")
        fh.write("//! of them but EBCDIC, whose table covers every byte. A byte with no\n")
        fh.write("//! mapping is U+FFFD.\n\n")
        for index, (name, codec) in enumerate(ENCODINGS):
            emit(fh, name, table_for(codec, name), last=index == len(ENCODINGS) - 1)
    print(f"wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
