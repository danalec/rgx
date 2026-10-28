#!/usr/bin/env python3
"""Generate the multi-byte CJK charset tables, and the fixtures that test them.

    python scripts/gen_charset_mb_tables.py

## What goes in the table

The high half of the legacy CJK encodings is a *pair* of bytes, not one, so
the single-byte table of `charset_table.rs` cannot hold it. Each encoding
gets three things:

- **the single-byte half**: the characters that stand alone in 0x80..=0xFF
  (Shift_JIS and EUC-JP's half-width katakana). 128 entries, as in the
  single-byte table.
- **the two-byte table**: indexed by the lead byte and then by the trail
  byte, which is a two-level lookup with no search in it. The table covers
  the whole span from the lowest lead to the highest and from the lowest
  trail to the highest; a position the encoding does not use is zero.
- **the extra forms**: EUC-JP's three-byte JIS X 0212 (`0x8F` and two more
  bytes) and GB18030's four-byte extension to the Unicode planes.

A position with no character is zero in the table and U+FFFD in the output,
which is the WHATWG encoding standard's own rule.

## Why it is generated rather than vendored

These are tables of thousands of entries, and a hand-typed one is a
transcription error waiting to happen. Python's codec module is the
reference implementation of every one of these encodings, so the table is
what the reference says it is -- the same argument the single-byte tables
are built on.

The fixtures come from the same source for the same reason: the text is
written here, Python encodes it, and the decoder has to give the text back.
A table that is right and a decoder that reads it wrong are two different
bugs, and a round trip catches both.

## The four-byte form

GB18030's four-byte sequences do not map to Unicode one by one: they map
through a *pointer space* of 1,587,600 positions, and the standard's table
says which runs of that space are consecutive in Unicode. The runs are
derived here by walking the whole pointer space and keeping the maximal
runs whose codepoints advance by one -- which is the standard's table,
derived from the reference implementation rather than transcribed from a
second copy of it.
"""

import pathlib
import sys

# (Rust constant name, Python codec name, lead ranges, trail ranges)
ENCODINGS = [
    # Shift_JIS: JIS X 0208, with the half-width katakana standing alone.
    ("SHIFT_JIS", "shift_jis", [(0x81, 0x9F), (0xE0, 0xFC)], [(0x40, 0x7E), (0x80, 0xFC)]),
    # EUC-JP: JIS X 0208 in two bytes, the half-width katakana behind 0x8E.
    ("EUC_JP", "euc_jp", [(0x8E, 0x8E), (0xA1, 0xFE)], [(0xA1, 0xFE)]),
    # Big5 with the Hong Kong extensions, which is what the WHATWG index and
    # Python's `big5hkscs` both hold.
    ("BIG5", "big5hkscs", [(0x81, 0xFE)], [(0x40, 0x7E), (0xA1, 0xFE)]),
    # EUC-KR: KS X 1001 with the Unified Hangul, which is what Python's
    # `euc_kr` is.
    ("EUC_KR", "euc_kr", [(0x81, 0xFE)], [(0x41, 0x5A), (0x61, 0x7A), (0x81, 0xFE)]),
    # GB18030: the GBK two-byte form. The four-byte form is separate.
    ("GB18030", "gb18030", [(0x81, 0xFE)], [(0x40, 0x7E), (0x80, 0xFE)]),
]

# EUC-JP's three-byte form: 0x8F and two more bytes, JIS X 0212.
EUC_JP_PREFIX = 0x8F
EUC_JP_TRAILS = (0xA1, 0xFE)

# GB18030's four-byte form: the pointer space of the standard.
GB18030_POINTERS = 126 * 10 * 126 * 10

DEFAULT_OUT = pathlib.Path(__file__).resolve().parent.parent / (
    "crates/rgx-core/src/charset_mb_table.rs"
)
DEFAULT_TESTDATA = pathlib.Path(__file__).resolve().parent.parent / (
    "crates/rgx-core/testdata/charset"
)


def in_ranges(ranges, byte):
    return any(lo <= byte <= hi for lo, hi in ranges)


def single_table(codec):
    """The characters that stand alone in 0x80..=0xFF; 0 where there is none."""
    out = []
    for byte in range(0x80, 0x100):
        try:
            ch = bytes([byte]).decode(codec)
        except UnicodeDecodeError:
            out.append(0)
            continue
        out.append(ord(ch) if len(ch) == 1 else 0)
    return out


def two_byte_table(codec, leads, trails):
    """The table of the two-byte form, indexed by lead then by trail."""
    lead_min = min(lo for lo, _ in leads)
    lead_max = max(hi for _, hi in leads)
    trail_min = min(lo for lo, _ in trails)
    trail_max = max(hi for _, hi in trails)
    stride = trail_max - trail_min + 1
    table = [0] * ((lead_max - lead_min + 1) * stride)
    for lead in range(lead_min, lead_max + 1):
        if not in_ranges(leads, lead):
            continue
        for trail in range(trail_min, trail_max + 1):
            if not in_ranges(trails, trail):
                continue
            try:
                ch = bytes([lead, trail]).decode(codec)
            except UnicodeDecodeError:
                continue
            if len(ch) != 1:
                continue
            table[(lead - lead_min) * stride + (trail - trail_min)] = ord(ch)
    return lead_min, trail_min, trail_max, table


def three_byte_table(codec, prefix, trail_min, trail_max):
    """EUC-JP's JIS X 0212: a prefix byte and two trail bytes."""
    stride = trail_max - trail_min + 1
    table = [0] * (stride * stride)
    for t1 in range(trail_min, trail_max + 1):
        for t2 in range(trail_min, trail_max + 1):
            try:
                ch = bytes([prefix, t1, t2]).decode(codec)
            except UnicodeDecodeError:
                continue
            if len(ch) != 1:
                continue
            table[(t1 - trail_min) * stride + (t2 - trail_min)] = ord(ch)
    return table


def gb18030_ranges(codec):
    """The runs of GB18030's pointer space that are consecutive in Unicode.

    Each run is (the first pointer, its length, the codepoint of its first
    position): the standard's table, derived from the reference
    implementation rather than transcribed from a second copy of it.
    """
    ranges = []
    run_start = None
    run_len = 0
    run_base = 0
    prev_cp = None
    for pointer in range(GB18030_POINTERS):
        b1 = 0x81 + pointer // 12600
        rest = pointer % 12600
        b2 = 0x30 + rest // 1260
        rest %= 1260
        b3 = 0x81 + rest // 10
        b4 = 0x30 + rest % 10
        try:
            cp = ord(bytes([b1, b2, b3, b4]).decode(codec))
        except UnicodeDecodeError:
            cp = None
        if cp is None:
            if run_start is not None:
                ranges.append((run_start, run_len, run_base))
                run_start = None
            continue
        if run_start is not None and cp == prev_cp + 1:
            run_len += 1
        else:
            if run_start is not None:
                ranges.append((run_start, run_len, run_base))
            run_start = pointer
            run_len = 1
            run_base = cp
        prev_cp = cp
    if run_start is not None:
        ranges.append((run_start, run_len, run_base))
    return ranges


def emit_u32(fh, values, per_line, indent="    "):
    # Seven hex digits, so every literal is the same width and the packing
    # is the same on every line: `cargo fmt` fills a short-element array
    # up to its width, and a mixed-width one would be packed differently.
    # Eight per line is what it packs, and a regenerated file is therefore
    # one `cargo fmt --check` clean.
    for i in range(0, len(values), per_line):
        row = ", ".join(f"0x{cp:07X}" for cp in values[i:i + per_line])
        fh.write(f"{indent}{row},\n")


def emit_u32_triples(fh, values, per_line, indent="    "):
    # A tuple is longer than the width rustfmt packs short elements at, so
    # it is written one per line -- which is what rustfmt does with it.
    for a, b, c in values:
        fh.write(f"{indent}(0x{a:08X}, 0x{b:08X}, 0x{c:08X}),\n")


def emit_rust(fh, tables):
    fh.write("// SPDX-License-Identifier: Apache-2.0\n")
    fh.write("\n")
    fh.write("//! Legacy multi-byte CJK charset tables, generated.\n")
    fh.write("//!\n")
    fh.write("//! Do not edit: `python scripts/gen_charset_mb_tables.py` writes this\n")
    fh.write("//! file. The source of truth is Python's own codec module, which is\n")
    fh.write("//! the reference implementation of every one of these encodings.\n")
    fh.write("//!\n")
    fh.write("//! The high half of these encodings is a *pair* of bytes, so the table\n")
    fh.write("//! is indexed by the lead byte and then by the trail byte. A position\n")
    fh.write("//! with no character is zero, and the decoder turns that into U+FFFD.\n")
    fh.write("//!\n")
    fh.write("//! The single-byte half holds the characters that stand alone in\n")
    fh.write("//! 0x80..=0xFF: the half-width katakana of Shift_JIS and EUC-JP.\n\n")
    fh.write("use crate::charset::{MultiByte, Prefix3};\n\n")

    for name, codec, leads, trails in ENCODINGS:
        single = single_table(codec)
        lead_min, trail_min, trail_max, table = two_byte_table(codec, leads, trails)
        lead_max = max(hi for _, hi in leads)
        fh.write(f"/// {name}: the table of the two-byte form.\n")
        fh.write(f"pub(crate) static {name}: MultiByte = MultiByte {{\n")
        fh.write(f'    name: "{name.lower()}",\n')
        fh.write("    single: &[\n")
        emit_u32(fh, single, 8, "        ")
        fh.write("    ],\n")
        fh.write(f"    lead_min: 0x{lead_min:02X},\n")
        fh.write(f"    lead_max: 0x{lead_max:02X},\n")
        fh.write(f"    trail_min: 0x{trail_min:02X},\n")
        fh.write(f"    trail_max: 0x{trail_max:02X},\n")
        fh.write("    leads: &[")
        fh.write(", ".join(f"(0x{lo:02X}, 0x{hi:02X})" for lo, hi in leads))
        fh.write("],\n")
        fh.write("    trails: &[")
        fh.write(", ".join(f"(0x{lo:02X}, 0x{hi:02X})" for lo, hi in trails))
        fh.write("],\n")
        fh.write("    table: &[\n")
        emit_u32(fh, table, 8, "        ")
        fh.write("    ],\n")

        if name == "EUC_JP":
            three = three_byte_table(codec, EUC_JP_PREFIX, *EUC_JP_TRAILS)
            fh.write("    prefix3: Some(Prefix3 {\n")
            fh.write(f"        prefix: 0x{EUC_JP_PREFIX:02X},\n")
            fh.write(f"        trail_min: 0x{EUC_JP_TRAILS[0]:02X},\n")
            fh.write(f"        trail_max: 0x{EUC_JP_TRAILS[1]:02X},\n")
            fh.write("        table: &[\n")
            emit_u32(fh, three, 8, "            ")
            fh.write("        ],\n")
            fh.write("    }),\n")
        else:
            fh.write("    prefix3: None,\n")

        if name == "GB18030":
            ranges = gb18030_ranges(codec)
            fh.write("    quad: &[\n")
            emit_u32_triples(fh, ranges, 4, "        ")
            fh.write("    ],\n")
        else:
            fh.write("    quad: &[],\n")
        fh.write("};\n")
        # The blank line separates two tables and the file does not end with
        # one -- rustfmt has an opinion about that too.
        if name != ENCODINGS[-1][0]:
            fh.write("\n")


# --------------------------------------------------------------------------
# The fixtures
# --------------------------------------------------------------------------

# The text each fixture carries. It is written here, Python encodes it, and
# the decoder has to give it back: a table that is right and a decoder that
# reads it wrong are two different bugs, and a round trip catches both.
FIXTURES = {
    "shift_jis": (
        "Hello, world! こんにちは、世界。\n"
        "カタカナとひらがな。漢字：東京、山川。\n"
        "Half-width: ｱｲｳｴｵ and full-width: アイウエオ。\n"
        "Punctuation: 「こんにちは」、『世界』。１２３。\n"
    ),
    "euc_jp": (
        "Hello, world! こんにちは、世界。\n"
        "カタカナとひらがな。漢字：東京、山川。\n"
        "Half-width: ｱｲｳｴｵ and full-width: アイウエオ。\n"
        "Punctuation: 「こんにちは」、『世界』。１２３。\n"
    ),
    "big5": (
        "Hello, world! 你好，世界。\n"
        "繁體中文：臺北、香港、學校、電腦。\n"
        "標點：「你好」、『世界』。１２３。\n"
    ),
    "euc_kr": (
        "Hello, world! 안녕하세요, 세계。\n"
        "한글: 서울, 부산, 학교, 컴퓨터.\n"
        "문장부호: 「안녕하세요」, 『세계』. １２３.\n"
    ),
    "gb18030": (
        "Hello, world! 你好，世界。\n"
        "简体中文：北京、上海、学校、电脑。\n"
        "标点：「你好」、『世界』。１２３。\n"
    ),
}

# EUC-JP's three-byte form: JIS X 0212, which is behind 0x8F.

# GB18030's four-byte form: the extension to the Unicode planes.


# EUC-JP's three-byte form: JIS X 0212, which is behind 0x8F. The
# characters are the ones the reference encodes in that form -- Greek and
# Cyrillic letters the JIS X 0208 does not carry, and the symbols that
# live only in 0212.
EUC_JP_THREE_CANDIDATES = (
    "ΆΈΉΊΪΌΎΫΏάέήίϊΐόςύϋΰώ"
    "ЃЄЅІЇЈЉЊЋЌЎЏђѓ"
    "№™©®ªº˘ˇ¸˙˝¯˛˚~΄΅¡¦¿¤"
)

# GB18030's four-byte form: the extension to the Unicode planes.
GB18030_QUAD_CANDIDATES = "\U00020000 \U0002A700 \U0002B740 \U0001D11E \U0001F600 𠀀 𪚲 𠮷"


def encodable(codec, candidates, want_len):
    """The characters the reference can encode in the form of that length."""
    kept = []
    for ch in candidates:
        try:
            encoded = ch.encode(codec)
        except UnicodeEncodeError:
            continue
        if len(encoded) != want_len:
            continue
        kept.append(ch)
    return "".join(kept)


def emit_fixtures(testdata):
    testdata.mkdir(parents=True, exist_ok=True)
    for name, text in FIXTURES.items():
        codec = {n.lower(): c for n, c, _, _ in ENCODINGS}[name]
        (testdata / f"{name}.bin").write_bytes(text.encode(codec))
        (testdata / f"{name}.expected").write_bytes(text.encode("utf-8"))

    codec = "euc_jp"
    three = encodable(codec, EUC_JP_THREE_CANDIDATES, 3)
    (testdata / "euc_jp_three.bin").write_bytes(three.encode(codec))
    (testdata / "euc_jp_three.expected").write_bytes(three.encode("utf-8"))

    codec = "gb18030"
    quad = encodable(codec, GB18030_QUAD_CANDIDATES, 4)
    (testdata / "gb18030_quad.bin").write_bytes(quad.encode(codec))
    (testdata / "gb18030_quad.expected").write_bytes(quad.encode("utf-8"))

    # The sampled table: every 97th position of every two-byte table, every
    # 97th of the three-byte one, and the first, the middle and the last
    # position of every four-byte range, with the codepoint the reference
    # says it holds. The tables themselves are generated, so they cannot be
    # mistyped; what this pins down is the *decoder's* indexing of them.
    lines = []
    for name, codec, leads, trails in ENCODINGS:
        lead_min, trail_min, trail_max, table = two_byte_table(codec, leads, trails)
        stride = trail_max - trail_min + 1
        for index in range(0, len(table), 97):
            cp = table[index]
            if cp == 0:
                continue
            lead = lead_min + index // stride
            trail = trail_min + index % stride
            lines.append(f"{name} {lead:02X}{trail:02X} {cp:04X}")

        if name == "EUC_JP":
            three = three_byte_table(codec, EUC_JP_PREFIX, *EUC_JP_TRAILS)
            tstride = EUC_JP_TRAILS[1] - EUC_JP_TRAILS[0] + 1
            for index in range(0, len(three), 97):
                cp = three[index]
                if cp == 0:
                    continue
                t1 = EUC_JP_TRAILS[0] + index // tstride
                t2 = EUC_JP_TRAILS[0] + index % tstride
                lines.append(f"{name} {EUC_JP_PREFIX:02X}{t1:02X}{t2:02X} {cp:04X}")

        if name == "GB18030":
            for start, length, base in gb18030_ranges(codec):
                for offset in (0, length // 2, length - 1):
                    pointer = start + offset
                    b1 = 0x81 + pointer // 12600
                    rest = pointer % 12600
                    b2 = 0x30 + rest // 1260
                    rest %= 1260
                    b3 = 0x81 + rest // 10
                    b4 = 0x30 + rest % 10
                    lines.append(f"{name} {b1:02X}{b2:02X}{b3:02X}{b4:02X} {base + offset:04X}")

    # The line endings are LF, and written as such: the file is inside a
    # `-text` directory, so git keeps its bytes exactly, and a file whose
    # bytes depend on the platform that generated it is not reproducible.
    with (testdata / "vectors.txt").open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(
            "# <encoding> <bytes in hex> <codepoint>. Sampled from every table of\n"
            "# every encoding: every 97th position of the two-byte and the\n"
            "# three-byte tables, and the first, the middle and the last position\n"
            "# of every four-byte range.\n"
            "# Generated: scripts/gen_charset_mb_tables.py\n"
        )
        fh.write("\n".join(lines))
        fh.write("\n")


def main() -> int:
    out_path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUT
    testdata = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_TESTDATA
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # The default newline handling, not "\n": the working tree here is CRLF
    # (`core.autocrlf=true`), and a generated file that came out LF would
    # show up as modified the moment git touched it.
    with out_path.open("w", encoding="utf-8") as fh:
        emit_rust(fh, ENCODINGS)
    emit_fixtures(testdata)
    print(f"wrote {out_path}")
    print(f"wrote {testdata}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
