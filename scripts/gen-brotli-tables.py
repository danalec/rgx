#!/usr/bin/env python3
"""Regenerate crates/rgx-adapters-archive/src/brotli/tables.rs from RFC 7932.

The Brotli format carries three blobs of normative data that no amount of
cleverness can derive: the static dictionary (Appendix A), the 121 word
transformations (Appendix B), and the three literal-context lookup tables
(Section 7.1). They are transcribed from the RFC text and checked against
the CRC-32 values the RFC prints alongside each of them, so a transcription
error is a hard failure here rather than a decoder that quietly produces
the wrong bytes.

    curl -O https://www.rfc-editor.org/rfc/rfc7932.txt
    python scripts/gen-brotli-tables.py rfc7932.txt

Pass the output path as a second argument to write somewhere other than
the default.
"""

import binascii
import os
import re
import sys

NL = chr(10)

DEFAULT_OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "crates", "rgx-adapters-archive", "src", "brotli", "tables.rs",
)


def crc32(data):
    return binascii.crc32(data) & 0xFFFFFFFF


def section(lines, start_pat, end_pat):
    """Text between the first line matching start_pat and the next end_pat."""
    out, on = [], False
    for line in lines:
        if not on:
            if re.match(start_pat, line):
                on = True
            continue
        if re.match(end_pat, line):
            break
        out.append(line)
    return out


def unpage(lines):
    """Drop the RFC's page furniture: running heads and form feeds."""
    keep = []
    for line in lines:
        if line.startswith("\f"):
            continue
        if re.match(r"^Alakuijala & Szabadka", line):
            continue
        if re.match(r"^RFC 7932 ", line):
            continue
        keep.append(line)
    return keep


def parse_dictionary(lines):
    body = unpage(section(lines, r"^Appendix A\.", r"^Appendix B\."))
    hexdigits = []
    started = False
    for line in body:
        if not started:
            if "hexadecimal form of the DICT array" in line:
                started = True
            continue
        s = line.strip()
        if re.fullmatch(r"(?:[0-9a-f]{32}){1,2}", s):
            hexdigits.append(s)
    data = binascii.unhexlify("".join(hexdigits))
    if len(data) != 122784:
        raise SystemExit(f"dictionary: {len(data)} bytes, RFC says 122784")
    if crc32(data) != 0x5136CB04:
        raise SystemExit(f"dictionary: CRC-32 0x{crc32(data):08x}, RFC says 0x5136cb04")
    print(f"  DICT: {len(data)} bytes, CRC-32 0x{crc32(data):08x} ok")
    return data


KIND = {"Identity": 0, "FermentFirst": 1, "FermentAll": 2}
for i in range(1, 10):
    KIND[f"OmitFirst{i}"] = 2 + i
    KIND[f"OmitLast{i}"] = 11 + i

C_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "'": "'", "0": "\0"}


def unescape(literal):
    literal = literal[1:-1]
    out, i = [], 0
    while i < len(literal):
        c = literal[i]
        if c == "\\":
            i += 1
            if literal[i] == "x":
                out.append(chr(int(literal[i + 1:i + 3], 16)))
                i += 2
            else:
                out.append(C_ESCAPES[literal[i]])
        else:
            out.append(c)
        i += 1
    return "".join(out).encode("latin-1")


def parse_transforms(lines):
    body = unpage(section(lines, r"^Appendix B\.", r"^Appendix C\."))
    row = re.compile(
        r'^\s*(\d+)\s+(""|"(?:[^"\\]|\\.)*")\s+(\w+)\s+(""|"(?:[^"\\]|\\.)*")\s*$')
    transforms, blob = [], b""
    for line in body:
        m = row.match(line)
        if not m:
            continue
        idx, prefix, kind, suffix = m.groups()
        if int(idx) != len(transforms):
            raise SystemExit(f"transform {idx} out of order")
        p, s = unescape(prefix), unescape(suffix)
        if kind not in KIND:
            raise SystemExit(f"transform {idx}: unknown {kind}")
        blob += p + b"\0" + bytes([KIND[kind]]) + s + b"\0"
        transforms.append((p, KIND[kind], s))
    if len(transforms) != 121:
        raise SystemExit(f"transforms: {len(transforms)}, RFC says 121")
    if crc32(blob) != 0x3D965F81:
        raise SystemExit(f"transforms: CRC-32 0x{crc32(blob):08x}, RFC says 0x3d965f81")
    print(f"  transforms: {len(transforms)} entries, blob {len(blob)} bytes, "
          f"CRC-32 0x{crc32(blob):08x} ok")
    return transforms


def parse_lut(lines, name, want_len, want_crc):
    # Section 7.1 prints the three tables in order between "Lut0 :=" and
    # the CRC table that follows them.
    start = next(i for i, l in enumerate(lines) if l.strip().startswith("Lut0 :="))
    end = next(i for i, l in enumerate(lines)
               if i > start and l.strip().startswith("The lengths and the CRC-32"))
    order = ["Lut0", "Lut1", "Lut2"]
    which = order.index(name)
    marker = f"{name} :="
    at = next(i for i in range(start, end) if lines[i].strip().startswith(marker))
    nxt = order[which + 1] if which + 1 < len(order) else None
    stop = next((i for i in range(at + 1, end)
                 if nxt and lines[i].strip().startswith(f"{nxt} :=")), end)
    values = []
    for line in unpage(lines[at + 1:stop]):
        for tok in line.replace(",", " ").split():
            if re.fullmatch(r"\d+", tok):
                values.append(int(tok))
    data = bytes(values[:want_len])
    if len(data) != want_len:
        raise SystemExit(f"{name}: {len(data)} values, RFC says {want_len}")
    if crc32(data) != want_crc:
        raise SystemExit(f"{name}: CRC-32 0x{crc32(data):08x}, RFC says 0x{want_crc:08x}")
    print(f"  {name}: {len(data)} bytes, CRC-32 0x{crc32(data):08x} ok")
    return data


def rust_bytes(data, per_line=16, indent="    "):
    out = []
    for i in range(0, len(data), per_line):
        chunk = ", ".join(f"0x{b:02x}" for b in data[i:i + per_line])
        out.append(indent + chunk + ",")
    return "\n".join(out)


def rust_byte_str(data):
    """A byte string literal, one source line per 60 source characters."""
    if not data:
        return 'b""'
    body = "".join(chr(b) if 32 <= b < 127 and chr(b) not in '"\\' else f"\\x{b:02x}"
                   for b in data)
    lines = [body[i:i + 60] for i in range(0, len(body), 60)]
    return "\n".join("    b\"" + ln + "\"" for ln in lines)


def main():
    rfc = sys.argv[1] if len(sys.argv) > 1 else "rfc7932.txt"
    out_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_OUT
    lines = open(rfc, encoding="utf-8", errors="replace").read().splitlines()

    print(f"reading {rfc}")
    dictionary = parse_dictionary(lines)
    transforms = parse_transforms(lines)
    lut0 = parse_lut(lines, "Lut0", 256, 0x8E91EFB7)
    lut1 = parse_lut(lines, "Lut1", 256, 0xD01A32F4)
    lut2 = parse_lut(lines, "Lut2", 256, 0x0DD7A0D6)

    bits = [0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8,
            7, 7, 6, 6, 5, 5]
    offsets = [0] * 25
    for n in range(4, 24):
        offsets[n + 1] = offsets[n] + n * (1 << bits[n])
    size = offsets[24] + 24 * (1 << bits[24])
    if size != len(dictionary):
        raise SystemExit(f"DOFFSET recursion gives {size}, DICT is {len(dictionary)}")

    kinds = ["Identity", "FermentFirst", "FermentAll"] + \
            [f"OmitFirst{i}" for i in range(1, 10)] + \
            [f"OmitLast{i}" for i in range(1, 10)]

    body = f'''//! RFC 7932's normative tables: the static dictionary, the 121 word
//! transformations, and the three literal-context lookup tables.
//!
//! Generated by `scripts/gen-brotli-tables.py` from the RFC text itself
//! (Appendix A, Appendix B and Section 7.1), not from any implementation.
//! Each blob is checked here against the CRC-32 the RFC prints for it --
//! DICT 0x5136cb04, the transform sequence 0x3d965f81, Lut0 0x8e91efb7,
//! Lut1 0xd01a32f4, Lut2 0x0dd7a0d6 -- so a bad transcription is a build
//! failure rather than a decoder that decodes something else.
//!
//! This file is generated. Edit the generator, not this.

/// RFC 7932 Section 8: the 21 elementary transforms, in the order the RFC
/// numbers them, which is what the transform check value is built from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {{
{chr(10).join(
    "    /// Listed by the RFC; Appendix B uses none of them." + NL
    + "    #[allow(dead_code)]" + NL + f"    {k} = {i},"
    if k == "OmitFirst8" else f"    {k} = {i},"
    for i, k in enumerate(kinds))}
}}

/// One of the 121 transforms: `prefix + T(word) + suffix` (Section 8).
#[derive(Clone, Copy, Debug)]
pub struct Transform {{
    pub prefix: &'static [u8],
    pub kind: Kind,
    pub suffix: &'static [u8],
}}

/// Appendix A: the static dictionary, {len(dictionary)} bytes.
pub static DICT: [u8; {len(dictionary)}] = [
{rust_bytes(dictionary)}
];

/// Section 8: the byte offset of the first word of each length. Derived
/// from the NDBITS recursion, and checked against DICT's length.
pub const DICT_OFFSET: [u32; 25] = [
    {", ".join(str(v) for v in offsets)},
];

/// Section 8: `log2` of the number of words of each length.
pub const DICT_SIZE_BITS: [u8; 25] = [
    {", ".join(str(v) for v in bits)},
];

/// Appendix B: the 121 word transformations.
pub static TRANSFORMS: [Transform; 121] = [
{chr(10).join(f'    Transform {{ prefix: {rust_byte_str(p)}, kind: Kind::{kinds[t]}, suffix: {rust_byte_str(s)} }},' for p, t, s in transforms)}
];

/// Section 7.1: literal context ID lookup, indexed by the last byte `p1`.
pub static LUT0: [u8; 256] = [
{rust_bytes(lut0)}
];

/// Section 7.1: literal context ID lookup, indexed by the second-to-last
/// byte `p2`.
pub static LUT1: [u8; 256] = [
{rust_bytes(lut1)}
];

/// Section 7.1: literal context ID lookup for the Signed context mode.
pub static LUT2: [u8; 256] = [
{rust_bytes(lut2)}
];
'''
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    print(f"wrote {out_path} ({len(body)} bytes)")


if __name__ == "__main__":
    main()
