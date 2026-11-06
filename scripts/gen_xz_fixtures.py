"""Regenerate the two xz fixtures so the streams carry the CURRENT label.

A change to the plaintext fixtures (`kuon` -> `rgx`) landed without
re-encoding the `.xz` streams they are compared against, which desynchronised
the pair and failed two tests. Restoring the `.plain` files to `kuon` fixes the
tests but reverts a deliberate provenance change, so this goes the other way:
the label stays `rgx` and the STREAMS are regenerated, which is what the
project wants.

Two traps this file exists to respect:

* `open(path, 'w')` rewrites `\\n` as `\\r\\n` on Windows, which would corrupt
  both the fixture and the provenance digest of the generated file. Everything
  here is binary.
* A test that encoded with our own encoder and decoded it back would be a
  matched pair and would prove nothing about whether the parser understands the
  format. These come from Python's `lzma`, a binding to the reference
  implementation, which is what `container.rs` says the vectors must be.

Usage:  python scripts/gen_xz_fixtures.py
"""

import lzma
import pathlib

HERE = pathlib.Path(__file__).resolve().parent.parent
DATA = HERE / "crates" / "rgx-core" / "src" / "compress" / "xz" / "testdata"

# The exact bytes the `.plain` files hold. Read rather than written here, so
# this can never disagree with them.
PLAIN = {
    "crc32": DATA / "tiny-crc32.plain",
    "crc64": DATA / "tiny-crc64.plain",
}

CHECK = {
    "crc32": lzma.CHECK_CRC32,
    "crc64": lzma.CHECK_CRC64,
}

for kind in ("crc32", "crc64"):
    src = PLAIN[kind]
    raw = src.read_bytes()  # binary: a text-mode read would not change bytes,
    # but a text-mode WRITE below would, and that is the part that bites.
    out = DATA / f"tiny-{kind}.xz"
    blob = lzma.compress(raw, format=lzma.FORMAT_XZ, check=CHECK[kind])
    out.write_bytes(blob)
    print(f"{out.name}: {len(blob)} bytes from {src.name} ({len(raw)} bytes, check={kind})")

# Prove the pair round-trips through the reference decompressor before anyone
# looks at a diff.
for kind in ("crc32", "crc64"):
    raw = PLAIN[kind].read_bytes()
    blob = (DATA / f"tiny-{kind}.xz").read_bytes()
    assert lzma.decompress(blob) == raw, f"{kind} does not round-trip"
    print(f"{kind}: round-trips through liblzma")