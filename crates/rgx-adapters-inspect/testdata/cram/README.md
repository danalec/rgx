# CRAM fixtures

The fixtures here are the bytes the CRAM adapter is checked against. Each
one is recorded with where it came from and what it is for, so that a
reader can tell a fixture that was written by an independent implementation
from one that was assembled by hand.

| file | size | sha256 | what it is |
|---|---|---|---|
| `cram21-eof.cram` | 56 | `2b25f8e3127a16912897a6c4052d0ee83da75f9563e89477f710a5a730470eb9` | A CRAM 2.1 file that holds nothing but the end-of-file marker: the 26-byte file definition, then the 30-byte container of §8. |

## `cram21-eof.cram`

**Provenance.** Written by hand in the research corpus
(`target/fmt/cram/write_cram21.py`), from the CRAM 2.1 specification's own
listing of the end-of-file marker (§8, page 12 of `CRAMv2.1.pdf`). The
container header, the compression header block and the file definition are
the specification's bytes; the only difference from the specification's
listing is that the reference id -1 is spelled `ff ff ff ff 0f` rather than
the five `ff`s the listing prints. Both spell the same value, because the
last byte of an ITF-8's 5-byte form is masked with `0x0f`, and htsjdk
writes the `ff ff ff ff 0f` form for a v2 marker.

**What it is for.** The anchor of the CRAM 2.1 container: a reader that
read the container's `length` as anything but an int32, that counted a
CRC32 CRAM 2 does not have, or that read the landmark count as part of the
blocks would not add up to the 30 bytes the specification says the marker
is long.

**The sibling fixture** `testdata/sample.cram` (a CRAM 3.1 file htsjdk
wrote, with eight reads on `chr1`) is recorded in `testdata/README.md`.
