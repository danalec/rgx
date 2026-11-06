# rgx-adapters-mail

E-mail adapters. Message bodies become searchable text; MIME attachments
become `Outcome::Members`, so the pipeline recurses into them with the
full adapter chain and a PDF attachment is still a PDF.

## What it claims

| adapter | extensions |
|---|---|
| `mbox` | mbox, mbx |
| `eml` | eml |
| `msg` | msg |
| `emlx` | emlx |
| `pst` | pst, ost |
| `wab` | wab |
| `mmdf` | mmdf |
| `msf` | msf |
| `mailbox-index` | mboxindex |

All of them declare `Reach::Reveal`. A message archive is not text
ripgrep reads on its own.

## How it works

`parse_message` works on `&[u8]` throughout: header parsing, boundary
detection and base64 payload decoding all stay in byte space until the
final body string is built, rather than copying each header block into a
`String` first. It looks for the RFC-822 separator in both its CRLF and
its bare-LF spelling.

`mbox` sanity-checks that the first line is a `From_` line before
splitting the archive. The split is over **bytes**: the archive used to be
decoded as UTF-8 first, so every byte above 0x7F in every message was
U+FFFD before a single message was separated, and no per-message charset
could get them back. `msg` reads the Outlook compound file through the
shared CFB reader. `emlx` stops at the end of the RFC-822 part and reads
the trailer that follows it. `pst` parses the PST container: it walks the
NBT for every node, reads each node's property context through the HN heap,
and joins the folder tree on NBTENTRY's `nidParent`. That last field is not
cosmetic — in every store measured, each `bidSub` is zero, so a walk that
followed subnode lists reached the root folder and stopped there, reporting
a forty-folder mailbox as empty.

**The encoding a message declares is the encoding it is read in.** A MIME
part's `charset=` goes through `rgx-core::charset`, and a header's RFC 2047
encoded-word (`=?UTF-8?B?...?=`) is decoded too — the subject is the most
valuable line in a message, and undecoded it is a base64 blob. Reading
either as UTF-8 regardless does not read the bytes differently, it replaces
every byte above 0x7F with U+FFFD, and the character is gone from the
answer. A part that declares nothing is read leniently instead: valid UTF-8
as it is, anything else as Latin-1, which keeps every byte.

An `.ost` travels this exact path. [MS-PST] gives the offline and the personal
store the same NDB layer and the same two B-trees, and the header agrees:
`wMagicClient` is 0x4F53 ("SO") rather than 0x4D53 ("SM"), and the parser
accepts both. What the one public `.ost` fixture lacks is a tree, not a format.
Its ROOT passes every header check and then places BREFNBT.ib at 577,536 and
BREFBBT.ib at 413,696 — both above its own `ibAMapLast` of 139,264, which is the
allocation map saying those pages were never written. The file is 99.6% zero
holes past byte 712,699 and carries no BTPAGE anywhere: a scanner that finds
1170 of them in a real 28.9 MB PST finds none in it. So the adapter declines,
and names which of the two things is missing — "no node database is allocated",
not a node.

`wab` reads Windows Address Book files as OLE Compound File containers:
the adapter validates the CFB magic and sector size, walks the directory
entries to enumerate streams (`__SUBRECORD__*`, `Properties`, `Summary`),
and falls back to printable-run extraction over the data sectors so a
search for a contact name or email still finds it. Decoding each
`__SUBRECORD__` stream into a `name <tab> email` line would mean a full
MAPI property parser; that is out of scope, so the adapter emits the
strings and lets the searcher do the matching.

## Feature flags

`default` is `std` and the nine mailbox formats (`mbox`, `eml`, `msg`, `emlx`,
`pst`, `wab`, `mmdf`, `thunderbird`, `apple-mailbox`). The `std` feature
re-enables the `std::error::Error` impl on `PstErr`; the gate exists so the
crate stays buildable as `no_std` + `alloc` without it.

## Licence

Apache-2.0 only. See [LICENSE-APACHE](https://github.com/danalec/rgx/blob/main/crates/rgx-adapters-mail/LICENSE-APACHE), and the
repository's [COPYING](https://github.com/danalec/rgx/blob/main/COPYING) for what the licence covers and what
it does not.
