# rgx-adapters-mail/src

## Overview

The implementation of the e-mail family. `lib.rs` holds the crate's
`no_std` shell, the `adapters()` factory and the MIME machinery; the other
modules hold one container family each.

The design point the whole crate is built on: **message bodies become
searchable text, MIME attachments become members**. An `.eml` yields a
`message.txt` unit plus one member per attachment, and the pipeline then
walks those members through the whole adapter chain, so a PDF attachment is
still read by the PDF adapter. An mbox instead keeps its messages inline —
the manifest keeps the mbox a single searchable unit — and says so in its
own output.

## Interface

Only `wab` is a public module; the readers of `extra`, `pst` and `variants`
are crate-internal and no item of theirs is nameable from outside the
crate.

- `pub fn adapters() -> Vec<Box<dyn Adapter>>` — the factory the binary's
  registry consumes, in feature order: `Mbox`, `Eml`, `extra::Msg`,
  `extra::Emlx`, `pst::PstAdapter`, `wab::Wab`, `variants::Mmdf`,
  `variants::ThunderbirdMsf`, `variants::AppleMailboxIndex`.
- `pub struct Mbox` (feature `mbox`) — `impl Adapter`: `name() == "mbox"`,
  `extensions() == &["mbox", "mbx"]`. Also implements `facts()`: the first
  message's headers, `mail.messages` (how many messages the box holds) and
  `has.attachments` (the attachment count of the whole box, reported only
  when it is non-zero).
- `pub struct Eml` (feature `eml`) — `impl Adapter`: `name() == "eml"`,
  `extensions() == &["eml"]`. Also implements `facts()`: the message's
  headers and `has.attachments`.
- `pub struct extra::Msg` (feature `msg`, crate-internal) — Outlook `.msg`:
  MAPI properties stored as named streams inside a CFB. `impl Adapter`:
  `name() == "msg"`, `extensions() == &["msg"]`. Reads subject, body (ANSI
  or UTF-16) and the attachment inventory; it does not extract sender or
  recipient itself. `pst::PstAdapter` resolves `PROP_SENDER_NAME`,
  `PROP_SENDER_EMAIL` and `PROP_DISPLAY_TO` into `from:` / `to:` lines, and
  `header_facts` reports `mail.from` / `mail.to` for `Eml` and `Mbox`
  (`facts()` on both).
- `pub struct extra::Emlx` (feature `emlx`, which implies `eml`,
  crate-internal) — Apple Mail `.emlx`: an RFC-822 message followed by
  `\n<message-count>\n` and a binary plist. `impl Adapter`: `name() ==
  "emlx"`, `extensions() == &["emlx"]`.
- `pub struct pst::PstAdapter` (feature `pst`, which implies `std`,
  crate-internal) — Outlook Personal Storage Table / Offline Storage
  Table. `impl Adapter`: `name() == "pst"`, `extensions() == &["pst",
  "ost"]`.
- `pub struct wab::Wab` (feature `wab`) — Windows Address Book. `impl
  Adapter`: `name() == "wab"`, `extensions() == &["wab"]`.
- `pub struct variants::Mmdf` (feature `mmdf`, crate-internal) — `impl
  Adapter`: `name() == "mmdf"`, `extensions() == &["mmdf"]`.
- `pub struct variants::ThunderbirdMsf` (feature `thunderbird`,
  crate-internal) — `impl Adapter`: `name() == "msf"`, `extensions() ==
  &["msf"]`.
- `pub struct variants::AppleMailboxIndex` (feature `apple-mailbox`,
  crate-internal) — `impl Adapter`: `name() == "mailbox-index"`,
  `extensions() == &["mboxindex"]`.
- `pub mod wab` — the WAB reader is a public module, and it carries its
  **own** CFB parser (it imports only `rgx_core::{bail, decline}` and
  `rgx_core::{Adapter, Outcome, Result}`). It is the `.msg` reader that
  uses the shared `rgx_core::cfb::Cfb`.

## Invariants

- The crate is `#![no_std]` + `alloc` by default. The `std` feature exists
  only for the `std::error::Error` impl on `PstErr`; every family but `pst`
  is pure byte slicing and needs no `std` at all.
- Every adapter sits behind a Cargo feature named after the format it
  reads; the default build carries all of them. `emlx` implies `eml`,
  because the `.emlx` reader strips the trailer and hands the message to
  the `eml` adapter.
- **An mbox is split over bytes, not over a decoded string.** The previous
  shape read the whole file as `from_utf8_lossy` and split *that*, so every
  byte above 0x7F in every message was already U+FFFD before a single
  message was separated — and no per-message charset could recover it,
  because the bytes were gone. A latin-1 mbox lost its accented characters
  at the one point where they were still on the disk.
- A `Reveal` adapter's output is the only view of the file there is, so a
  loss at the split is a loss in the corpus.
- The MIME machinery stays in byte space until the final body string is
  built: header parsing, boundary detection and base64 payload decoding all
  operate on `&[u8]`. A per-message `charset=` is honoured when the
  message declares one.
- An mbox's first line must be a `From ` line; anything else is declined.
  The `From ` line of the *first* message is kept in that message's text.
- Attachments inside an mbox's messages stay inline — the manifest keeps
  the mbox a single searchable unit — and full MIME recursion is available
  on single `.eml` files, where the body is `message.txt` and each
  attachment is a member named `<index>-`.
- A fact is reported only when it is true of the file: `has.attachments` is
  emitted only when the message (or box) really has attachments, because a
  question whose answer is always yes is not a question. A box reports the
  *first* message's headers — the box's own convention for who it is from
  — plus `mail.messages`, so one `mail.from` is not passed off as the
  sender of every message in the file.
- An adapter declines a file it does not recognise (bad magic, wrong shape)
  rather than answering. The Thunderbird index declines the pre-version-78
  Berkeley DB format instead of guessing at it; the Apple mailbox index
  declines anything that is not a `bplist00`.
- The MMDF reader splits on its own four-byte attribute separator
  (`00 00 00 01`), not on `From ` lines, and declines a file that does not
  start with the MMDF file header (`01 00 01 0C`).
- The Thunderbird index requires a bare integer version line on its first
  line and folds continuation lines (those starting with a space) into the
  value above them.
- The PST reader is hand-rolled per [MS-PST] and cross-checked against
  Microsoft's `outlook-pst-rs`: Unicode (v23) and ANSI (v14/15) databases,
  NBT/BBT page trees, data trees (XBLOCK/XXBLOCK), subnode trees,
  heaps-on-node, BTH indices, property and table contexts, and all three
  block encodings (none / permute / cyclic).
- **Page CRCs and block signatures are not enforced** on purpose, so lightly
  damaged files still yield text.
- The WAB reader walks the CFB entirely in Rust — no C, no subprocess — and
  reads the MAPI property streams by their low-16-bit type
  (`PT_STRING8` = 0x1E, `PT_UNICODE` = 0x1F, `PT_BINARY` = 0x102) and
  high-16-bit identifier (`PR_DISPLAY_NAME` = 0x3001,
  `PR_EMAIL_ADDRESS` = 0x3003).
- The `.msg` reader locates its properties by stream-name suffix
  (`_0037001F`/`_0037001E` for the subject, `_1000001F`/`_1000001E` for the
  body) and builds the attachment inventory from every directory entry whose
  name contains `__attach`, taking the displayed names from the
  `_3707001F`/`_3001001F` streams inside them.
- The Apple Mail `.mboxindex` is reported as an *index*, not a mailbox: the
  mbox it points at is the file rgx already reads.

## Side Effects

- None. Every adapter is a pure function over `&[u8]`: nothing here reads
  the filesystem, consults the clock or the environment, opens a socket,
  spawns a process or takes a lock. The crate allocates through `alloc`.

## Verification

- Run: `cargo test --release --locked --workspace`
