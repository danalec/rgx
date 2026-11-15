# rgx-adapters-mail

## Overview

The e-mail family of `rgx`. Message bodies become searchable text; MIME
attachments become `Outcome::Members` so the pipeline recurses into them with
the full adapter chain — a PDF attachment is still a PDF.

The family covers the formats mail actually lives in: mbox archives (and the
MMDF variant), single `.eml` messages, Apple Mail `.emlx` files, Outlook
`.msg` (OLE2/CFB), Outlook PST/OST stores, Windows Address Book `.wab`
files, Thunderbird's per-folder `.msf` index, and Apple's `.mboxindex`.

The crate is `#![no_std]` + `alloc` by default and declares a `std` feature
of its own: the only thing `std` buys is the `std::error::Error` impl on
`PstErr`, and the `pst` feature requires it. Every other family is pure
byte slicing and needs no `std` at all. Each adapter sits behind a Cargo
feature named after the format it reads, and the default build carries all
of them.

## Subdirectories & Boundaries

- `src`: [src/EGM.md](./src/EGM.md) — the whole implementation: the
  `adapters()` factory and the MIME machinery (`Mbox`, `Eml`) in `lib.rs`,
  the Outlook/Apple readers in `extra.rs`, the hand-rolled PST/OST reader in
  `pst.rs`, the mailbox variants and the Thunderbird index in `variants.rs`,
  and the Windows Address Book reader in `wab.rs`. Public symbols: `pub fn
  adapters()`, `pub struct Mbox`, `pub struct Eml`, `pub mod wab` (`pub
  struct wab::Wab`), and `impl Adapter` for each adapter. The readers of
  the private modules — `extra::Msg`, `extra::Emlx`, `pst::PstAdapter`,
  `variants::Mmdf`, `variants::ThunderbirdMsf` and
  `variants::AppleMailboxIndex` — are crate-internal and are not nameable
  from outside the crate.
