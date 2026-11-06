# crates

## Overview

`crates/` holds the workspace's twelve libraries: the engine, the RAR
codec, and the ten adapter families that turn a file into searchable
text. Every adapter is written against the `Adapter` trait the engine
defines, and the engine owns the walk, the recursion and the caps that
turn an answer into units. Every crate of the workspace is a path dependency
inside this tree; the external crates the crates here reach for are the ones
`scripts/check-vendoring.sh` enumerates and enforces.

## Subdirectories & Boundaries

- `rar-codec`: [rar-codec](./rar-codec/EGM.md) — `rar-codec` is the pure-Rust RAR container codec that `rgx` uses for `.rar` extraction, kept as its own crate so the container walk and the decompression algorithms can be exercised on their own instead of through the search pipeline.

- `rgx-adapters-archive`: [rgx-adapters-archive](./rgx-adapters-archive/EGM.md) — `rgx-adapters-archive` is the adapter family that opens archives and compressed streams so their contents can be searched. Every adapter is a synchronous function over a byte slice: no subprocess, no mount, no loop device, no privileges.

- `rgx-adapters-docs`: [rgx-adapters-docs](./rgx-adapters-docs/EGM.md) — The long-tail adapter family of `rgx`: the only family in the tree whose answers come from **external binaries** rather than from in-process readers.

- `rgx-adapters-inspect`: [rgx-adapters-inspect](./rgx-adapters-inspect/EGM.md) — The forensic-triage family of `rgx`: an always-in-process adapter set that never trusts a file's extension, never spawns a subprocess and never ships a heavyweight parser.

- `rgx-adapters-llm`: [rgx-adapters-llm](./rgx-adapters-llm/EGM.md) — The machine-learning model family of `rgx`. Its adapters never extract weights — a multi-GB payload of floats is useless to a text search — they extract *metadata*: tensors, shapes, hyperparameters, architecture strings, vocabularies.

- `rgx-adapters-mail`: [rgx-adapters-mail](./rgx-adapters-mail/EGM.md) — The e-mail family of `rgx`. Message bodies become searchable text; MIME attachments become `Outcome::Members` so the pipeline recurses into them with the full adapter chain — a PDF attachment is still a PDF.

- `rgx-adapters-media`: [rgx-adapters-media](./rgx-adapters-media/EGM.md) — The media-metadata family of `rgx`. Heavy binary payloads — pixels, waveforms, media streams — are never extracted; only the metadata is.

- `rgx-adapters-office`: [rgx-adapters-office](./rgx-adapters-office/EGM.md) — The office / OpenDocument / e-book family of `rgx`, fully in-process: no external tool is ever spawned for these formats.

- `rgx-adapters-pdf`: [rgx-adapters-pdf](./rgx-adapters-pdf/EGM.md) — The PDF family of `rgx`: an in-process text extractor, fully in-process (no subprocess, no external tool), and the only adapter in the tree that carries its own security handler.

- `rgx-adapters-tabular`: [rgx-adapters-tabular](./rgx-adapters-tabular/EGM.md) — The tabular / geospatial / database family of `rgx`. Its premise is on the crate's own header: **databases are dumped as grep-friendly TSV (schema + rows) rather than queried** — the whole point is making them greppable, not serving SQL.

- `rgx-adapters-threed`: [rgx-adapters-threed](./rgx-adapters-threed/EGM.md) — The 3D / point-cloud / volumetric family of `rgx`. Its premise is on the crate's own header: **extract structure and names, not geometry payloads**.

- `rgx-core`: [rgx-core](./rgx-core/EGM.md) — The engine crate of the `rgx` workspace.
