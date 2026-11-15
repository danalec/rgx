# rgx-adapters-docs

The only crate that shells out. It holds the adapters that delegate to
binaries already on the machine; every other crate in the workspace is
in-process. Each adapter probes `PATH` in `available()` and is skipped
entirely when the binary is missing, so a minimal machine still gets the
full in-process adapter set. Nothing is spawned unless a matching file is
actually found.

## What it claims

| adapter | extensions | needs |
|---|---|---|
| `soffice` | pub | `soffice` or `libreoffice` on `PATH` |
| `ocr` | ocr.jpg, ocr.jpeg, ocr.png, ocr.tiff, ocr.tif, ocr.pdf | `tesseract` on `PATH`, and `pdftoppm` or `pdftocairo` for a PDF whose pages are drawn |

`soffice` claims a single extension on purpose: the rest of the
legacy-office family is read in-process by the office crate, and MS
Publisher is the one format nothing else reads.

`ocr` claims **dotted** extensions, which is what keeps it off ordinary
photos. `extension_candidates` offers `scan.ocr.jpg` as `ocr.jpg` first and
`jpg` second, so an adapter may name a multi-component extension and still
lose to nothing: the more specific claim runs first, and a `Bail` from it
falls through to whatever claims the plain extension. With the declarations
removed the mechanism reverts to `rgx_core::extension_of`, which resolves
only the last dot — and this adapter becomes unreachable code that still
compiles and still ships.

Image metadata (`.jpg`, `.jpeg`, `.png`, `.webp`, `.tif`, `.tiff`), the
legacy `.doc` compound file and X.509 certificates are read in-process too —
by the media, office and inspect crates, the last through a hand-rolled DER
walker. None of them needs a binary on `PATH`.

## How it works

Bytes go to the tool in a scratch directory and come back as text; nothing is
passed to a shell. `soffice` is the only adapter, and it is also the exception
to the stdin/stdout shape: it converts to a file in `--outdir` rather than to
stdout, writes into a scratch directory and reads the result back.

That result is **flat ODF** (`fodg`), not plain text. LibreOffice imports MS
Publisher as a *Draw* document, and Draw ships no text export filter at all —
a `txt:Text` target aborts with `no export filter ... found` before writing a
byte, which is why this adapter claimed `pub` and could never answer for it.
`fodg` is the one Draw export that is plain XML, and it is handed to the
office crate's `xml_to_text`, the tree's only XML → text pass. That is the
crate's single workspace dependency, and it is compile-time only: the office
adapters themselves still reach the registry through the root's own
`adapters-office` feature.

`PATH` probes are memoised per process. Without that cache `available()`
costs filesystem stats per adapter per file, which dominated whole-corpus
searches.

Every invocation is bounded by a 30-second wall clock — 120 seconds for the
rasteriser, which is one call for the whole document. The child's pipes
are drained on background threads — leaving them unread would let a child
block on a full buffer and never exit — and the child is killed if the
deadline passes first. A tool that exits non-zero or produces no text
declines with `bail!`, so the pipeline falls through to the next adapter.

## Licence

Apache-2.0 only. See [LICENSE-APACHE](https://github.com/danalec/rgx/blob/main/crates/rgx-adapters-docs/LICENSE-APACHE), and the
repository's [COPYING](https://github.com/danalec/rgx/blob/main/COPYING) for what the licence covers and what
it does not.