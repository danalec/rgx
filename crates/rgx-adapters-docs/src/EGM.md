# rgx-adapters-docs/src

## Overview

The implementation of the long-tail adapters. Two adapters, both of which
delegate to a binary that is already on the machine:

- `Soffice` — LibreOffice headless, for MS Publisher (`.pub`). LibreOffice
  converts *to a file* in `--outdir` rather than to stdout, so the adapter
  points it at a scratch directory and reads the flat ODF back.
- `ProcAdapter` — a generic "pipe the bytes to a tool's stdin and capture its
  stdout" harness, used by `ocr()` (Tesseract). It owns the optional
  `preprocess` step that turns one input into the inputs the tool can
  actually read, and the optional `rasteriser` fallback for PDF pages that
  carry no picture of their own.

The file is one module: no submodules, no `std` feature (the crate spawns
processes), and two cargo features (`soffice`, `ocr`) that gate the two
adapters and the helpers only they use.

## Interface

- `pub fn adapters() -> Vec<Box<dyn Adapter>>` — the factory the binary's
  registry consumes. Returns `Soffice` (feature `soffice`) and `ocr()`
  (feature `ocr`) in that order; an adapter whose tool is missing reports
  `available() == false` and is skipped entirely — the file's own bytes are
  then searched raw, beside the note `[rgx: adapter 'x' skipped: its
  external tool is not on PATH]`.
- `pub struct Soffice` (feature `soffice`) — the LibreOffice adapter.
  `impl Adapter`: `name() == "soffice"`,
  `extensions() == &["pub"]`,
  `available() == which("soffice") || which("libreoffice")`.
- `pub fn ocr() -> ProcAdapter` (feature `ocr`) — the Tesseract adapter.
  Name `"ocr"`, binary `"tesseract"`, argv `["stdin", "stdout", "--psm", "3"]`,
  extensions `["ocr.jpg", "ocr.jpeg", "ocr.png", "ocr.tiff", "ocr.tif",
  "ocr.pdf"]`, timeout `DEFAULT_TIMEOUT`.
- `pub struct ProcAdapter` (feature `ocr`) — the subprocess harness. Private
  fields: `name`, `binaries` (candidate names, first hit on `PATH` wins),
  `args: fn(&str) -> Vec<String>` (informational — the data goes over stdin),
  `exts`, `post: fn(Vec<u8>) -> Vec<u8>` (optional post-processing of the
  captured stdout), `preprocess: fn(&[u8], Option<&str>) -> Option<Prepared>`,
  `timeout: Duration`, `rasteriser: Option<&'static str>`.
  `impl Adapter`: `name`, `extensions`, `available` (any candidate binary on
  `PATH`), `extract`.
- `pub struct Prepared` (feature `ocr`) — what a `preprocess` hook produced:
  - `pub inputs: Vec<Vec<u8>>` — the payloads the tool will be run on, one
    invocation each.
  - `pub skipped: Vec<String>` — what was found and *not* turned into an
    input, with the reason.
  - `pub notes: Vec<String>` — what the answer has to say about itself.
- Private helpers (not part of the contract): `which` / `which_uncached`
  (PATH probing with a process-lifetime cache), `temp_path`, `wait_with_timeout`,
  `drain`, `rasteriser`, `pages_of_a_pdf`, `rasterise_in`,
  `read_rasterised_pages`, `page_of`; constants `DEFAULT_TIMEOUT` (30 s),
  `RASTERISERS` (`["pdftoppm", "pdftocairo"]`), `RASTER_DPI` (300),
  `RASTER_TIMEOUT` (120 s), `IDENTITY`.

## Invariants

- A tool is spawned only when a matching file was found *and* the binary is
  on `PATH`; `available()` gates the adapter, and `extract()` re-checks the
  binary and fails with "binary vanished between detection and spawn" if it
  is gone.
- The `PATH` is assumed constant for the life of the process: each candidate
  binary is probed once and the verdict cached, because an uncached probe
  costs ~20 filesystem stats per adapter per file.
- The OCR adapter claims **only** double extensions (`*.ocr.*`). The dotted
  declaration is what makes the second component reachable at all:
  `extension_candidates` offers `scan.ocr.jpg` as `ocr.jpg` first and `jpg`
  second, so OCR runs before the media adapter that claims `jpg` alone.
- `preprocess` returning `Some` with **empty** `inputs` is a failure, not an
  empty decode: the adapter bails with the reason instead of handing the
  tool nothing.
- A PDF page becomes an input only when it can be turned into an image the
  tool can read: a `/DCTDecode` page hands over the JPEG its stored bytes
  already are, and a `/CCITTFaxDecode` or `/JBIG2Decode` page hands over a
  PNG the reader builds from the decoded scan. Anything else is reported by
  its filter rather than passed along to fail the same way a second time.
- A page that carries no picture at all (a page whose content is *drawn*) has
  nothing to hand over, so the page is rasterised by an external tool
  (`pdftoppm`, then `pdftocairo`). The rasteriser is asked for **only** when
  there is nothing else to hand over, and when the machine has none the
  answer says so rather than pretending the page was rendered.
- Every invocation is bounded by a wall-clock limit: 30 s per tool
  invocation, 120 s per rasterisation. A child that exceeds it is killed and
  the run fails.
- The child's stdout and stderr are drained on background threads while a
  third thread waits; leaving the pipes unread would let the child block on
  a full pipe buffer and never reach `wait()`.
- Empty stdout is a failure: either "produced no text", or "produced no
  text: <notes>" when there are notes.
- `soffice` converts to **flat ODF** (`fodg`), never `txt:Text`: LibreOffice
  imports MS Publisher as a *Draw* document, and Draw ships no text export
  filter, so the `txt` target aborted before writing a byte and the adapter
  could never return text for the one extension it owns. The office crate
  already owns the XML → text pass over the flat ODF.
- The facts the answer cannot show are written down: notes are appended to
  the answer as `[rgx: ocr: ...]` lines, and a page that was not rasterised
  is named rather than silently dropped.

## Side Effects

- Spawns child processes: `soffice`/`libreoffice`, `tesseract`, and
  `pdftoppm`/`pdftocairo`. The OCR tool's stdin, stdout and stderr are
  piped, and its stdin is the one that receives the payload bytes.
  `soffice` gets a null stdin, stdout and stderr — its payload is handed
  over as a file — and the rasteriser gets a null stdin and stdout but a
  **piped** stderr, because the failure reason is read back from it.
- Writes scratch files under `std::env::temp_dir()`, named
  `rgx-<pid>-<nanoseconds>`: the source copy handed to `soffice`, the
  `soffice` output directory, the `input.pdf` given to the rasteriser and
  the `page-<n>.png` files it writes.
- Removes what it wrote: the source copy, the flat ODF and the output
  directory for `soffice`; the work directory (and therefore every PNG in
  it) for the rasteriser. **The rasteriser removes its directory on every
  failure path; the `soffice` adapter does not** — a spawn or a wait
  failure returns before the cleanup and leaves the source copy and the
  output directory on disk.
- Kills a child process that outlives its timeout.
- Reads the `PATH` and the filesystem to locate binaries; caches the verdict
  for the process lifetime. No network access, no locks.

## Verification

- Run: `cargo test --release --locked --workspace`
