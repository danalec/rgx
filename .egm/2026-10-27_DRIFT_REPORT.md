# Drift report -- the EGM contracts of `rgx`

The contracts the bootstrap wrote are checked against the code they
describe. Only the differences are reported; a contract with nothing
wrong with it says so and nothing else.
## src/EGM.md

- **`mmap.rs` is not a module beside `main.rs`.** The Overview lists `mmap.rs` among "the modules beside `main.rs` ... `mmap.rs` decides read-versus-map for a file's bytes", and the `### mmap.rs` section presents its symbols as the package's public surface. `src/main.rs:23-30` declares `mod cache; mod cli; mod detector; mod engine; mod pick; mod rc; mod type_db; mod walk;` — there is no `mod mmap;`. The file is compiled as `crate::engine::mmap` through `#[path = "mmap.rs"] pub(crate) mod mmap;` at `src/engine.rs:40-41`, whose header states it is declared from `engine.rs` "rather than from the crate root because `main.rs` is not this module's to edit". So every symbol the contract lists (`MAP_THRESHOLD`, `AUTO_MMAP_THRESHOLD`, `worth_mapping`, `should_map`, `enabled_by_env`, `MappedFile`) lives at `engine::mmap::...` and the module is `pub(crate)`, not `pub` at the crate root.
- **`Mode::from_env()` does not reject the retired names.** The contract says it "reads `RGX_ENGINE` and rejects the retired names". `src/engine.rs:155-184` warns once on stderr for `grep`/`both` and then returns `Mode::Rgx`; the run continues. The engine's own doc (`src/engine.rs:145-154`) says the opposite of "rejects": "the names are recognised *as retired* and reported, and the run continues — an ambient variable should not be able to fail a search that would otherwise have succeeded."
- **"The tally is printed once ... printed on the way out of `main`" is not what the code does.** The search path prints the tally inside `run()` at `src/main.rs:7795`, whose comment (`src/main.rs:7792-7794`) reads "Reported here as well as in `main`: ... the exit status ... leaves through `process::exit`, which does not run the tail of `main`", and `run()` ends at `src/main.rs:7814` with `std::process::exit(...)`. The copy in `main` (`src/main.rs:6941`) therefore never executes for a search — the tally the user sees comes from `run()`, not from the way out of `main`.
- **The engine tally is not printed unconditionally.** `engine::stats::report()` returns immediately unless `EXPLICIT` is set (`src/engine.rs:216-219`), and `EXPLICIT` is set only when `RGX_ENGINE=rgx` is seen (`src/engine.rs:157-161`). The Side Effects section states stderr carries "the engine tally" with no such precondition; by default no tally line is printed at all.
- **`pub enum Event { Match, Context, Other, Finish }` — the variants carry payloads.** The code is `Match(Option<u64>, Vec<u8>)`, `Context(Option<u64>, Vec<u8>)`, `Other(Option<u64>, Vec<u8>)`, `Finish(Option<u64>)` (`src/engine.rs:446-451`).
- **`binary_detection(&self) -> RgxBinaryDetection` is listed as a `Searcher` method without qualification.** In the code it is `#[cfg(test)] pub fn binary_detection(&self) -> RgxBinaryDetection` (`src/engine.rs:323-324`) — it does not exist in a release build.
- **`TypeFilter::accepts(&Path) -> bool` is listed as interface.** In the code it is `#[cfg(test)] pub fn accepts(&self, path: &Path) -> bool` (`src/walk.rs:134-135`), so it is absent from a non-test build.
- **`run()`'s dispatch order is incomplete.** The contract's list ("shell completions, `--serve`, `--mcp`, cache clear/prune, `--type-list`, pack-store build, token-index build, facts-index build/export, then the search itself") omits the `--tv-verify` branch, which sits between the pack-store build and the token-index build (`src/main.rs:7741-7749`), and the `--index-dir` query branch, which sits between the token-index build and the facts-index build (`src/main.rs:7752-7754`, `query_with_index` at `src/main.rs:7445`).

## src/cli/EGM.md

- **`AppSettings`, `ParseError` and `parse_args` are not reachable from the `cli` module.** The contract lists them as the layer's interface, but `src/cli/mod.rs:23-27` re-exports only `App`, `Arg`, `generate_completion`, `Shell`, `ArgMatches` and `ErrorKind`; `AppSettings` lives in the private `mod app` (`src/cli/app.rs:16`), `ParseError` and `parse_args` in the private `mod parser` (`src/cli/parser.rs:44`, `src/cli/parser.rs:57`). `cli::AppSettings`, `cli::ParseError` and `cli::parse_args` are not nameable paths — `main.rs` itself imports only the six re-exported names (`src/main.rs:32`).
- **"a self-contained, `std`-only module with five files"** — `src/cli/` contains six Rust files: `app.rs`, `arg.rs`, `completion.rs`, `matches.rs`, `parser.rs` and `mod.rs`.
- **"Every completion script is a pure function of the `App` table, so a flag cannot be missing from a script without the table missing it too" is contradicted by hidden arguments.** All four generators build their option list from `options(app)` (`src/cli/completion.rs:142`, `220`, `325`, `373`), and `options()` filters them: `app.args.iter().filter(|a| !a.hidden)` (`src/cli/completion.rs:120`). A flag that is in the table but marked `hidden` — the attribute whose own doc says it "Keeps the argument out of the help text and the completions" (`src/cli/arg.rs:93-95`) — is absent from every script while still being in the table.
- **Two builder methods have undocumented side effects.** `Arg::optional_value` also sets `takes_value = true` (`src/cli/arg.rs:74-77`) and `Arg::multiple` also sets `takes_value = true` (`src/cli/arg.rs:115-118`); the contract's builder list describes both as plain setters.

## crates/rar-codec/EGM.md

- **Blocker** — The claim "all with CRC-32 verification" (line 18) is not what the code does for RAR 4.x: the RAR4 header CRC is read but deliberately *not enforced*, and only the member *data* CRC is checked at extract time. `crates/rar-codec/src/read.rs:868` takes `_verify_crc: bool` and never uses it; `crates/rar-codec/src/read.rs:880-883` states "the RAR 4.x header CRC … is read but not enforced. The data CRC of a member is enforced at extract time." The only header CRC actually verified is the RAR5 one (`crates/rar-codec/src/read.rs:664-665`, `BadCrc("rar5 header")`).
- **Blocker** — The claim "the RAR 7.x compression algorithm (version 1) are reported as `Error::Unsupported` rather than guessed at" (lines 21-23) is not implemented anywhere. `compression_version` is parsed and stored (`crates/rar-codec/src/read.rs:810`, `crates/rar-codec/src/read.rs:844`, field declared at `crates/rar-codec/src/read.rs:134`) but never inspected: the extract path dispatches on `entry.method` only (`crates/rar-codec/src/read.rs:340-351`), and every `Error::Unsupported` site in the crate is one of `encrypted payload`, `member spans volumes`, `unknown RAR4 compression method`, `PPMd filters`, `RAR VM program filter`, `unknown filter type` (`crates/rar-codec/src/read.rs:321`, `:330`, `:503`; `crates/rar-codec/src/unpack3.rs:600`, `:1145`; `crates/rar-codec/src/unpack.rs:702`). A version-1 member would fail inside the RAR5 decoder with `Malformed`/`Truncated`, not `Unsupported`.

## crates/rar-codec/examples/EGM.md

No drift detected.

## crates/rar-codec/src/EGM.md

- **Blocker** — "Archive::open(data: &[u8]) -> Result<Self> parses one volume strictly (every header CRC32 verified)" (line 27) contradicts the RAR4 path: `crates/rar-codec/src/read.rs:868` ignores the `verify_crc` flag for RAR4 and `crates/rar-codec/src/read.rs:880-883` says the header CRC is "read but not enforced". Strictness is real only for RAR5 (`crates/rar-codec/src/read.rs:664-665`).
- **Nit** — "Archive::open_lenient(data: &[u8]) -> Result<Self> parses without the header checks" (line 27) has no effect on RAR4: `crates/rar-codec/src/read.rs:868` never reads `_verify_crc`, so `open` and `open_lenient` behave identically for a RAR4 volume.
- **Blocker** — "`Unpacker3` likewise verifies the CRC-32 of the decoded member" (line 49) is false. `Unpacker3::finish_member` (`crates/rar-codec/src/unpack3.rs:762-781`) checks filter completion and the member byte count, and performs no checksum at all; the only `crc32` use in that module is the VM-program fingerprint (`crates/rar-codec/src/unpack3.rs:1119`). The member CRC-32 is verified one level up, in `Archive::extract` (`crates/rar-codec/src/read.rs:352-356` and `crates/rar-codec/src/read.rs:520-524`).
- **Major** — "Allocates: the LZ window (rounded up to a power of two, at least 64 KiB, at most the 4 MiB RAR3 dictionary ceiling)" (line 54) states a ceiling the RAR5 path does not have. `Unpacker::new` takes `dict_size.max(64 * 1024)` and rounds it up to the next power of two with no upper bound (`crates/rar-codec/src/unpack.rs:121-126`), and the RAR5 dictionary size comes from the header as `128 * 1024 << dict_exp.min(30)` (`crates/rar-codec/src/read.rs:813`) — up to 128 GiB. The 4 MiB cap is RAR3/RAR4-only (`crates/rar-codec/src/unpack3.rs:85` `DICTIONARY_MAX_SIZE = 0x40000 * 16`; `crates/rar-codec/src/read.rs:436` `RAR4_MAX_WINDOW`).
- **Major** — The Interface section enumerates every field of `Entry` but omits `Archive`'s four public fields, which are part of the crate's public surface and are readable by any caller: `format: Format`, `encrypted: bool`, `multivolume: bool`, `volume_number: Option<u64>` (`crates/rar-codec/src/read.rs:223-231`).

## crates/rgx-adapters-archive/EGM.md

- **Blocker** — "Every adapter declares `Reach::Reveal`" (lines 28-30) is contradicted by `SvnDump`, which declares `Reach::Render` (`crates/rgx-adapters-archive/src/backups.rs:82-84`) and `reach_needs_bytes() -> true` (`crates/rgx-adapters-archive/src/backups.rs:85-87`). It is the only adapter in the crate that overrides `reach` at all — every other adapter takes the trait default (`crates/rgx-adapters-archive/src/lib.rs:44-108`).
- **Nit** — "the block-image containers (VHD, VHDX, QCOW2, VMDK, VDI, WIM, EROFS, APFS/HFS+)" (line 17) mis-classifies WIM: `Wim` parses the WIM XML metadata header and returns a text report, not a block-image geometry (`crates/rgx-adapters-archive/src/images.rs:1467-1528`). This also contradicts the crate's own `src/EGM.md`, which lists WIM among the catalogue filesystems that "hand back real members".

## crates/rgx-adapters-archive/examples/EGM.md

- **Major** — "Neither writes a file, spawns a process, takes a lock or opens a socket" (line 39) is false: `decomp_bench` implements a `--dump <path>` option that writes the decoded output to disk (`crates/rgx-adapters-archive/examples/decomp_bench.rs:41` parses it, `crates/rgx-adapters-archive/examples/decomp_bench.rs:99-101` calls `std::fs::write(d, &out)`). The flag is also missing from the Interface bullet (line 25) and from the usage line the contract quotes, so the documented command line does not match the program's.

## crates/rgx-adapters-archive/src/EGM.md

- **Major** — "Filesystems with a catalogue (ISO 9660, SquashFS, WIM) hand back real members and are a `Reach::Reveal`" (line 59) is false for WIM: `Wim::extract` returns `Outcome::Text` built from the XML metadata header (`crates/rgx-adapters-archive/src/images.rs:1467`, `crates/rgx-adapters-archive/src/images.rs:1528`). Only `Iso9660` (`crates/rgx-adapters-archive/src/images.rs:439`) and `Squashfs` (`crates/rgx-adapters-archive/src/squashfs.rs:575`) return `Outcome::Members`.
- **Nit** — "`pub mod budget`" (line 36) is presented as unconditionally public, but the module is gated on `feature = "std"` (`crates/rgx-adapters-archive/src/lib.rs:43-44`); the Side Effects claim that "budget.rs reads two environment variables" (line 64) therefore does not exist in a `--no-default-features` build.
- **Nit** — "(the byte one takes a plain count or a `k`/`m`/`g` suffix)" (line 64) implies only `RGX_MAX_MEMBER_BYTES` accepts a suffix; both variables go through the same `parse_size` (`crates/rgx-adapters-archive/src/budget.rs:99-107` and `crates/rgx-adapters-archive/src/budget.rs:113-126`), so `RGX_MAX_MEMBERS` takes `k`/`m`/`g` too.
- **Nit** — "`budget::testing::locked` / `budget::testing::under_budget`" (line 64) is described as part of the module's surface, but `testing` is `pub(crate)` (`crates/rgx-adapters-archive/src/budget.rs:360`, `:372`, `:380`), so neither helper is reachable from outside the crate.

## crates/rgx-adapters-archive/src/brotli/EGM.md

No drift detected.

## crates/rgx-adapters-archive/src/lz4/EGM.md

No drift detected.

## crates/rgx-adapters-archive/src/sevenz/EGM.md

No drift detected.

## crates/rgx-adapters-docs/EGM.md

No drift detected.

## crates/rgx-adapters-docs/src/EGM.md

- The contract's Side Effects claim "A failure path removes the directory it created before returning" is false for the `soffice` adapter: `cmd.spawn()` (`crates/rgx-adapters-docs/src/lib.rs:409`) and `wait_with_timeout()` (`crates/rgx-adapters-docs/src/lib.rs:410`) both return early with `?`, leaving the source copy (`src`) and the output directory (`outdir`) on disk; only the rasteriser removes its directory on every failure path (`crates/rgx-adapters-docs/src/lib.rs:591`, `:611`, `:621`).
- The Side Effects claim "Their stdout and stderr are piped (or sent to null for `soffice` and the rasteriser) and the child's stdin receives the payload bytes" misstates two of the three: the rasteriser's **stderr is piped**, not null (`crates/rgx-adapters-docs/src/lib.rs:607` — only its stdout is null, `:606`), because the failure reason is read back from it (`crates/rgx-adapters-docs/src/lib.rs:628`); and `soffice`'s **stdin is null** (`crates/rgx-adapters-docs/src/lib.rs:406`), its payload being handed over as a file — only the OCR tool receives the bytes on stdin.

## crates/rgx-adapters-inspect/EGM.md

- The Overview claims the crate "is part of the `no_std` port", but the manifest enables `rgx-core`'s `std` feature unconditionally (`crates/rgx-adapters-inspect/Cargo.toml:26`: `default-features = false, features = ["std", "sha256-hw"]`), and that feature pulls `dep:libc` and `memchr/std` (`crates/rgx-core/Cargo.toml:42`) — so the crate's dependency graph always contains `std` and it cannot be built for a target without it.

## crates/rgx-adapters-inspect/src/EGM.md

- The `magic_classify` label list names `pcx`, `riff` and `neson`, but the function never returns any of them — the body (`crates/rgx-adapters-inspect/src/lib.rs:907`–`:1019`) has no branch for those three magics; the list was copied from the function's own doc comment (`crates/rgx-adapters-inspect/src/lib.rs:905`–`:906`).
- The same list omits `cfb` and `macho`, both of which the function does return (`crates/rgx-adapters-inspect/src/lib.rs:978`, `:981` for `cfb`; `crates/rgx-adapters-inspect/src/lib.rs:988` for `macho`).
- The invariant "returns `Outcome::Bail("no embedded structures, raw binary semantics")` when nothing was found" overstates the code: the bail fires only for the nine generic extensions (`bin|dat|raw|img|rom|blob|payload|scratch|fw`, `crates/rgx-adapters-inspect/src/lib.rs:875`–`:883`); `objbin`, `exe`, `dll`, `sys`, `drv`, `efi`, `mui`, `ocx`, `cpl`, `apk` and `msi` get the structural report instead (`crates/rgx-adapters-inspect/src/lib.rs:870`–`:874`).
- The "`Inspect` is bounded" invariant omits the total carve budget: `CARVE_TOTAL_MAX` caps all carved bytes at 16 MiB (`crates/rgx-adapters-inspect/src/lib.rs:780`), which is the bound the code's own comment calls the architectural fix for the unbudgeted carve pass (`crates/rgx-adapters-inspect/src/lib.rs:764`–`:767`).

## crates/rgx-adapters-llm/EGM.md

- The "Public symbols" list names `pub struct extra::KerasZip`, `pub struct extra::Torch` and `pub struct extra::PickleStrings`, but `mod extra;` is private (`crates/rgx-adapters-llm/src/lib.rs:113`): the structs are `pub` inside a private module and are not reachable from outside the crate, so none of the three is a public symbol.

## crates/rgx-adapters-llm/src/EGM.md

- The Interface presents `pub struct extra::KerasZip`, `pub struct extra::Torch` and `pub struct extra::PickleStrings` as public symbols; `mod extra;` is private (`crates/rgx-adapters-llm/src/lib.rs:113`), so none of the three paths exists outside the crate.
- The Interface lists the little-endian readers `rd_u16`, `rd_u32`, `rd_u64`, `rd_f32`, `rd_f64` without their feature gates: each is compiled only under a format feature (`crates/rgx-adapters-llm/src/lib.rs:88` and `:92` need `gguf` or `npy`; `:97` needs `gguf` or `safetensors`; `:102` and `:106` need `gguf`), so a `--no-default-features --features safetensors` build has only `rd_u64` of the five.

## crates/rgx-adapters-mail/EGM.md

- The "Public symbols" list names `pub struct extra::Msg`, `pub struct extra::Emlx`, `pub struct pst::PstAdapter`, `pub struct variants::Mmdf`, `pub struct variants::ThunderbirdMsf` and `pub struct variants::AppleMailboxIndex`, but `mod extra;` (`crates/rgx-adapters-mail/src/lib.rs:39`), `mod pst;` (`crates/rgx-adapters-mail/src/lib.rs:41`) and `mod variants;` (`crates/rgx-adapters-mail/src/lib.rs:43`) are private; only `pub mod wab;` (`crates/rgx-adapters-mail/src/lib.rs:45`) is public, so the six other paths are not part of the crate's public surface.

## crates/rgx-adapters-mail/src/EGM.md

- The `extra::Msg` entry claims it "Reads subject, body (ANSI or UTF-16), sender, recipients and the attachment inventory"; the code reads only the subject (`crates/rgx-adapters-mail/src/extra.rs:63`), the body (`crates/rgx-adapters-mail/src/extra.rs:71`) and the attachment inventory (`crates/rgx-adapters-mail/src/extra.rs:84`–`:102`) — there is no sender or recipient extraction anywhere in the crate; those two words appear only in the module's own doc comment (`crates/rgx-adapters-mail/src/extra.rs:27`–`:28`).
- "`pub mod wab` — … the CFB reader it uses is `rgx_core::cfb::Cfb`, shared with the office crate's `.doc` adapter" is wrong: the WAB reader carries its **own** CFB parser (`struct Cfb` at `crates/rgx-adapters-mail/src/wab.rs:137`, `OLE_MAGIC` at `crates/rgx-adapters-mail/src/wab.rs:50`) and imports only `rgx_core::{bail, decline}` and `rgx_core::{Adapter, Outcome, Result}` (`crates/rgx-adapters-mail/src/wab.rs:45`–`:46`); it is the `.msg` reader that uses `rgx_core::cfb::Cfb` (`crates/rgx-adapters-mail/src/extra.rs:16`–`:18`).
- The Interface presents `pub struct extra::Msg`, `pub struct extra::Emlx`, `pub struct pst::PstAdapter`, `pub struct variants::Mmdf`, `pub struct variants::ThunderbirdMsf` and `pub struct variants::AppleMailboxIndex` as the module's public symbols; `mod extra;` (`crates/rgx-adapters-mail/src/lib.rs:39`), `mod pst;` (`crates/rgx-adapters-mail/src/lib.rs:41`) and `mod variants;` (`crates/rgx-adapters-mail/src/lib.rs:43`) are private, so none of those paths is reachable outside the crate.
- The claim that the `.msg` reader "reads the attachment inventory from the `__attach_version1.0_` storages" is imprecise: the code selects any directory entry of kind 2 whose name merely **contains** `"__attach"` (`crates/rgx-adapters-mail/src/extra.rs:87`), and the displayed names come from the `_3707001F`/`_3001001F` streams inside them (`crates/rgx-adapters-mail/src/extra.rs:92`).

## crates/rgx-core/EGM.md

- 🔴 **Blocker** — The Overview states: *"the pack store (`tv`, `tv-runtime`) and the ZIP reader (`zip`) are **not** in `default`"*. The code contradicts this: `crates/rgx-core/Cargo.toml:41` reads `default = ["std", "sha256-hw", "gzip", "zlib", "deflate", "bzip2", "lzma", "xz", "zstd", "snappy", "lz4", "blosc", "zip"]` — `zip` **is** in `default`. Only `tv` (`Cargo.toml:81`) and `tv-runtime` (`Cargo.toml:89`) are outside it.

## crates/rgx-core/examples/EGM.md

- 🔴 **Blocker** — The Interface says `json_dump.rs` emits *"`OK <canonical dump>` for an accepted document"*. The code never writes that token: the accepted branch writes only the canonical tokens and a newline (`crates/rgx-core/examples/json_dump.rs:79-83`); `b"NO "` is written only on the rejection paths (`json_dump.rs:66`, `json_dump.rs:85`, `json_dump.rs:73`). The literal `OK` appears nowhere in the file except the doc comment at `json_dump.rs:8`.
- 🔴 **Blocker** — The Overview says *"the measurement happens in-process so no process-spawn floor is inside the interval"*, and the Invariants say *"A measurement runs in-process"*. Three examples do the opposite: `status_table.rs` spawns both binaries and times the wall clock, and says so itself — *"This harness measures the CLI -- it spawns both binaries and times the wall clock"* (`crates/rgx-core/examples/status_table.rs:101-104`, spawn at `status_table.rs:415`); `thread_curve.rs` spawns the `rgx` binary (`crates/rgx-core/examples/thread_curve.rs:308-313`) and has a whole rule about subtracting a measured *spawn floor* (`thread_curve.rs:41-46`); `pipeline_profile.rs` prices whole `rgx` invocations by wall clock (`crates/rgx-core/examples/pipeline_profile.rs:89-113`, `pipeline_profile.rs:732`).
- 🟡 **Major** — The Invariants say *"they write no file and change no configuration"* and the Side Effects say *"Touch no global configuration, no lock and no file outside the corpus path; they leave nothing behind"*. The code writes files: `status_table.rs` writes the whole report to `--out PATH` (`crates/rgx-core/examples/status_table.rs:1703-1708`, option documented at `status_table.rs:189`) and, with `--flush`, creates and fills a 64 MB file `rgx-status-flush.bin` in the temp directory (`status_table.rs:588-605`); `thread_curve.rs` writes its report to `--out` (`crates/rgx-core/examples/thread_curve.rs:853-856`).
- 🟡 **Major** — The Interface says `json_accept.rs` is *"the whole interface the `json-harness` suite assumes of a parser"*. No such suite exists in the tree: there is no `conformance/` directory and no `run.py` anywhere in the repository, although the example itself cites `python conformance/run.py --parser ...` at `crates/rgx-core/examples/json_accept.rs:11`. The referenced consumer of this interface is absent.
- 🟡 **Nit** — The Interface says `json_accept.rs` reads *"the document named as the last argument"*. The code takes `std::env::args().nth(1)` — the **first** argument — and ignores any further ones (`crates/rgx-core/examples/json_accept.rs:19`).
- 🟡 **Nit** — The Overview says *"the `include` list in `Cargo.toml` ships `/src/**` only"*. `crates/rgx-core/Cargo.toml:20-26` also ships `/Cargo.toml`, `/README.md`, `/LICENSE-APACHE` and `/NOTICE` — the parent contract states this correctly at `crates/rgx-core/EGM.md:10`, so the child contradicts its parent.
- 🟡 **Nit** — The Overview says the examples *"share a shape: a corpus path or a pattern list comes from the command line or from an environment variable"*. `json_bench.rs` has neither: it generates its corpora in-process (`crates/rgx-core/examples/json_bench.rs:93-98`, "Corpora: generated, but shaped like what the adapters see") and takes no arguments.
- 🟡 **Nit** — The Interface describes `scan_floor.rs` as *"a raw byte walk against `scan::pair_offsets` and `scan::byte_bits`"*. The file times nine kernels: `pair_bits` with a 3- and a 7-byte needle (`crates/rgx-core/examples/scan_floor.rs:85-103`), `term_bits` (`scan_floor.rs:106-114`), the 64 KiB-granularity variants of both (`scan_floor.rs:120-136`), and the fused `scan::pair_term_bits` (`scan_floor.rs:153-165`).
- 🟡 **Nit** — The Invariants say a corpus path is *"named by an argument or by an environment variable, never written into the file"*. `scan_floor.rs` falls back to the literal `".rgx-bench/big235.rs"` written into the source (`crates/rgx-core/examples/scan_floor.rs:23`).
- 🟡 **Nit** — The Invariants say a measurement runs *"with a warmup discarded"*. `scan_floor.rs` runs 7 rounds and takes the minimum with no discarded warmup round of the measured work (`crates/rgx-core/examples/scan_floor.rs:35-47`); the only prior pass is a page-warming walk (`scan_floor.rs:28-33`).
- 🟡 **Nit** — The Invariants say the examples *"read nothing but their arguments and the corpus they are given"*. `json_dump.rs` reads a list of document paths from **stdin** when given no argument (`crates/rgx-core/examples/json_dump.rs:40-51`).

## crates/rgx-core/fuzz/EGM.md

- 🟡 **Nit** — The Overview says *"The directory holds the manifest, the lockfile, the `.gitignore`, the seed `corpus/` and the build `target/`"*. There is no `crates/rgx-core/fuzz/target/` directory in the tree; it is excluded by `crates/rgx-core/fuzz/.gitignore:1`, so it is a build artefact rather than part of the directory's contents.

## crates/rgx-core/fuzz/fuzz_targets/EGM.md

- 🔴 **Blocker** — The Invariants state *"Every adapter the registry can reach by extension belongs in `EXTS`"*. The code breaks this on a wide scale. The registry is built from every family's `adapters()` (`crates/rgx-core/fuzz/fuzz_targets/process.rs:74-90`) with the adapter crates' default features enabled (`crates/rgx-core/fuzz/Cargo.toml:21-40`; `crates/rgx-adapters-media/Cargo.toml:31-51`; `crates/rgx-adapters-llm/Cargo.toml:29`), so it reaches many extensions absent from `EXTS` (`process.rs:24-72`):
  - `crates/rgx-adapters-media/src/photos.rs:118` — `"psd"`, `"psb"`
  - `crates/rgx-adapters-media/src/photos.rs:389` — `"jp2"`, `"j2k"`, `"j2c"`, `"jpf"`, `"jpx"`, `"jpm"`
  - `crates/rgx-adapters-media/src/photos.rs:729` — `"jxl"`
  - `crates/rgx-adapters-media/src/photos.rs:833` — `"exr"`
  - `crates/rgx-adapters-media/src/lib.rs:300` — `"jpeg"`, `"webp"`
  - `crates/rgx-adapters-media/src/lib.rs:457` — `"ogg"`, `"oga"`, `"opus"`
  - `crates/rgx-adapters-media/src/lib.rs:761` — `"fit"`, `"fts"`
  - `crates/rgx-adapters-media/src/lib.rs:812` — `"dicom"`, `"ima"`
  - `crates/rgx-adapters-media/src/extra.rs:166` — `"otf"`, `"ttc"`, `"otc"`
  - `crates/rgx-adapters-media/src/extra.rs:332` — `"azw"`, `"azw3"`, `"prc"`
  - `crates/rgx-adapters-media/src/mpeg.rs:21` — `"m2ts"`, `"vob"`, `"mts"`
  - `crates/rgx-adapters-llm/src/lib.rs:487` — `"sft"`, `"st"`
  - `crates/rgx-adapters-mail/src/lib.rs:729` — `"mbx"`
  - `crates/rgx-adapters-inspect/src/rasters.rs:96-98` — `"arw"`, `"pef"`, `"srw"`, `"rw2"`
  - `crates/rgx-adapters-inspect/src/plist.rs:35` — `"pref"`, `"plist"`
- 🟡 **Nit** — The Side Effects say *"which is why `corpus/**` is marked `-text` in `.gitattributes`"*. The rule that exists is `**/fuzz/corpus/** -text` (root `.gitattributes:18`); there is no bare `corpus/**` rule, and the parent contract states the pattern correctly at `crates/rgx-core/fuzz/EGM.md:6`.

## scripts/EGM.md

- **Pair list does not match the authority it cites (Major).** The contract says "The full list of the pairs is in `AGENTS.md` §1.1" and then lists 14 pairs including `publish-cratesio`, but the §1.1 table (`AGENTS.md:177-191`) holds 15 pairs and does **not** contain `publish-cratesio` — it does contain `bench-linkers`, which the contract's list omits. The `publish-cratesio` pair is real in the tree (`scripts/publish-cratesio.sh`, `scripts/publish-cratesio.ps1`), so either the contract's list is not AGENTS.md §1.1's list, or AGENTS.md §1.1 is stale; the contract asserts they are the same.
- **`release-linux.sh` writes to `.dist/`, not `./dist` (Major).** The contract says the script "copies the verified artifacts back to `./dist`"; the code does `mkdir -p .dist` and `scp -q "$HOST:$REMOTE/out/"* .dist/` (`scripts/release-linux.sh:38-39`). The contract's own Side Effects section says `.dist/`, contradicting its Interface line. (The script's own header, `scripts/release-linux.sh:2-3`, carries the same stale `./dist` the contract copied.)
- **"pushes HEAD" is wrong (Nit).** The script pushes the named ref, defaulting to `main` (`REF="${1:-main}"`, `git push forgejo "$REF"` — `scripts/release-linux.sh:16,29`), not HEAD.
- **"the spawn floor is measured first and subtracted from both sides" does not hold anywhere under `scripts/` (Major).** The floor-subtraction protocol lives in `benchmark/extent-ab.sh:183-184`. Inside `scripts/`: `tv-matrix.sh` computes a paired percentage against a ±2% band (`scripts/tv-matrix.sh:79,246-270`); `tv-threads.sh` prints a ±2% note (`scripts/tv-threads.sh:138`); the harness behind `bench-status.sh` uses ±3%/±2% *percentage* floors (`crates/rgx-core/examples/status_table.rs:115-119`); `walk_phase.rs` prints the spawn floor as a third arm and never subtracts it (`scripts/walk_phase.rs:30,37`).
- **"A measurement prints no timing when the arms disagree" is broken by `tv-matrix.sh` (Major).** The gate only sets `FAIL=1` and prints a line (`scripts/tv-matrix.sh:214-239`); the per-arm median/min/max/verdict rows are then printed unconditionally (`scripts/tv-matrix.sh:242-275`). (`bench-linkers.sh:114-122` and `tv-threads.sh:117` do withhold, so the invariant is true for those and false for this one.)
- **Side Effects: `rsync` is never spawned (Minor).** The only copy of release artifacts uses `scp` (`scripts/release-linux.sh:39`, `scripts/release-all.sh:89`); the `rsync/scp` mention is in the script's header comment only (`scripts/release-linux.sh:9`).
- **Side Effects: `rustc` is never spawned (Minor).** `rustc -O --edition 2021 -o walk_patterns scripts/walk_patterns.rs` is a manual invocation documented in the probe's own header (`scripts/walk_patterns.rs:5`); no script under `scripts/` calls `rustc`.
- **Side Effects: `perl` is spawned but not listed (Minor).** `apply-vendored-edits.sh` requires `perl` and refuses to run without it (`scripts/apply-vendored-edits.sh:63-73`).
- **Side Effects: network hosts list omits two (Nit).** `scripts/gen_casefold_table.py:52-53` reaches `www.unicode.org` and `scripts/gen-brotli-tables.py:12` reaches `www.rfc-editor.org`; the contract lists only crates.io, GitHub, the forgejo, homebrew-core and "the two public corpus hosts".
- **Side Effects: the `__pycache__` claim is not realised (Nit).** Every script under `scripts/` imports stdlib only — none imports a sibling module — so running them as `python3 script.py` leaves no bytecode cache behind.
- **`engine-sweep.sh` cannot run as the contract shows it (Minor).** The contract gives `bash scripts/engine-sweep.sh` with no flags; the script exits 1 unless `--store` is given (`scripts/engine-sweep.sh:23`), and also takes `--rounds` (`scripts/engine-sweep.sh:18-19`).
- **Flag lists are abridged to the point of being wrong (Minor).** Omitted flags that the code accepts: `commit-block.sh --patches/--note/--no-count` (`scripts/commit-block.sh:44-46`), `tv-matrix.sh --ref/--arms/--rm-store` (`scripts/tv-matrix.sh:66-68`), `tv-threads.sh --mode/--pool` (`scripts/tv-threads.sh:39-40`), `publish-cratesio.sh --allow-existing` (`scripts/publish-cratesio.sh:30`; the twin adds `-AllowExisting/-Attempts/-WaitSeconds`, `scripts/publish-cratesio.ps1:22-26`), `publish-release.sh --version` (`scripts/publish-release.sh:42`), `build-release.sh --version` (`scripts/build-release.sh:42`), `apply-vendored-edits.ps1 -AllocToStd` (`scripts/apply-vendored-edits.ps1:26-29`).
- **Overview's list of generated files omits one (Nit).** It names `charset_table.rs`, `charset_state_table.rs`, `casefold_table.rs` and `brotli/tables.rs`; a fifth generator writes `crates/rgx-core/src/charset_mb_table.rs` (`scripts/gen_charset_mb_tables.py:75`, header `crates/rgx-core/src/charset_mb_table.rs:5`).

## benchmark/EGM.md

- **"The detector's algorithm was kept apart from its wiring on purpose" is false (Major).** The algorithm lives inside `regress.py` itself — `median` (`benchmark/regress.py:48`), `mad_flag` (`benchmark/regress.py:54`) and the whole `ScalarKalman` class (`benchmark/regress.py:75-88`) — and the contract's own Interface section lists `ScalarKalman(x0, p0, q, r)` with `step(z_log)` as `regress.py`'s public surface, contradicting its Overview. Nothing is "kept apart"; the only thing that is absent is the file `benchmark/kalman-drift.py`, which is merely *referenced* by the docstring (`benchmark/regress.py:6`) and the printed footer (`benchmark/regress.py:209`).
- **"Both scripts refuse to run when the release binaries are missing, telling the caller to build them first" is false for the PowerShell twin (Major).** `benchmark/extent-ab.sh:46-47` checks both binaries and exits 2 with "build it first: cargo build --release"; `benchmark/extent-ab.ps1` has no existence check at all — it runs `& $rgxtv build $Corpus --store $Store` directly and only throws a generic "rgx-tv build failed" (`benchmark/extent-ab.ps1:57-58`). This also breaks the invariant that the twins "run the same protocol and print the same rows for the same inputs".

## benchmark/diffrig/EGM.md

- **The `rg` resolution rule does not hold for `cmp.sh` (Major).** The Overview ("`rg` takes an `RG` environment override, then `PATH`, then the ripgrep that the Git for Windows ships") and the invariant repeat it for "each harness", but `cmp.sh` invokes bare `rg` with no `RG` override (`benchmark/diffrig/cmp.sh:12,15`). The `$RG` override reaches only the three Python programs (`benchmark/diffrig/fuzz.py:13`, `benchmark/diffrig/ptytest.py:34`, `benchmark/diffrig/conpty.py:142`).
- **Binary resolution is Windows-only, so the Unix counterpart resolves nothing (Minor).** All four harnesses hardcode the `.exe` suffix — `benchmark/diffrig/cmp.sh:6-7`, `benchmark/diffrig/fuzz.py:10-12`, `benchmark/diffrig/ptytest.py:31-33`, `benchmark/diffrig/conpty.py:139-141` — so `ptytest.py`, the POSIX-pty harness the contract describes, finds no `rgx` on the Unix platform it exists for; the invariant "a run from any working directory compares the same two executables" holds only on Windows.
- **The `fx/` corpus described is not the corpus the matrix runs over (Minor).** The Overview describes fixtures including "a binary file carrying NUL bytes, a file whose needle is surrounded by spaces, and a deep file of many short lines", but `FILESETS` selects only `hello.txt`, `two.txt`, `multi.txt`, `nonl.txt`, `ctx.txt`, `empty.txt`, `blank.txt` and `oneword.txt` (`benchmark/diffrig/fuzz.py:32-43`); `bin.dat`, `crlf.txt`, `crlf2.txt`, `gap.txt`, `deep.txt`, `zw.txt`, `wt.txt`, `b.txt` and `nonl2.txt` are in no file set.

## Formula/EGM.md

- **"Nothing in the tree reads it except `brew` and `scripts/publish-homebrew.sh`" is false (Major).** `scripts/push-github.sh` reads the formula, rewrites its `url`, `sha256` and `version` lines in place (`scripts/push-github.sh:73,188-203`) and stages it (`scripts/push-github.sh:209`). The contract contradicts itself here: its own Overview states that "`scripts/push-github.sh` rewrites the URLs, the digests and the version when it publishes the macOS archives".

## crates/rgx-core/src/EGM.md

- **Major** — The module map ("The modules here fall into three groups…") omits ten public modules of the crate, none of which is named anywhere in the contract: `base64` (`crates/rgx-core/src/lib.rs:117`), `cfb` (`lib.rs:119`), `fuzzkit` (`lib.rs:140`), `index` (`lib.rs:143`), `index_io` (`lib.rs:144`), `mcp` (`lib.rs:148`), `png` (`lib.rs:152`), `sha256` (`lib.rs:159`), `sha256_hw` (`lib.rs:160`) and `walk_policy` (`lib.rs:176`).
- **Major** — The invariant "`process` returns `true` only when the sole unit it appended is the file's own bytes" (and the same claim in the Overview) is contradicted by the missing-tool path: when the extension is claimed but every claimant's external tool is absent, `process` pushes a second unit — `[rgx: adapter '…' skipped: its external tool is not on PATH]`, filed under `via: "raw"` (`crates/rgx-core/src/lib.rs:1556-1567`) — and still returns `true`, because `raw_only` is computed from `notes.is_empty()` (`lib.rs:1576`) and the skip note is not in `notes`. The function returns `true` with two units appended, one of which is not the file's own bytes.
- **Nit** — The Interface lists `pub fn profile_add(name, ns)`, `pub fn profile_dump()` and `pub struct DepthGuard` — `enter(depth)` as public symbols; all three are `#[cfg(feature = "std")]`-gated (`crates/rgx-core/src/lib.rs:1219-1238`, `lib.rs:1240-1254`) and do not exist in the `no_std` configuration the same contract describes.
- **Nit** — The invariant "A magic-prefix claim is a candidate only when no adapter claimed the file by name" is not enforced: the magic phase runs whenever the extension keys are exhausted, whether or not an extension claimant was already offered and declined (`crates/rgx-core/src/lib.rs:1039-1061`), so a magic claimant is still offered after a name claimant declined. (The same sentence is in `Adapter::magic`'s own doc at `lib.rs:692-694` — the contract is faithful to a doc the code does not implement.)
- **Nit** — The Overview says the `std` feature gates "the typed error chain, the profiler map and the `f64` JSON parser — and nothing else that matters". The memory-mapping module is `std`-gated too (`crates/rgx-core/src/lib.rs:134-135`), the pack store behind `tv`/`tv-runtime` (`lib.rs:170-173`) and the ZIP reader behind `zip` (`lib.rs:180-181`).
- **Nit** — The Children entry for `bin` gives "Public symbols: `main`, `parse_size`, `print_usage`", but all three are private `fn`s of a binary crate (`crates/rgx-core/src/bin/rgx-tv.rs:23`, `:41`, `:112`); the binary exports no public symbol at all.

## crates/rgx-core/src/bin/EGM.md

- **Blocker** — The invariant "`--engine` selects between `auto` (the default: the in-house engine for a line-anchored pattern, `grep` otherwise — measured, see `EngineMode::pick`), `rgx` (always in-house where the pattern compiles), `grep`, and `both` (cross-checked, with divergences named on stderr)" describes an engine set the code does not have. Only `auto` and `rgx` are accepted; `grep` and `both` are legacy aliases that print `--engine {value} is gone, using rgx` on stderr and resolve to the in-house engine (`crates/rgx-core/src/bin/rgx-tv.rs:414-432`, bundled form at `rgx-tv.rs:508-521`). There is no cross-check engine and no divergence report. `EngineMode` has only the `Auto` and `Rgx` variants — the `Grep` arm was dropped on purpose — and `EngineMode::pick` returns `EngineMode::Rgx` unconditionally (`crates/rgx-core/src/tv/query.rs:64-84`). The contract copies the program's own stale usage text (`rgx-tv.rs:76-79`).
- **Major** — The Interface's list of accepted options is incomplete. The code also accepts `--validate` (`crates/rgx-core/src/bin/rgx-tv.rs:377`), `--mmap` (`:482`), `--no-mmap` (`:486`), `--serial-buffered` (`:490`), `--packs-per-thread <N>` (`:399`, `:494`), `--no-pool` (`:359`), `--leak-mmap` (`:502`), `--stats` (`:498`), `-h`/`--help` (`:188`, `:553`) and, for `update`, `--compact` (`:701`). The contract names only `--pool`.
- **Major** — The invariant "the exit status distinguishes 'no match' from 'error' the way ripgrep's does" is false: there is no separate status for "no match". A search that succeeds with zero matches prints nothing and exits 0; only an `Err` exits 1 (`crates/rgx-core/src/bin/rgx-tv.rs:604-628`). ripgrep exits 1 on no match.
- **Nit** — The Interface's description of `parse_size` ("a bare number is bytes, `k`/`kb`/`kib` are 1024, …") omits the explicit `b` suffix (`crates/rgx-core/src/bin/rgx-tv.rs:32`), and the number is parsed as an `f64`, so a fractional value such as `1.5m` is accepted (`rgx-tv.rs:27-28`).
- **Nit** — The Overview says the program "owns no logic of its own — the decisions live in `crate::tv` and the filesystem in `crate::tv_runtime`". The binary owns the whole argument grammar and the value parsers (`walk_filters`, `split_bundled`, `parse_threads`, `pin_threads`, `parse_lines`, `parse_claims` — `crates/rgx-core/src/bin/rgx-tv.rs:143-334`) and the output formatting (`print_stages`, `rgx-tv.rs:634`).
- **Nit** — Side Effects: "…and to stderr (usage, diagnostics and engine divergences)". Engine divergences no longer exist; the only engine-related stderr output is the deprecation notice for the removed `grep`/`both` aliases (`crates/rgx-core/src/bin/rgx-tv.rs:425`).

## crates/rgx-core/src/compress/EGM.md

- **Major** — The Overview states "The `.lz4` file wrapper is deliberately absent: it is not interop-proven here, so `.lz4` files still go through `lz4_flex`." The `.lz4` file wrapper is read in-house and `lz4_flex` was replaced: the archive adapter decodes both the modern frame and the deprecated `lz4 -l` container with its own vendored decoder (`crates/rgx-adapters-archive/src/lib.rs:465-470`, `:569-577`; `crates/rgx-adapters-archive/src/lz4/`), and the adapter's own comment says "the `lz4_flex` crate this replaced read both". `lz4_flex` survives only in the `rgx` binary's extraction cache (`src/cache.rs:756`, `:780`).
- **Nit** — The invariant "`Bounded::declared` is `None` where the format has no declared size, or where the value is known to be a lie (gzip's ISIZE is the size modulo 2^32)" does not hold for gzip: it publishes the ISIZE as `Some(..)` in every case (`crates/rgx-core/src/compress/gzip.rs:307-319`), and its own test pins `whole.declared == Some(full.len() as u64)` (`gzip.rs:792`). The value is known to be a floor once a member passes 4 GiB (`gzip.rs:313-314`) and is still reported.
- **Nit** — The Interface lists the codec submodules (`blosc`, `bwt`, `bzip2`, `deflate`, `gzip`, `huffman`, `lz4`, `lz77`, `lzma`, `snappy`, `xz`, `zlib`, `zstd`) and the module-root re-exports as unconditional; every one of them is `#[cfg(feature = …)]` (`crates/rgx-core/src/compress/mod.rs:42-70`, re-exports at `:72-90`). Only `cap`, `crc32` and `error` exist without their feature.
- **Nit** — The Overview says `crc32` and `xz::crc64` are "both specified by polynomial and bit-at-a-time recurrence". Both are table-driven: CRC-32 folds eight bytes per step through a 256-entry table (`crates/rgx-core/src/compress/crc32.rs:28-60`) and CRC-64 does the same (`crates/rgx-core/src/compress/xz/crc64.rs:57-87`).

## crates/rgx-core/src/compress/xz/EGM.md

- **Major** — The invariant "The magic is checked first: `data[..6] == XZ_MAGIC`, and a stream shorter than header plus footer is refused as 'too short to be an XZ stream'" reverses the code's order: the length check comes first and the magic second (`crates/rgx-core/src/compress/xz/container.rs:361-366`). A 3-byte input is refused as "file is too short to be an XZ stream" and never reaches the magic comparison; the magic mismatch is reported as "bad magic bytes". The refusal text is also "file is too short…", not "too short to be an XZ stream".
- **Nit** — The Interface presents `pub const XZ_MAGIC`, `pub const FOOTER_MAGIC` and `pub fn crc64` as the module's symbols, but none is at the `xz` module root: the two constants live in `compress::xz::container` (`crates/rgx-core/src/compress/xz/container.rs:28`, `:31`) and `crc64` in `compress::xz::crc64` (`crates/rgx-core/src/compress/xz/crc64.rs:98`); `crates/rgx-core/src/compress/xz/mod.rs:9-11` re-exports only `XzReader`.
- **Nit** — The Overview describes `crc64.rs` as "the CRC-64 check type" without noting the three other check kinds the container accepts and verifies: none `0x00`, CRC-32 `0x01`, CRC-64 `0x04` and SHA-256 `0x0A` (`crates/rgx-core/src/compress/xz/container.rs:36-44`), the last verified against `crate::sha256` (`container.rs:663`).

## crates/rgx-core/src/crypt/EGM.md

- **Nit** — Side Effects: "None. Every entry point is a pure function over byte slices." `Aes::encrypt_block` and `Aes::decrypt_block` mutate the caller's block in place (`crates/rgx-core/src/crypt/aes.rs:262`, `:278`), `rc4_in_place` mutates the caller's buffer (`crates/rgx-core/src/crypt/rc4.rs:23`), and the three hashers keep streaming state behind `&mut self` (`crates/rgx-core/src/crypt/md5.rs:69`, `crates/rgx-core/src/crypt/sha512.rs:350`, `sha512.rs:382`).

## crates/rgx-core/src/djson/EGM.md

- **Blocker** — Overview: "`parse` returns `(Value, Arena)`". The code returns only the arena: `pub fn parse(input: &str) -> Result<Arena, JsonParseError>` at `crates/rgx-core/src/djson/parser.rs:46` (and `parse_indexed` at `crates/rgx-core/src/djson/index_parser.rs:47` has the same shape). The contract contradicts its own Interface line ("`parse(input: &str) -> Result<Arena, JsonParseError>`") and the code.
- **Major** — Overview: "The streaming layer (`stream`) is `std`-only for its reader convenience". `stream` is `no_std` + `alloc`; only `from_reader` is `std`-gated (`crates/rgx-core/src/djson/stream.rs:317`, and `crates/rgx-core/src/djson/mod.rs:70-71`). The module's own header says the opposite ("the parser, the NDJSON iterator and the `ndjson` constructor are `no_std` + `alloc`", `crates/rgx-core/src/djson/mod.rs:62-63`); `format!` is only used inside the `std` arm (`crates/rgx-core/src/djson/stream.rs:332`).
- **Major** — Overview: "`serde` is opt-in". There is no `serde` dependency and no `serde` feature: `crates/rgx-core/Cargo.toml` has no `serde` entry at all, and no `serde`/`serde_json`/`Serialize` impl exists anywhere under `crates/rgx-core/src` (the only mentions are prose comparisons to `serde_json` in comments, e.g. `crates/rgx-core/src/djson/value.rs:31`). There is nothing to opt into.
- **Nit** — Interface: "`pub mod index_parser` — stage 2, the walker that populates the arena (`parse_indexed`)". `parse_indexed` is `pub(super)`, not public (`crates/rgx-core/src/djson/index_parser.rs:47`), so the named entry point cannot be reached from outside the crate.
- **Nit** — Interface: the `Value` method list omits five public methods that exist: `len` (`crates/rgx-core/src/djson/value.rs:487`), `is_empty` (495), `contains_key` (499), `keys` (505), `values` (517).
- **Nit** — Interface: the `ondemand` "Public symbols" are private test helpers; they live in a `#[cfg(test)] mod tests` (`crates/rgx-core/src/djson/ondemand.rs:968-969`, helpers at `crates/rgx-core/src/djson/ondemand/tests.rs:28-119`).

## crates/rgx-core/src/djson/json_scan/EGM.md

- **Nit** — Invariant: "All `unsafe` is confined to the `#[target_feature]` functions in the private `avx2` module". Two `unsafe fn`s in that module carry no `#[target_feature]`: `rect` (`crates/rgx-core/src/djson/json_scan/avx2.rs:64`) and `rect128` (`crates/rgx-core/src/djson/json_scan/avx2.rs:292`).
- **Nit** — Interface: `StructuralIndex` is described as "`pub structural: BitSet`" plus two methods. The struct also carries `pub quote: BitSet` (`crates/rgx-core/src/djson/json_scan/mod.rs:381`), `pub len: usize` (383) and `pub end_in_string: bool`; the last is what stage 2 tests first (`crates/rgx-core/src/djson/index_parser.rs:50`).
- **Nit** — Interface: `classify16_avx2` is listed without the `x86_64` gate it actually carries (`crates/rgx-core/src/djson/json_scan/mod.rs:716-718`), while `scan_avx2` is annotated as x86_64-only.

## crates/rgx-core/src/djson/ondemand/EGM.md

No drift detected.

## crates/rgx-core/src/memchr/EGM.md

- **Major** — Invariant: "`memmem` uses this crate's own pair scanner (`crate::scan::pair_find` / `pair_rfind`) ... the upstream packed-pair kernel is unreachable without `std`"; Overview: "`memmem` is this crate's own". The crate's own scanner is used only on x86_64 *and* only when the probe reports AVX2 (`crates/rgx-core/src/memchr/memmem.rs:75-81` and `:104-110`); every other case falls back to `::memchr::memmem::find`/`rfind` — the upstream kernel — which the contract never mentions.
- **Nit** — Interface: `memrchr_iter`, `memrchr2_iter`, `memrchr3_iter` are listed as if they returned the same iterator types as their forward counterparts. They return `Rev<Memchr<'h>>`, `Rev<Memchr2<'h>>` and `Rev<Memchr3<'h>>` (`crates/rgx-core/src/memchr/dispatch.rs:139`, `:152`, `:165`); `Rev` is a public return type absent from the contract.

## crates/rgx-core/src/memmap2/EGM.md

- **Major** — Invariant: "`lock`/`unlock` take and release an OS file lock on the mapped range". They take a *page* lock: `mlock`/`munlock` on Unix (`crates/rgx-core/src/memmap2/platform/linux.rs:247-265`, same in `macos.rs:236-254` and `freebsd.rs:241-259`) and `VirtualLock`/`VirtualUnlock` on Windows (`crates/rgx-core/src/memmap2/platform/windows.rs:250-286`). No file lock is taken anywhere in the module.
- **Major** — Side Effects: "`lock` takes an OS lock that other processes can observe". `mlock`/`VirtualLock` are process-private page locks; no other process can observe them.
- **Major** — Invariant: "`MmapOptions::offset` must be a multiple of the page size and `len` must not overflow `isize`; both are refused with `Error::LengthOverflow` / `Error::OffsetBeyondFile` rather than clamped". On Unix the offset is silently aligned *down* and the length extended (`crates/rgx-core/src/memmap2/platform/linux.rs:50-56`); on Windows the check is against the allocation granularity and returns the OS error `ERROR_MAPPED_ALIGNMENT` (1132), not one of those variants (`crates/rgx-core/src/memmap2/platform/windows.rs:55-58`). `Error::OffsetBeyondFile` is raised only when the offset is past the end of the file (`crates/rgx-core/src/memmap2/options.rs:58-60`).
- **Major** — Side Effects: "A mapping owns a file descriptor (Unix) or a handle (Windows) and releases it when dropped." The Unix `MmapInner` holds only a pointer and a length — no descriptor is owned or closed (`crates/rgx-core/src/memmap2/platform/linux.rs:11-14`, `macos.rs:14-17`, `freebsd.rs:19-22`); only Windows duplicates and owns a handle (`crates/rgx-core/src/memmap2/platform/windows.rs:22`, `:84-107`, `:36-40`).
- **Major** — Interface: "The checked variant refuses an advice the running kernel does not have; the unchecked one hands the number over as-is." Both variants hand the number straight to `madvise(2)`; the crate performs no capability check at all (`crates/rgx-core/src/memmap2/mmap.rs:40-49` → `crates/rgx-core/src/memmap2/platform/linux.rs:232-245`, `macos.rs:221-234`).
- **Nit** — Interface: "`pub type MmapRawDescriptor` — the platform's raw descriptor type." It is a `pub struct` newtype, not a type alias, and on the fallback target it carries a lifetime: `pub struct MmapRawDescriptor<'a>(pub &'a File)` (`crates/rgx-core/src/memmap2/platform/mod.rs:291-301`).
- **Nit** — Invariant: `Error::LengthOverflow` / `Error::OffsetBeyondFile` are named as if public; the enum is `pub(crate)` inside a private module (`crates/rgx-core/src/memmap2/error.rs:8`, module declared at `crates/rgx-core/src/memmap2/mod.rs:18`).
- **Nit** — Interface: `Mmap::lock`/`unlock` and `MmapMut::lock`/`unlock` are listed unconditionally; both pairs are `#[cfg(unix)]` (`crates/rgx-core/src/memmap2/mmap.rs:66-74`, `crates/rgx-core/src/memmap2/mmap_mut.rs:97-105`), so the Windows build has neither.
- **Nit** — Invariant: "the safe wrappers on `MmapOptions` do not exist" — `MmapOptions::map_anon` is a safe wrapper (`crates/rgx-core/src/memmap2/options.rs:104`).
- **Nit** — Interface: the platform's "Public symbols" list includes `page_size()`, `file_len()`, `file_len_for_desc()` and `MmapInner`, all of which are `pub(crate)` (`crates/rgx-core/src/memmap2/platform/mod.rs:15`, `:47`, `:96`, `:100`); the `platform` module itself is private (`crates/rgx-core/src/memmap2/mod.rs:22`).

## crates/rgx-core/src/memmap2/platform/EGM.md

- **Major** — Invariant: "The `fallback` implementation refuses every operation rather than pretending to succeed; it never returns a mapping that is not there." `map_anon` *succeeds* and returns a heap `Vec<u8>` of zeros (`crates/rgx-core/src/memmap2/platform/fallback.rs:71-81`), and `flush`, `flush_async`, `make_read_only`, `make_exec`, `make_mut`, `advise`, `lock`, `unlock` all return `Ok(())` (`fallback.rs:90-113`). Only the five file-mapping entry points refuse (`fallback.rs:28-69`). The Overview's "maps nothing and refuses every call" is contradicted the same way.
- **Major** — Interface: "Every platform defines one with the same shape of API: `map(len, fd, offset, populate)`". The fallback's signature takes `&File`, not a raw descriptor (`crates/rgx-core/src/memmap2/platform/fallback.rs:28-69`, versus `platform/linux.rs:74` and `platform/windows.rs:111`).
- **Major** — Side Effects: "`LockFileMapping` on Windows". No such call exists — the string `LockFileMapping` appears nowhere in the crate; the Windows lock is `VirtualLock`/`VirtualUnlock` (`crates/rgx-core/src/memmap2/platform/windows.rs:256-280`, FFI at `:384-385`).
- **Major** — Side Effects: "`MmapInner::drop` unmaps and releases the handle; dropping a `MmapMut` also releases any file lock taken by `lock()`." There is no file lock; `lock()` takes a page lock, and the Unix drop only `munmap`s (`crates/rgx-core/src/memmap2/platform/linux.rs:19-26`).
- **Nit** — Interface: "`pub type MmapRawDescriptor`" — a `pub struct` newtype (`crates/rgx-core/src/memmap2/platform/mod.rs:291-301`).
- **Nit** — Interface: "`MmapAsRawDesc` ... implemented for `&File` and for `RawFd`/`RawHandle` wrappers". On Unix and Windows there is no `&File` impl — `&File` is covered only incidentally by the blanket `impl<'a, T> MmapAsRawDesc for &'a T where T: AsRawFd/AsRawHandle` (`platform/mod.rs:314-339`); an explicit `&File` impl exists only on the fallback target (`platform/mod.rs:347-351`).
- **Nit** — Interface: the `MmapInner` method list omits the fallback's extra `map_file(file: &File, want: usize) -> io::Result<MmapInner>` (`crates/rgx-core/src/memmap2/platform/fallback.rs:83`).

## crates/rgx-core/src/regex/EGM.md

- **Major** — Invariant: "The differential comparisons are against the `regex` crate with `unicode(false)`". No `unicode(false)` call exists in the suite; the single oracle call is `regex::bytes::Regex::new(...)` with no builder options (`crates/rgx-core/src/regex/tests.rs:966`). Byte mode there comes from the `bytes` API and the `(?-u)` flag carried by the translated pattern — not from a `unicode(false)` setting. (The sibling oracle *does* use `RegexBuilder ... .unicode(false)`, `crates/rgx-core/src/searcher/oracle.rs:95`, `:146`, `:216`, `:265`.)
- **Major** — Overview: "The remainder holds the anchor selection, the candidate stream, the case-folding behaviour, the glob translation and the replacement templates against the `regex` crate". Only the glob translation is compared against the oracle (`crates/rgx-core/src/regex/tests.rs:964-987`). The replacement templates are pinned to hand-written expected strings (`tests.rs:1084-1119`), and no case-folding test in the file uses the oracle at all.
- **Nit** — The Interface's test list omits five tests that exist in the suite: `quit_after_bounds_reported_matches` (`crates/rgx-core/src/regex/tests.rs:182`), `a_sink_returning_false_stops_the_search` (`:195`), `line_numbers_count_from_one` (`:211`), `line_numbers_are_reported_when_context_needs_them_and_skipped_otherwise` (`:234`), `a_sparse_reader_search_finds_every_needle_with_the_skip_active` (`:1849`).

## crates/rgx-core/src/searcher/EGM.md

- **Nit** — The `tests.rs` test list omits five tests that exist in the suite: `quit_after_bounds_reported_matches` (`crates/rgx-core/src/searcher/tests.rs:182`), `a_sink_returning_false_stops_the_search` (`:195`), `line_numbers_count_from_one` (`:211`), `line_numbers_are_reported_when_context_needs_them_and_skipped_otherwise` (`:234`), `a_sparse_reader_search_finds_every_needle_with_the_skip_active` (`:1849`). The `oracle.rs` list, the helper list and every invariant checked out.

## crates/rgx-core/src/tv/EGM.md

- **Major** — Overview: "`rgx-tv` is the `std` crate that owns the filesystem, the threads and the wall clock". `rgx-tv` is a *binary* target of `rgx-core`, not a crate (`crates/rgx-core/Cargo.toml:165-171`); the `std` half is the `rgx_core::tv_runtime` module behind the `tv-runtime` feature (`crates/rgx-core/src/lib.rs:172-173`), and no `rgx-tv` crate exists in the workspace (`Cargo.toml:2-…`).

## crates/rgx-core/src/tv_runtime/EGM.md

No drift detected.

## crates/rgx-adapters-media/EGM.md

- The "Public symbols" list names `pub mod exif`; the crate declares `mod exif;` — a private module — at `crates/rgx-adapters-media/src/lib.rs:95`, gated on `any(feature = "exif", "tiff", "psd", "jpeg2000", "jpegxl")` (`src/lib.rs:88-95`). No `exif` item is reachable outside the crate.
- The same "Public symbols" list presents `pub struct imgmeta::Gif`, `imgmeta::Bmp`, `photos::Psd`, `photos::Jpeg2000`, `photos::JpegXl`, `photos::OpenExr`, `avi::AviInfo`, `asf::AsfInfo`, `flv::FlvInfo`, `mpeg::MpegInfo`, `mp4mkv::VideoTags`, `extra::FontNames`, `extra::Woff`, `extra::Mobi` as crate-public symbols; every one of those modules is private (`mod asf;` `src/lib.rs:85`, `mod avi;` `:87`, `mod extra;` `:97`, `mod flv;` `:99`, `mod imgmeta;` `:101`, `mod mp4mkv;` `:103`, `mod mpeg;` `:105`, `mod photos;` `:112`), so none of those types is nameable from outside the crate. Only `adapters()`, `ExifJpeg`, `Tiff`, `AudioTags`, `Fits` and `Dicom` are exported.

## crates/rgx-adapters-media/src/EGM.md

- "`pub mod exif` (feature `exif`)" — the module is private (`mod exif;`, `crates/rgx-adapters-media/src/lib.rs:95`), and its gate is `any(feature = "exif", "tiff", "psd", "jpeg2000", "jpegxl")` (`src/lib.rs:88-95`), not the single feature named.
- The module-qualified entries (`pub struct imgmeta::Gif`, `imgmeta::Bmp`, `photos::Psd`, `photos::Jpeg2000`, `photos::JpegXl`, `photos::OpenExr`, `avi::AviInfo`, `asf::AsfInfo`, `flv::FlvInfo`, `mpeg::MpegInfo`, `mp4mkv::VideoTags`, `extra::FontNames`, `extra::Woff`, `extra::Mobi`) name private modules: `mod asf;` `src/lib.rs:85`, `mod avi;` `:87`, `mod extra;` `:97`, `mod flv;` `:99`, `mod imgmeta;` `:101`, `mod mp4mkv;` `:103`, `mod mpeg;` `:105`, `mod photos;` `:112`. The structs are `pub` but unreachable; the only `pub fn` the crate really exports besides `adapters()` is `mp4mkv::extract_text` (`src/mp4mkv.rs:20`) — itself inside a private module.

## crates/rgx-adapters-media/src/exif/EGM.md

- "The reader has three parts" is followed by five modules (`mod.rs`, `ifd.rs`, `tags.rs`, `tiff.rs`, `makers/`, `crates/rgx-adapters-media/src/exif/EGM.md:10-14`); the module set is `mod ifd;` `crates/rgx-adapters-media/src/exif/mod.rs:37`, `mod tags;` `:38`, `mod tiff;` `:40`, plus `pub mod makers;` `:39`.

## crates/rgx-adapters-media/src/exif/makers/EGM.md

No drift detected.

## crates/rgx-adapters-office/EGM.md

- The "Public symbols" list names `pub struct ppt::Ppt`, `xls::Xls`, `visio::Visio`, `tex::Tex`, `markup::Markup`, `legacy::AbiWord`, `legacy::HwpRaw`, `legacy::WordPerfect`; the modules holding them are private (`mod legacy;` `crates/rgx-adapters-office/src/lib.rs:55`, `mod markup;` `:57`, `mod ppt;` `:59`, `mod tex;` `:61`, `mod visio;` `:63`, `mod xls;` `:65`).
- The Overview's enumeration of the markup family (reStructuredText, org-mode, MediaWiki wikitext, Jupyter notebooks, Textile, troff/groff man pages) omits four formats the adapter claims: Markdown (`md`, `markdown`, `gfm`), HTML (`html`, `htm`, `xhtml`), Txt2Tags (`t2t`) and FictionBook 2 (`fb2`) — `crates/rgx-adapters-office/src/markup.rs:43-51`.

## crates/rgx-adapters-office/src/EGM.md

- "`pub struct ppt::Ppt`", "`xls::Xls`", "`visio::Visio`", "`tex::Tex`", "`markup::Markup`", "`legacy::AbiWord`", "`legacy::HwpRaw`", "`legacy::WordPerfect`" are listed as the crate's interface, but the modules are private (`mod legacy;` `crates/rgx-adapters-office/src/lib.rs:55`, `mod markup;` `:57`, `mod ppt;` `:59`, `mod tex;` `:61`, `mod visio;` `:63`, `mod xls;` `:65`); only `Office`, `Doc`, `Rtf` and `xml_to_text` are exported.
- The invariant "The ZIP-based members of the 'legacy office' family — ODF's `.sxw`, `.uot`, `.odi`, and UOF's package form — are already container members once the archive adapter opens them, so claiming them again here would only take the extension away from the reader that can actually read them" is contradicted by the code: the `Office` adapter claims `odi` and `odgi` (`crates/rgx-adapters-office/src/lib.rs:717`) and `kind_of` has no mapping for them (`src/lib.rs:113-124`), so those files are claimed and then declined with "unsupported office extension"; and the archive adapter does not claim `odi` at all (`crates/rgx-adapters-archive/src/lib.rs:217` lists only `uof`, `uot`, `uos`, `uop`), while `.sxw` is claimed by a different crate (`crates/rgx-adapters-inspect/src/compound.rs:65`).

## crates/rgx-adapters-pdf/EGM.md

No drift detected.

## crates/rgx-adapters-pdf/src/EGM.md

- "`pub struct PdfReader` with `pub fn parse(...)`, `pub fn page_count`, `pub fn page_text`, `pub fn page_text_with_runs`, `pub fn page_images`, `pub fn all_images`, `pub fn extract_text_with_notes`, `pub fn metadata`" — `PdfReader` has only `parse` (`crates/rgx-adapters-pdf/src/pdf_full.rs:2974-2980`); `page_count` (`:3084`), `page_text` (`:3101`), `page_text_with_runs` (`:3111`), `page_images` (`:3169`), `all_images` (`:3257`), `extract_text_with_notes` (`:3326`) and `metadata` (`:3359`) are methods of `PdfDocument`, not `PdfReader`.
- "`pub struct Extraction` (`text`, `runs`, `notes`)" — the struct has no `notes` field; its fields are `text`, `undecodable`, `missing_fonts`, `pages`, `runs` (`crates/rgx-adapters-pdf/src/pdf_full.rs:3045-3059`).
- "`Extraction` … `page_count()`" — `Extraction` has no `page_count()` method (`crates/rgx-adapters-pdf/src/pdf_full.rs:3061-3080`); `page_count()` belongs to `PdfDocument` (`:3084`), and `Extraction` carries a `pages` field (`:3056`).
- "One piece of hygiene is part of the contract: `Security`'s `Debug` prints nothing about the key" — `Security` implements no `Debug` at all: no derive and no manual impl (`crates/rgx-adapters-pdf/src/security.rs:135-143`); the only `Debug` in the module is on `Method` (`:61`) and `SecurityError` (`:107`).

## crates/rgx-adapters-pdf/src/jbig2/EGM.md

No drift detected.

## crates/rgx-adapters-tabular/EGM.md

- The "Public symbols" list names `pub mod databases` (`pub struct Bson`, `pub struct RedisRdb`, `pub struct Foxpro`), `pub mod eri` (`pub struct Eri`), `pub mod leveldb` (`pub struct LevelDb`), `pub mod lmdb` (`pub struct Lmdb`), `pub mod redis_aof` (`pub struct RedisAof`), `pub mod scientific` (`pub struct MatV5`, `pub struct NetCdf3`, `pub struct ArrowIpc`, `pub struct Hdf5`); all six modules are private (`mod databases;` `crates/rgx-adapters-tabular/src/lib.rs:64`, `mod eri;` `:68`, `mod leveldb;` `:72`, `mod lmdb;` `:74`, `mod redis_aof;` `:80`, `mod scientific;` `:87`).
- "`pub struct Foxpro`" — the code declares `pub(crate) struct Foxpro;` (`crates/rgx-adapters-tabular/src/databases.rs:1986`), not `pub`.
- The list also omits `Slk` (`crates/rgx-adapters-tabular/src/sylk.rs:44`), an adapter registered in `adapters()` (`crates/rgx-adapters-tabular/src/lib.rs:109-110`).

## crates/rgx-adapters-tabular/src/EGM.md

- "`pub mod databases`", "`pub mod eri`", "`pub mod leveldb`", "`pub mod lmdb`", "`pub mod redis_aof`" and "`pub mod scientific`" are all private in the code (`mod databases;` `crates/rgx-adapters-tabular/src/lib.rs:64`, `mod eri;` `:68`, `mod leveldb;` `:72`, `mod lmdb;` `:74`, `mod redis_aof;` `:80`, `mod scientific;` `:87`); only `dif`, `lotus`, `mdb` and `zarr` are `pub mod` (`src/lib.rs:66, 76, 78, 91`).
- "`pub struct Foxpro` (feature `foxpro`)" — the code declares `pub(crate) struct Foxpro;` (`crates/rgx-adapters-tabular/src/databases.rs:1986`).
- The Interface omits the `sylk` module and the `Slk` adapter entirely: `pub struct Slk` (`crates/rgx-adapters-tabular/src/sylk.rs:44`, `name() == "slk"`, `extensions() == &["slk"]` at `src/sylk.rs:46-51`, `Reach::Render` at `src/sylk.rs:63-65`) and its registration in `adapters()` (`crates/rgx-adapters-tabular/src/lib.rs:109-110`).

## crates/rgx-adapters-threed/EGM.md

No drift detected.

## crates/rgx-adapters-threed/src/EGM.md

- "the NIfTI reader requires at least 348 bytes and a `n+1` magic" — the reader requires ≥348 bytes and `sizeof_hdr` ∈ {348, 540} in either endianness (`crates/rgx-adapters-threed/src/lib.rs:2420-2435`); the 4-byte magic at offset 344 is copied and printed verbatim, never validated (`src/lib.rs:2471-2489`), so a file with any other magic is answered, and a NIfTI-2 file (`sizeof_hdr` 540, magic `n+2`) is accepted (`src/lib.rs:2476-2478`).

## EGM.md

No drift detected.

The root blueprint is written against the house's own notes (`AGENTS.md` §1
and §2) and against the code it points at: the twelve libraries under
`crates/`, the ten adapter families, the exit codes, the `no_std` engine, the
member separator, the note beside a file's own bytes, and the gate itself.
Every link in it resolves, and the manifest scan confirms that every edge in
the graph is a path dependency inside the tree.

## crates/EGM.md

No drift detected.

The intermediate blueprint's summaries are the children's own: each one is
the opening of the child's contract, so the roll-up cannot say something the
child does not.

