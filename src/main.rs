// SPDX-License-Identifier: Apache-2.0

//! rgx — search inside everything: ripgrep-compatible search with
//! in-process content adapters (PDF, Office, archives, 3D models, ML model
//! files, databases, e-mail, ...).
//!
//! Architecture: the walker (`walk` module, gitignore semantics as rg)
//! and the searcher (the in-house engine, `engine.rs`) sandwich an adapter
//! pipeline (`rgx-core`). Adapters are sync functions over byte slices; the
//! pipeline — not the adapters — handles archive recursion, depth limits
//! and bail-out. External-tool adapters only spawn when their binary is on
//! PATH and a matching file is actually found.
//!
//! Search layer: files an adapter claims are read and piped through the
//! adapter chain, then searched in memory. Everything else is searched
//! **directly on disk** (read, or memory-mapped where `src/mmap.rs`'s
//! platform default says so) - plain text never gets loaded into the
//! adapter pipeline, so multi-GB logs behave exactly like they do under rg.

use rgx_core::regex::ByteRegex;
use rgx_core::{Context, Result};

mod cache;
mod cli;
mod detector;
mod engine;
mod pick;
mod rc;
mod type_db;
mod walk;

use cli::{generate_completion, App, Arg, ArgMatches, ErrorKind, Shell};
use engine::Searcher as CompatSearcher;
use rgx_core::regex::Matcher as _;
/// An inline string that holds up to `N` bytes on the stack and spills to
/// a heap `String` past that. The interface is a strict subset of
/// `std::string::String` -- `write!`, `len`, `as_str`, `Into<String>` --
/// which is everything the prefix formatter needs and nothing more.
///
/// Sized to fit the typical `{path}:{line}:` prefix (`Cargo.toml:42:` is
/// 14 bytes) on the stack and only spill when the path or the line
/// number column is genuinely wider than the inline capacity.
#[derive(Clone)]
struct Inline<const N: usize> {
    buf: [u8; N],
    len: u16,
    /// `Some` once the prefix has spilled past `N`; `None` while the
    /// bytes are still in `buf`.
    spill: Option<String>,
}

impl<const N: usize> Inline<N> {
    fn new() -> Self {
        Self {
            buf: [0; N],
            len: 0,
            spill: None,
        }
    }
    fn as_str(&self) -> &str {
        match &self.spill {
            Some(s) => s.as_str(),
            None => unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len as usize]) },
        }
    }
    fn as_bytes(&self) -> &[u8] {
        match &self.spill {
            Some(s) => s.as_bytes(),
            None => &self.buf[..self.len as usize],
        }
    }
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn len(&self) -> usize {
        self.spill
            .as_ref()
            .map(String::len)
            .unwrap_or(self.len as usize)
    }
    fn push_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        if let Some(spill) = self.spill.as_mut() {
            spill.push_str(s);
            return;
        }
        if self.len as usize + bytes.len() <= N {
            let dst = &mut self.buf[self.len as usize..self.len as usize + bytes.len()];
            dst.copy_from_slice(bytes);
            self.len += bytes.len() as u16;
        } else {
            let mut heap = String::with_capacity(self.len as usize + bytes.len());
            heap.push_str(self.as_str());
            heap.push_str(s);
            self.spill = Some(heap);
        }
    }
}

impl<const N: usize> core::fmt::Display for Inline<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<const N: usize> core::fmt::Write for Inline<N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

impl<const N: usize> From<Inline<N>> for String {
    fn from(s: Inline<N>) -> String {
        s.spill.unwrap_or_else(|| unsafe {
            String::from_utf8_unchecked(s.buf[..s.len as usize].to_vec())
        })
    }
}
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::IsTerminal;
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use walk::{Builder as WalkBuilder, Override, OverrideBuilder, WalkParallel, WalkState};

use rgx_core::searcher::{
    Config as RgxConfig, ContextKind as RgxContextKind, Sink as RgxSink,
    SinkContext as RgxSinkContext, SinkFinish as RgxSinkFinish, SinkMatch as RgxSinkMatch,
};
use rgx_core::{Ctx, Registry};

/// Resolves `--color <when>` to a single bool. `None` falls back to
/// "TTY only", `always`/`ansi` force on, `never` forces off. Anything
/// else is left as "off" so a typo at least stays quiet.
///
/// **Both costs here were paid per matched file**, from inside the
/// formatting loop on all three output paths, and neither can vary over the
/// life of a run:
///
/// - `spec.map(str::to_ascii_lowercase)` allocated a `String` per call. The
///   comparison is case-insensitive by intent, so `eq_ignore_ascii_case`
///   answers it without the copy and takes the same branches.
/// - the `auto` arm called `stdout().is_terminal()`, which on Windows is
///   `GetStdHandle` plus `GetConsoleMode` — two API calls per matched file.
///   `heading` and `lines` already resolve the identical predicate once,
///   outside their loops; this was the one call site not hoisted with them.
fn color_resolved(spec: Option<&str>) -> bool {
    if let Some(s) = spec {
        if s.eq_ignore_ascii_case("always") || s.eq_ignore_ascii_case("ansi") {
            return true;
        }
        if s.eq_ignore_ascii_case("never") {
            return false;
        }
    }
    // `None` (auto): a TTY gets colour, a pipe does not. rg
    // also gates colour on `is_terminal(stdout)` in its auto
    // arm; the same call here lets piped output stay clean.
    static IS_TTY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *IS_TTY.get_or_init(|| std::io::stdout().is_terminal())
}

/// True when stdin is something to search: a pipe, or a redirected file.
///
/// `IsTerminal` answers the wrong question here. It says "no" for the NUL
/// device and for an inherited console handle as well as for a pipe, and
/// those first two mean "there is no stdin here", not "search this". With
/// `!is_terminal()` as the test, `rgx PATTERN` in a script or a CI step --
/// where stdin is NUL or a dangling handle -- read that empty input and
/// reported no matches, while `rg PATTERN` searched the current directory.
/// rg asks whether the handle is a pipe or a file; so does this.
fn readable_stdin() -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;

        #[link(name = "kernel32")]
        extern "system" {
            fn GetFileType(h_file: *mut core::ffi::c_void) -> u32;
        }

        // FILE_TYPE_PIPE (3) is a pipe and FILE_TYPE_DISK (1) is a
        // redirected file: both are input. FILE_TYPE_CHAR (2) is a console
        // or the NUL device, FILE_TYPE_UNKNOWN (0) a closed or invalid
        // handle: neither is. FFI is inlined rather than pulled from
        // windows-sys, the same choice `mmap::file_len` makes and
        // `memmap2/platform/windows.rs` documents.
        const FILE_TYPE_UNKNOWN: u32 = 0;
        const FILE_TYPE_CHAR: u32 = 2;
        // SAFETY: the handle is the process's own standard input and stays
        // open for the call; `GetFileType` only inspects it and cannot
        // invalidate it. A failure answers UNKNOWN, which is "no stdin".
        let kind = unsafe { GetFileType(std::io::stdin().as_raw_handle().cast()) };
        kind != FILE_TYPE_UNKNOWN && kind != FILE_TYPE_CHAR
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::FileTypeExt;
        use std::os::unix::io::{AsRawFd, BorrowedFd};

        // The same question asked with fstat: a pipe, a socket or a regular
        // file is input, a character device (a terminal, /dev/null) is not.
        let fd = std::io::stdin().as_raw_fd();
        // SAFETY: fd 0 is open for the process lifetime; `borrow_raw` only
        // ties a `BorrowedFd` to it, and the clone below duplicates it so
        // the `File` owns its own descriptor.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        match borrowed.try_clone_to_owned() {
            Ok(owned) => match std::fs::File::from(owned).metadata() {
                Ok(md) => {
                    let ft = md.file_type();
                    ft.is_fifo() || ft.is_socket() || ft.is_file()
                }
                Err(_) => false,
            },
            Err(_) => false,
        }
    }
}

/// ANSI SGR sequences rgx emits when `--color` resolves to true. The
/// codes match ripgrep's choice (bold red for the match, green for
/// line numbers, magenta for the path, dim cyan for columns) and are
/// inline `&'static [u8]` so the per-match wrap costs no allocation.
/// `LINE_GREEN` / `PATH_MAGENTA` / `COL_DIM_CYAN` are surfaced for the
/// `--vimgrep` / `-b` paths and future expansion; clippy flags them
/// as unused today and the `#[allow]` keeps the surface intact.
#[allow(dead_code)]
mod sgr {
    pub const RESET: &[u8] = b"\x1b[0m";
    /// Every style carries ripgrep's leading reset: a styled segment is
    /// `\x1b[0m\x1b[<attrs>m` + text + `\x1b[0m`, with the separators left
    /// plain. The byte layout is copied from `rg --color=always`'s output
    /// (od -c of a multi-file `-n` run) so a colored rgx line and a colored
    /// ripgrep line are the same bytes.
    pub const MATCH_BOLD_RED: &[u8] = b"\x1b[0m\x1b[1m\x1b[31m";
    pub const LINE_GREEN: &[u8] = b"\x1b[0m\x1b[32m";
    pub const PATH_MAGENTA: &[u8] = b"\x1b[0m\x1b[35m";
    pub const COL_DIM_CYAN: &[u8] = b"\x1b[2;36m";
}

/// Search inside everything.
///
/// The fields and their defaults are the contract; `app()` below is the
/// only place that knows how they are spelled on the command line, and
/// `from_matches` is the only place that turns parsed text back into
/// them. Everything else in this file reads `args.field` and does not
/// care which parser produced it.
#[derive(Clone)]
struct Args {
    pattern: Option<String>,
    paths: Vec<String>,
    ignore_case: bool,
    smart_case: bool,
    fixed_strings: bool,
    word_regexp: bool,
    invert_match: bool,
    multiline: bool,
    /// `--multiline-dotall`: implies `-U` and also makes `.` match a newline.
    /// Kept separate because that is how ripgrep splits them — `-U` alone does
    /// NOT let `.` cross a line, and conflating the two would make `rgx -U`
    /// answer differently from `rg -U` on the same pattern.
    multiline_dotall: bool,
    max_count: Option<usize>,
    threads: Option<usize>,
    only_matching: bool,
    replace: Option<String>,
    files_with_matches: bool,
    files_without_match: bool,
    list_files: bool,
    count: bool,
    /// `--sort <key>` — emit the file list in deterministic order.
    /// Only `path` is wired up today; the field is `Option<String>` so
    /// the CLI parser can record the user's choice and the worker can
    /// decide which key to honour.
    sort: Option<String>,
    /// `--sortr <key>` — same as `--sort` but in reverse direction.
    /// When both are present, `--sortr` wins, matching rg.
    sort_reversed: bool,
    quiet: bool,
    json: bool,
    serve: bool,
    /// `--mcp`: speak the Model Context Protocol on stdio.
    ///
    /// JSON-RPC 2.0, one object per line, the same framing `--serve`
    /// uses. The difference is who is asking: `--serve` takes rgx's own
    /// argv arrays, `--mcp` takes the protocol's methods (`initialize`,
    /// `tools/list`, `tools/call`) and offers the tools `search` and
    /// `facts`.
    mcp: bool,
    /// `rgx -0` / `rgx --null`: terminate file-list output with a NUL
    /// instead of `\n`, the shape `xargs -0` and the `find -print0`
    /// pipeline expect. The default of `\n` is what rg and rgx have
    /// always done; the flag is the change.
    null_data: bool,
    after_context: usize,
    before_context: usize,
    context: Option<usize>,
    chunk: Option<usize>,
    glob: Vec<String>,
    /// Skip the hidden files. The hidden files are READ by default: a
    /// format that keeps its own metadata in a dotfile -- a Zarr array's
    /// `.zarray`, a `.zattrs`, a `.gitignore` -- is invisible otherwise,
    /// and a search tool that cannot see the metadata cannot read the
    /// format. This flag puts ripgrep's behaviour back.
    no_hidden: bool,
    no_ignore: bool,
    follow: bool,
    text: bool,
    max_depth: Option<usize>,
    max_filesize: String,
    no_filename: bool,
    line_number: bool,
    no_line_number: bool,
    /// `None` ⇒ auto: heading when stdout is a TTY (rg's default),
    /// `Some(true)` / `Some(false)` when `--heading` / `--no-heading`
    /// is on the command line. When heading=true and multi=true, the
    /// path is printed only on the first match line of a file;
    /// subsequent lines use the single-file `{line}:` shape.
    heading: Option<bool>,
    /// `rgx --column` / `rgx --vimgrep`: print the 1-based column of
    /// the leftmost match in each line as `{path}:{line}:{col}:{text}`.
    /// The shape editors (Neovim, VS Code, Emacs) read to jump
    /// directly to the column of the match. `--vimgrep` is the
    /// same flag with a different name; consumers wire whichever
    /// they want.
    column: bool,
    /// `-E / --encoding <name>`: declare the file encoding, bypassing
    /// BOM detection. Only UTF-8, UTF-16LE and UTF-16BE are wired up
    /// today; other names are accepted as a no-op so downstream
    /// tooling sees the same shape `rg` does.
    encoding: Option<String>,
    max_adapter_depth: usize,
    /// `--filter <expr>`: a structured query over what is known about a
    /// file. `None` when the flag was not given.
    filter: Option<String>,
    /// Extraction cache: directory when the flag is given, `None` when it is
    /// not. Off unless asked for — a wrong default serves stale bytes.
    cache: Option<String>,
    cache_clear: bool,
    cache_prune: bool,
    cache_max_age: usize,
    /// Hand the results to an external picker; see [`pick`].
    pick: bool,
    fzf_binary: Option<String>,
    fzf_args: Vec<String>,
    /// Generator outputs rather than query inputs: handled before any of
    /// the search state is built, because neither takes a pattern.
    completions: Option<String>,
    /// Search engine selection: auto, tv, rgx.
    engine: Option<String>,
    /// prepared-pack storage engine (shorthand for --engine tv).
    tv: bool,
    /// Custom pack store directory.
    tv_store: Option<String>,
    /// Build or update pack store from target directory and exit.
    tv_build: bool,
    /// Pre-extract adapter text during pack build.
    tv_pre_extract: bool,
    /// Build a token index for the target directory and exit.
    ///
    /// Writes a single `.ugi` file into the directory named by
    /// `--index-store` (default `<root>/.rgx-idx.ugi`). The next run
    /// with `--index <root>` loads it and uses the candidates it
    /// returns to skip the work the byte engine would have done
    /// scanning every line of every file. The format is rgx's own;
    /// the flag is ugrep-compatible.
    index_build: Option<String>,
    /// Load a token index from the named directory and use it to
    /// answer queries. Without this, rgx walks the corpus every run.
    index_dir: Option<String>,
    /// Where `--index-build` writes its `.ugi` file. Defaults to
    /// `<index-dir>/.rgx-idx.ugi`, then to `<root>/.rgx-idx.ugi`
    /// when `--index-dir` is not set.
    index_store: Option<String>,
    /// Build a persistent index of the facts of every file under the named
    /// directory, and exit.
    ///
    /// The facts are what the pipeline knows about a file: the path, the
    /// extension, the format, the MIME type, and whatever the adapter that
    /// answered for it reported. The filter asks the same question of
    /// every file, every run; the index asks it once and keeps the answer.
    ///
    /// The index is written to `--facts-store` (default
    /// `<root>/.rgx-facts.jsonl`) as JSON Lines: one object per path, one
    /// line per object, so the index can be read with `rg` itself.
    facts_build: Option<String>,
    /// Answer `--filter` from the persistent facts index in the named
    /// directory, instead of walking the corpus.
    ///
    /// This is the query language over the index: the same `--filter`
    /// expression the walk applies per file, applied here to the facts
    /// that were kept. A corpus that changes once is walked once.
    facts_index: Option<String>,
    /// Write the facts index to the named file as JSON Lines, and exit.
    facts_export: Option<String>,
    /// Where `--facts-build` writes the index. Defaults to
    /// `<root>/.rgx-facts.jsonl` when `--facts-store` is not set.
    facts_store: Option<String>,
    /// Measure both pack engines on one pattern and report which one won.
    tv_verify: Option<String>,
    /// Explain the automatic engine detector's decision and rationale on stderr.
    explain_engine: bool,
    /// Print the in-process stage decomposition of a pack-store query on
    /// stderr. Opt-in like `--explain-engine`: a tool that speaks on stderr
    /// when nobody asked is a tool whose stderr nobody reads.
    stats: bool,
    /// Skip the per-record freshness walk and answer wholly from the store.
    /// The caller asserts the corpus has not moved since the store was built;
    /// the store is then not asked and does not guess. See
    /// `benchmark/ladder-findings.md` 25: on a 20,000-record store the walk
    /// is 20,000 `stat` calls and about 40 ms of every query.
    tv_assume_fresh: bool,
    /// The type selections, in the order the command line gave them.
    ///
    /// `-t X` selects a type and `-T X` negates one, and ripgrep's rule
    /// is that the last one that matches a file decides — so the two
    /// kinds have to keep their places relative to each other, not just
    /// their own.
    types: Vec<walk::TypeSel>,
    /// Extend the type table (repeatable `--type-add 'name:ext,ext'`).
    type_add: Vec<String>,
    /// Wipe every entry from the type table (`--type-clear`).
    type_clear: bool,
    /// Print the registered type table and exit (`--type-list`).
    type_list: bool,
    /// `--color when`: wrap match spans, line numbers and paths in
    /// ANSI SGR sequences. `None` means auto (TTY -> colour, pipe ->
    /// off); `Some("never")` suppresses; `Some("always")` or
    /// `Some("ansi")` forces colour regardless of TTY. The string is
    /// stored verbatim so the struct stays trivially Clone-able
    /// without a hand-rolled enum that has to live above the struct
    /// definition (Rust has no forward declarations).
    color: Option<String>,
}

/// The formats this build carries, in the order of the `format-*` features.
///
/// One entry per feature, so the list is the build's own truth: a binary
/// built without `format-zip` does not claim to read zip. The name of each
/// entry is the name the adapter itself reports, which is the string `--json`
/// prints in the `format` field.
// The list is built with a push per feature because a `vec!` cannot hold
// elements that are individually `#[cfg]`-ed out.
#[allow(clippy::vec_init_then_push)]
fn built_formats() -> Vec<&'static str> {
    // `mut` only when a format is in the build: the engine alone never
    // pushes, and `unused_mut` is a warning.
    #[allow(unused_mut)]
    let mut v: Vec<&'static str> = Vec::new();
    #[cfg(feature = "format-zip")]
    v.push("zip");
    #[cfg(feature = "format-7z")]
    v.push("7z");
    #[cfg(feature = "format-tar")]
    v.push("tar");
    #[cfg(feature = "format-cpio")]
    v.push("cpio");
    #[cfg(feature = "format-ar")]
    v.push("ar");
    #[cfg(feature = "format-git-pack")]
    v.push("git-pack");
    #[cfg(feature = "format-git-bundle")]
    v.push("git-bundle");
    #[cfg(feature = "format-svn-dump")]
    v.push("svn-dump");
    #[cfg(feature = "format-decompress")]
    v.push("decompress");
    #[cfg(feature = "format-rar")]
    v.push("rar");
    #[cfg(feature = "format-pgdump")]
    v.push("pgdump");
    #[cfg(feature = "format-borg")]
    v.push("borg");
    #[cfg(feature = "format-iso9660")]
    v.push("iso9660");
    #[cfg(feature = "format-img")]
    v.push("img");
    #[cfg(feature = "format-applefs")]
    v.push("applefs");
    #[cfg(feature = "format-vhd")]
    v.push("vhd");
    #[cfg(feature = "format-vhdx")]
    v.push("vhdx");
    #[cfg(feature = "format-qcow2")]
    v.push("qcow2");
    #[cfg(feature = "format-vmdk")]
    v.push("vmdk");
    #[cfg(feature = "format-vdi")]
    v.push("vdi");
    #[cfg(feature = "format-wim")]
    v.push("wim");
    #[cfg(feature = "format-erofs")]
    v.push("erofs");
    #[cfg(feature = "format-squashfs")]
    v.push("squashfs");
    #[cfg(feature = "format-soffice")]
    v.push("soffice");
    #[cfg(feature = "format-ocr")]
    v.push("ocr");
    #[cfg(feature = "format-pe-resources")]
    v.push("pe-resources");
    #[cfg(feature = "format-inspect")]
    v.push("inspect");
    #[cfg(feature = "format-macho-strings")]
    v.push("macho-strings");
    #[cfg(feature = "format-elf-provenance")]
    v.push("elf-provenance");
    #[cfg(feature = "format-dex-strings")]
    v.push("dex-strings");
    #[cfg(feature = "format-wasm")]
    v.push("wasm");
    #[cfg(feature = "format-wasm-meta")]
    v.push("wasm-meta");
    #[cfg(feature = "format-lnk")]
    v.push("lnk");
    #[cfg(feature = "format-x509")]
    v.push("x509");
    #[cfg(feature = "format-ole2-compound")]
    v.push("ole2-compound");
    #[cfg(feature = "format-bplist")]
    v.push("bplist");
    #[cfg(feature = "format-tiff-pages")]
    v.push("tiff-pages");
    #[cfg(feature = "format-djvu")]
    v.push("djvu");
    #[cfg(feature = "format-isobmff")]
    v.push("isobmff");
    #[cfg(feature = "format-dwg")]
    v.push("dwg");
    #[cfg(feature = "format-parasolid-xt")]
    v.push("parasolid-xt");
    #[cfg(feature = "format-acis-sab")]
    v.push("acis-sab");
    #[cfg(feature = "format-rvt")]
    v.push("rvt");
    #[cfg(feature = "format-dgn")]
    v.push("dgn");
    #[cfg(feature = "format-dxf")]
    v.push("dxf");
    #[cfg(feature = "format-step")]
    v.push("step");
    #[cfg(feature = "format-iges")]
    v.push("iges");
    #[cfg(feature = "format-acis-sat")]
    v.push("acis-sat");
    #[cfg(feature = "format-stl-ascii")]
    v.push("stl-ascii");
    #[cfg(feature = "format-cgm")]
    v.push("cgm");
    #[cfg(feature = "format-cals")]
    v.push("cals");
    #[cfg(feature = "format-edmics-c4")]
    v.push("edmics-c4");
    #[cfg(feature = "format-plt")]
    v.push("plt");
    #[cfg(feature = "format-grib")]
    v.push("grib");
    #[cfg(feature = "format-bufr")]
    v.push("bufr");
    #[cfg(feature = "format-segy")]
    v.push("segy");
    #[cfg(feature = "format-root")]
    v.push("root");
    #[cfg(feature = "format-n5")]
    v.push("n5");
    #[cfg(feature = "format-firebird")]
    v.push("firebird");
    #[cfg(feature = "format-bam")]
    v.push("bam");
    #[cfg(feature = "format-bcf")]
    v.push("bcf");
    #[cfg(feature = "format-cram")]
    v.push("cram");
    #[cfg(feature = "format-sam")]
    v.push("sam");
    #[cfg(feature = "format-fasta")]
    v.push("fasta");
    #[cfg(feature = "format-fastq")]
    v.push("fastq");
    #[cfg(feature = "format-vcf")]
    v.push("vcf");
    #[cfg(feature = "format-gff")]
    v.push("gff");
    #[cfg(feature = "format-pdb")]
    v.push("pdb");
    #[cfg(feature = "format-mmcif")]
    v.push("mmcif");
    #[cfg(feature = "format-gguf")]
    v.push("gguf");
    #[cfg(feature = "format-safetensors")]
    v.push("safetensors");
    #[cfg(feature = "format-npy")]
    v.push("npy");
    #[cfg(feature = "format-protobuf")]
    v.push("protobuf");
    #[cfg(feature = "format-tiktoken")]
    v.push("tiktoken");
    #[cfg(feature = "format-keras")]
    v.push("keras");
    #[cfg(feature = "format-torch")]
    v.push("torch");
    #[cfg(feature = "format-pickle")]
    v.push("pickle");
    #[cfg(feature = "format-mbox")]
    v.push("mbox");
    #[cfg(feature = "format-eml")]
    v.push("eml");
    #[cfg(feature = "format-msg")]
    v.push("msg");
    #[cfg(feature = "format-emlx")]
    v.push("emlx");
    #[cfg(feature = "format-pst")]
    v.push("pst");
    #[cfg(feature = "format-wab")]
    v.push("wab");
    #[cfg(feature = "format-mmdf")]
    v.push("mmdf");
    #[cfg(feature = "format-msf")]
    v.push("msf");
    #[cfg(feature = "format-mailbox-index")]
    v.push("mailbox-index");
    #[cfg(feature = "format-exif")]
    v.push("exif");
    #[cfg(feature = "format-tiff")]
    v.push("tiff");
    #[cfg(feature = "format-gif")]
    v.push("gif");
    #[cfg(feature = "format-bmp")]
    v.push("bmp");
    #[cfg(feature = "format-psd")]
    v.push("psd");
    #[cfg(feature = "format-jpeg2000")]
    v.push("jpeg2000");
    #[cfg(feature = "format-jpegxl")]
    v.push("jpegxl");
    #[cfg(feature = "format-openexr")]
    v.push("openexr");
    #[cfg(feature = "format-avi")]
    v.push("avi");
    #[cfg(feature = "format-asf")]
    v.push("asf");
    #[cfg(feature = "format-flv")]
    v.push("flv");
    #[cfg(feature = "format-mpeg")]
    v.push("mpeg");
    #[cfg(feature = "format-audiotags")]
    v.push("audiotags");
    #[cfg(feature = "format-fits")]
    v.push("fits");
    #[cfg(feature = "format-dicom")]
    v.push("dicom");
    #[cfg(feature = "format-font")]
    v.push("font");
    #[cfg(feature = "format-woff")]
    v.push("woff");
    #[cfg(feature = "format-mobi")]
    v.push("mobi");
    #[cfg(feature = "format-videotags")]
    v.push("videotags");
    #[cfg(feature = "format-office")]
    v.push("office");
    #[cfg(feature = "format-rtf")]
    v.push("rtf");
    #[cfg(feature = "format-doc")]
    v.push("doc");
    #[cfg(feature = "format-ppt")]
    v.push("ppt");
    #[cfg(feature = "format-xls")]
    v.push("xls");
    #[cfg(feature = "format-tex")]
    v.push("tex");
    #[cfg(feature = "format-visio")]
    v.push("visio");
    #[cfg(feature = "format-markup")]
    v.push("markup");
    #[cfg(feature = "format-abiword")]
    v.push("abiword");
    #[cfg(feature = "format-hwp-raw")]
    v.push("hwp-raw");
    #[cfg(feature = "format-wordperfect")]
    v.push("wordperfect");
    #[cfg(feature = "format-pdf")]
    v.push("pdf");
    #[cfg(feature = "format-sqlite")]
    v.push("sqlite");
    #[cfg(feature = "format-duckdb")]
    v.push("duckdb");
    #[cfg(feature = "format-foxpro")]
    v.push("foxpro");
    #[cfg(feature = "format-dbf")]
    v.push("dbf");
    #[cfg(feature = "format-slk")]
    v.push("slk");
    #[cfg(feature = "format-dif")]
    v.push("dif");
    #[cfg(feature = "format-lotus123")]
    v.push("lotus123");
    #[cfg(feature = "format-mdb")]
    v.push("mdb");
    #[cfg(feature = "format-lmdb")]
    v.push("lmdb");
    #[cfg(feature = "format-shp")]
    v.push("shp");
    #[cfg(feature = "format-parquet")]
    v.push("parquet");
    #[cfg(feature = "format-eri")]
    v.push("eri");
    #[cfg(feature = "format-mat")]
    v.push("mat");
    #[cfg(feature = "format-netcdf")]
    v.push("netcdf");
    #[cfg(feature = "format-arrow")]
    v.push("arrow");
    #[cfg(feature = "format-hdf5")]
    v.push("hdf5");
    #[cfg(feature = "format-bson")]
    v.push("bson");
    #[cfg(feature = "format-redis-rdb")]
    v.push("redis-rdb");
    #[cfg(feature = "format-redis-aof")]
    v.push("redis-aof");
    #[cfg(feature = "format-leveldb")]
    v.push("leveldb");
    #[cfg(feature = "format-zarr")]
    v.push("zarr");
    #[cfg(feature = "format-glb")]
    v.push("glb");
    #[cfg(feature = "format-stl")]
    v.push("stl");
    #[cfg(feature = "format-ply")]
    v.push("ply");
    #[cfg(feature = "format-fbx")]
    v.push("fbx");
    #[cfg(feature = "format-pcd")]
    v.push("pcd");
    #[cfg(feature = "format-las")]
    v.push("las");
    #[cfg(feature = "format-vtk")]
    v.push("vtk");
    #[cfg(feature = "format-blend")]
    v.push("blend");
    #[cfg(feature = "format-3ds")]
    v.push("3ds");
    #[cfg(feature = "format-nifti")]
    v.push("nifti");
    #[cfg(feature = "format-mrc")]
    v.push("mrc");
    v
}

/// The version string: the version, and the formats this build carries.
///
/// A build with no adapter at all -- the engine alone -- prints the version
/// alone, because there is nothing to list.
fn version_string() -> String {
    let mut formats = built_formats();
    if formats.is_empty() {
        return env!("CARGO_PKG_VERSION").to_string();
    }
    // Sorted: the order the features are written in is the order the crates
    // are listed in, not the order a reader wants.
    formats.sort_unstable();
    format!(
        "{}\nformats: {}",
        env!("CARGO_PKG_VERSION"),
        formats.join(", ")
    )
}

/// The command line, as an argument grammar.
///
/// Order matters in one place only: the two positionals, which fill in
/// declaration order.
fn app() -> App {
    App::new("rgx")
        .version(version_string())
        .about("Search inside everything. Ripgrep-compatible search with native in-process
  adapters for PDF, Office, archives, 3D models, ML model files,
  databases, e-mail, and more. A few external tools (soffice, tesseract,
  ...) are used when present on PATH.
  Defaults are read from `.rgxrc` before argv is parsed: $RGX_CONFIG_PATH,
  then ./.rgxrc, then ~/.rgxrc, then ~/.config/rgx/rgxrc. Each line is
  prepended to argv, so CLI flags win over the file.")
        .arg(Arg::new("pattern").positional(true).help("pattern (regex); optional when --files is given"))
        .arg(Arg::new("paths").positional(true).multiple(true)
            .help("files or directories ('-' = stdin; default: stdin when piped, else .)"))
        .arg(Arg::new("ignore_case").short('i').long("ignore-case").help("case-insensitive"))
        .arg(Arg::new("smart_case").short('S').long("smart-case")
            .help("smart case: case-insensitive when pattern is all lowercase"))
        .arg(Arg::new("fixed_strings").short('F').long("fixed-strings")
            .help("treat pattern as a literal string"))
        .arg(Arg::new("word_regexp").short('w').long("word-regexp").help("match whole words only"))
        .arg(Arg::new("invert_match").short('v').long("invert-match")
            .help("invert match: select non-matching lines"))
        .arg(Arg::new("multiline").short('U').long("multiline")
            .help("permit matches to span multiple lines; a multi-line match is reported on \
                   the line it ends on. `.` still does not match a newline — that is \
                   --multiline-dotall, as in ripgrep"))
        .arg(Arg::new("multiline_dotall").long("multiline-dotall")
            .help("like --multiline, and also make `.` match a newline"))
        .arg(Arg::new("threads").short('j').long("threads").takes_value(true)
            .help("threads to use; a number, or `auto` for every available one (the default)"))
        .arg(Arg::new("max_count").short('m').long("max-count").takes_value(true)
            .help("stop after NUM matching lines per file"))
        .arg(Arg::new("only_matching").short('o').long("only-matching")
            .help("print only the matched parts of each line"))
        .arg(Arg::new("replace").short('r').long("replace").takes_value(true)
            .help("replace matches with this text in the output ($1/${name} supported)"))
        .arg(Arg::new("files_with_matches").short('l').long("files-with-matches")
            .help("print only files with matches"))
        .arg(Arg::new("sort").long("sort").takes_value(true)
            .possible_values(vec!["path".into()])
            .help("sort the file list deterministically (path)"))
        .arg(Arg::new("sortr").long("sortr").takes_value(true)
            .possible_values(vec!["path".into()])
            .help("sort the file list in reverse (path)"))
        // No short flag: ripgrep 15 moved `--follow` onto `-L` and left
        // `--files-without-match` long-only, and that is the spelling rgx
        // accepts. The pre-15 reading of `-L` is this project's older
        // compatibility choice and is now closed; see the flag parity test
        // in `tests/cli.rs`.
        .arg(Arg::new("files_without_match").long("files-without-match")
            .help("print only files WITHOUT matches (no short flag, as in ripgrep 15)"))
        .arg(Arg::new("list_files").long("files")
            .help("list files that would be searched (no searching)"))
        .arg(Arg::new("count").short('c').long("count")
            .help("print only the count of matching lines per file"))
        .arg(Arg::new("quiet").short('q').long("quiet")
            .help("quiet: exit 0 on first match, print nothing"))
        .arg(Arg::new("json").long("json")
            .help("machine-readable JSON stream (rg --json compatible)"))
        .arg(Arg::new("serve").long("serve")
            .help("serve mode: read one JSON argv-array query per line on stdin, answer on stdout framed by begin/end sentinels"))
        .arg(Arg::new("mcp").long("mcp")
            .help("MCP mode: speak the Model Context Protocol on stdio (JSON-RPC 2.0, one object per line); offers the tools 'search' and 'facts'"))
        .arg(Arg::new("null").short('0').long("null")
            .help("terminate file-list output with a NUL instead of \\n (use with xargs -0 and find -print0)"))
        .arg(Arg::new("after_context").short('A').long("after-context").takes_value(true).default("0")
            .help("show NUM lines after each match"))
        .arg(Arg::new("before_context").short('B').long("before-context").takes_value(true).default("0")
            .help("show NUM lines before each match"))
        .arg(Arg::new("context").short('C').long("context").takes_value(true)
            .help("show NUM lines around each match (shorthand for -A NUM -B NUM)"))
        .arg(Arg::new("chunk").long("chunk").optional_value("2048")
            .help("emit a paragraph-aware context chunk of BYTES around each match (default 2048 when bare), as `path:line` headers plus chunk text — sized for feeding LLM context windows"))
        .arg(Arg::new("glob").short('g').long("glob").multiple(true)
            .help("glob to include/exclude (repeatable), e.g. -g '*.zip' -g '!*.tar'"))
        .arg(Arg::new("types_include").short('t').long("type").multiple(true).takes_value(true)
            .help("only search files matching TYPE (repeatable), e.g. -t rust -t python"))
        .arg(Arg::new("types_exclude").short('T').long("type-not").multiple(true).takes_value(true)
            .help("exclude files matching TYPE (repeatable), e.g. -T minified"))
        .arg(Arg::new("type_add").long("type-add").multiple(true).takes_value(true)
            .help("add TYPE:ext,ext to the type table (repeatable), e.g. --type-add 'web:html,css,js'"))
        .arg(Arg::new("type_clear").long("type-clear")
            .help("clear every type from the type table before applying --type-add"))
        .arg(Arg::new("type_list").long("type-list")
            .help("print the registered type table and exit"))
        .arg(Arg::new("hidden").long("hidden").help("search hidden files (the default; accepted for compatibility)"))
        .arg(Arg::new("no_hidden").long("no-hidden").help("skip hidden files, the way ripgrep does by default"))
        .arg(Arg::new("no_ignore").long("no-ignore").help("don't respect ignore files"))
        .arg(Arg::new("follow").short('L').long("follow").help("follow symbolic links"))
        .arg(Arg::new("text").short('a').long("text").help("search binary files as if they were text"))
        .arg(Arg::new("max_depth").long("max-depth").takes_value(true).help("maximum directory depth"))
        .arg(Arg::new("max_filesize").short('M').long("max-filesize").takes_value(true).default("1G")
            .help("skip files larger than this (e.g. 100M)"))
        .arg(Arg::new("no_filename").short('I').long("no-filename").help("don't print filenames"))
        .arg(Arg::new("heading").long("heading").help("print the file path above matches, not before every line"))
        .arg(Arg::new("no_heading").long("no-heading")
            .help("print the file path before every match line (default when stdout is not a TTY)"))
        .arg(Arg::new("line_number").short('n').long("line-number")
            .help("show line numbers (default: on only when stdout is a terminal, as in rg)"))
        .arg(Arg::new("no_line_number").short('N').long("no-line-number")
            .help("hide line numbers (wins over --line-number; rg instead lets the last of the two win)"))
        .arg(Arg::new("column").long("column")
            .help("print the 1-based byte column of each match (editor integration: {path}:{line}:{col}:{text})"))
        .arg(Arg::new("vimgrep").long("vimgrep")
            .help("emacs/vim friendly output: {path}:{line}:{col}:{text}; implies --column"))
        .arg(Arg::new("encoding").short('E').long("encoding").takes_value(true)
            .possible_values(vec!["utf-8".into(), "utf-16le".into(), "utf-16be".into()])
            .help("decode input as the named encoding (utf-8, utf-16le, utf-16be)"))
        .arg(Arg::new("color").long("color").takes_value(true)
            .possible_values(vec!["auto".into(), "always".into(), "ansi".into(), "never".into()])
            .help("ANSI colour the output: auto (default), always, ansi, never"))
        .arg(Arg::new("max_adapter_depth").long("max-adapter-depth").takes_value(true).default("4")
            .help("maximum archive nesting depth for adapters"))
        .arg(Arg::new("filter").long("filter").takes_value(true)
            .help("keep only the files whose facts satisfy the expression: 'mime:pdf AND author:\"Jane\"', 'NOT ext:zip', 'archive.entry:>3'. The facts are the path, the extension, the format, the MIME type, the language, and what the adapters report."))
        .arg(Arg::new("cache").long("cache").optional_value("")
            .help("memo of adapter output, keyed by path+mtime+adapter version+config; bare uses $RGX_CACHE_DIR or ~/.rgx/cache, --cache=DIR names another. Off by default."))
        .arg(Arg::new("cache_clear").long("cache-clear")
            .help("delete the extraction cache and exit"))
        .arg(Arg::new("cache_prune").long("cache-prune")
            .help("drop extraction-cache entries older than --cache-max-age, then the oldest until the cache fits its size budget, and exit"))
        .arg(Arg::new("cache_max_age").long("cache-max-age").takes_value(true).default("30")
            .help("age in days at which --cache-prune drops an entry"))
        .arg(Arg::new("pick").long("pick")
            .help("send the results to fzf and print the selection (exit 0 picked, 1 nothing or dismissed, 2 no fzf)"))
        .arg(Arg::new("fzf_binary").long("fzf-binary").takes_value(true)
            .help("picker binary for --pick (default: the first of fzf, fz found on PATH)"))
        .arg(Arg::new("fzf_args").long("fzf-arg").multiple(true)
            .help("one argument passed through to the picker (repeatable), e.g. --fzf-arg=--multi"))
        .arg(Arg::new("completions").long("completions").takes_value(true)
            .possible_values(Shell::ALL.iter().map(|s| s.name().to_string()).collect())
            .help("print a shell completion script for SHELL, generated from the flags above"))
        .arg(Arg::new("engine").long("engine").takes_value(true)
            .possible_values(vec!["auto".into(), "tv".into(), "rgx".into()])
            .help("search engine: auto (adaptive detector), tv (pack store), rgx (in-process SIMD)"))
        .arg(Arg::new("tv").long("tv")
            .help("use prepared-pack storage engine (shorthand for --engine tv)"))
        .arg(Arg::new("tv_store").long("tv-store").takes_value(true)
            .help("directory for pack storage (contains manifest.tvm and .tvp files)"))
        .arg(Arg::new("tv_build").long("tv-build")
            .help("build or update pack store from target directory and exit"))
        .arg(Arg::new("tv_pre_extract").long("tv-pre-extract")
            .help("pre-extract adapter text during pack build for instant sub-millisecond queries"))
        .arg(Arg::new("index_build").long("index-build").takes_value(true)
            .help("build a token index for the named directory and exit (writes .ugi into --index-store)"))
        .arg(Arg::new("index_dir").long("index").takes_value(true)
            .help("load the token index from the named directory and use it to answer queries"))
        .arg(Arg::new("index_store").long("index-store").takes_value(true)
            .help("where --index-build writes the .ugi file (default: <root>/.rgx-idx.ugi)"))
        .arg(Arg::new("facts_build").long("facts-build").takes_value(true)
            .help("build a persistent index of the facts of every file under the named directory and exit"))
        .arg(Arg::new("facts_index").long("facts-index").takes_value(true)
            .help("answer --filter from the persistent facts index in the named directory, without walking the corpus"))
        .arg(Arg::new("facts_export").long("facts-export").takes_value(true)
            .help("write the facts index to the named file as JSON Lines, and exit"))
        .arg(Arg::new("facts_store").long("facts-store").takes_value(true)
            .help("where --facts-build writes the index (default: <root>/.rgx-facts.jsonl)"))
        .arg(Arg::new("tv_verify").long("tv-verify").takes_value(true)
            .help("measure the in-house engine on this pattern over the pack store, report which is faster, and exit"))
        .arg(Arg::new("explain_engine").long("explain-engine")
            .help("explain the automatic engine detector's decision and rationale on stderr"))
        .arg(Arg::new("stats").long("stats")
            .help("print the in-process stage decomposition of a pack-store query on stderr"))
        .arg(Arg::new("tv_assume_fresh").long("tv-assume-fresh")
            .help("answer wholly from the pack store: skip the per-record freshness walk, on the caller's word that the corpus has not moved"))
}

/// Every logical processor the machine has, which is what "automatic" means.
fn all_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

/// A value the grammar accepted but that is not a number.
///
/// The parser deals in text; seven fields are numbers. Saying which one
/// went wrong beats a generic "invalid digit found in string" from deep
/// inside a conversion. The message spells the flag the way the user
/// typed it — `--max-count`, not the grammar's `max_count`.
fn number(name: &str, raw: &str) -> Result<usize> {
    let flag = name.replace('_', "-");
    raw.parse::<usize>()
        .map_err(|_| rgx_core::anyhow!("invalid value '{raw}' for '--{flag}': expected a number"))
}

impl Args {
    /// Reads a boolean flag.
    fn flag(m: &ArgMatches, name: &str) -> bool {
        m.is_present(name)
    }

    /// Reads a text option.
    fn text(m: &ArgMatches, name: &str) -> Option<String> {
        m.value_of(name).map(str::to_string)
    }

    /// Reads a numeric option, if given.
    fn opt_num(m: &ArgMatches, name: &str) -> Result<Option<usize>> {
        match m.value_of(name) {
            Some(raw) => Ok(Some(number(name, raw)?)),
            None => Ok(None),
        }
    }

    /// Reads a numeric option that has a default in the grammar.
    fn num(m: &ArgMatches, name: &str) -> Result<usize> {
        Ok(Self::opt_num(m, name)?.unwrap_or(0))
    }

    /// A thread count, where the user may also say they do not care.
    ///
    /// `auto` (and `all`) is `None`, which is also what no flag at all gives:
    /// "use everything available" is the default, and being able to type it
    /// means a script can say so instead of inheriting it. An explicit 0 is
    /// the same word as ripgrep's, where it means "ask the OS".
    fn opt_num_or_auto(m: &ArgMatches, name: &str) -> Result<Option<usize>> {
        match m.value_of(name) {
            None => Ok(None),
            Some(raw) if raw.eq_ignore_ascii_case("auto") || raw.eq_ignore_ascii_case("all") => {
                Ok(None)
            }
            Some("0") => Ok(None),
            Some(raw) => Ok(Some(number(name, raw)?)),
        }
    }

    /// Reads a repeatable option.
    fn list(m: &ArgMatches, name: &str) -> Vec<String> {
        m.values_of(name)
            .map(<[String]>::to_vec)
            .unwrap_or_default()
    }

    /// Reads the type selections in the order the command line gave them.
    ///
    /// `-t` and `-T` are read together because their order is the
    /// rule: the last one that matches a file decides, so `-t js -T
    /// minified` and `-T minified -t js` are different queries.
    fn type_selections(m: &ArgMatches) -> Vec<walk::TypeSel> {
        m.values_in_order(&["types_include", "types_exclude"])
            .into_iter()
            .map(|(name, value)| walk::TypeSel {
                name: value.to_string(),
                negate: name == "types_exclude",
            })
            .collect()
    }

    fn from_matches(m: &ArgMatches) -> Result<Self> {
        Ok(Self {
            pattern: Self::text(m, "pattern"),
            paths: Self::list(m, "paths"),
            ignore_case: Self::flag(m, "ignore_case"),
            smart_case: Self::flag(m, "smart_case"),
            fixed_strings: Self::flag(m, "fixed_strings"),
            word_regexp: Self::flag(m, "word_regexp"),
            invert_match: Self::flag(m, "invert_match"),
            multiline: Self::flag(m, "multiline"),
            multiline_dotall: Self::flag(m, "multiline_dotall"),
            max_count: Self::opt_num(m, "max_count")?,
            threads: Self::opt_num_or_auto(m, "threads")?,
            only_matching: Self::flag(m, "only_matching"),
            replace: Self::text(m, "replace"),
            files_with_matches: Self::flag(m, "files_with_matches"),
            files_without_match: Self::flag(m, "files_without_match"),
            list_files: Self::flag(m, "list_files"),
            count: Self::flag(m, "count"),
            // `--sort path` and `--sortr path` collide on the buffer
            // shape; `--sortr` wins if both are present, matching rg.
            // Anything other than `path` is recorded but not yet
            // honoured — the surface stays open for future keys.
            sort: {
                let s = Self::text(m, "sort");
                let r = Self::text(m, "sortr");
                r.or(s)
            },
            sort_reversed: Self::flag(m, "sortr"),
            quiet: Self::flag(m, "quiet"),
            json: Self::flag(m, "json"),
            serve: Self::flag(m, "serve"),
            mcp: Self::flag(m, "mcp"),
            null_data: Self::flag(m, "null"),
            after_context: Self::num(m, "after_context")?,
            before_context: Self::num(m, "before_context")?,
            context: Self::opt_num(m, "context")?,
            chunk: Self::opt_num(m, "chunk")?,
            glob: Self::list(m, "glob"),
            no_hidden: Self::flag(m, "no_hidden"),
            no_ignore: Self::flag(m, "no_ignore"),
            follow: Self::flag(m, "follow"),
            text: Self::flag(m, "text"),
            max_depth: Self::opt_num(m, "max_depth")?,
            max_filesize: Self::text(m, "max_filesize").unwrap_or_else(|| "1G".to_string()),
            no_filename: Self::flag(m, "no_filename"),
            line_number: Self::flag(m, "line_number"),
            no_line_number: Self::flag(m, "no_line_number"),
            // `--heading` and `--no-heading` are mutually exclusive;
            // the default is resolved later against the stdout TTY
            // state, so we record `Some(true)` / `Some(false)` only when
            // the user expressed a preference.
            heading: {
                let h = Self::flag(m, "heading");
                let nh = Self::flag(m, "no_heading");
                if h {
                    Some(true)
                } else if nh {
                    Some(false)
                } else {
                    None
                }
            },
            // `--vimgrep` is a shape alias for `--column`: the output
            // format is the same and the consumer (editors) is the same.
            // OR-ing the two is the same OR rg does.
            column: Self::flag(m, "column") || Self::flag(m, "vimgrep"),
            encoding: Self::text(m, "encoding"),
            // `--color` accepts auto/always/ansi/never. Anything not
            // listed is recorded verbatim so a typo at least surfaces
            // later instead of being silently re-mapped.
            color: Self::text(m, "color"),
            max_adapter_depth: Self::num(m, "max_adapter_depth")?,
            filter: Self::text(m, "filter"),
            cache: Self::text(m, "cache"),
            cache_clear: Self::flag(m, "cache_clear"),
            cache_prune: Self::flag(m, "cache_prune"),
            cache_max_age: Self::num(m, "cache_max_age")?,
            pick: Self::flag(m, "pick"),
            fzf_binary: Self::text(m, "fzf_binary"),
            fzf_args: Self::list(m, "fzf_args"),
            completions: Self::text(m, "completions"),
            engine: Self::text(m, "engine"),
            tv: Self::flag(m, "tv"),
            tv_store: Self::text(m, "tv_store"),
            tv_build: Self::flag(m, "tv_build"),
            tv_pre_extract: Self::flag(m, "tv_pre_extract"),
            index_build: Self::text(m, "index_build"),
            index_dir: Self::text(m, "index_dir"),
            index_store: Self::text(m, "index_store"),
            facts_build: Self::text(m, "facts_build"),
            facts_index: Self::text(m, "facts_index"),
            facts_export: Self::text(m, "facts_export"),
            facts_store: Self::text(m, "facts_store"),
            tv_verify: Self::text(m, "tv_verify"),
            explain_engine: Self::flag(m, "explain_engine"),
            stats: Self::flag(m, "stats"),
            tv_assume_fresh: Self::flag(m, "tv_assume_fresh"),
            types: Self::type_selections(m),
            type_add: Self::list(m, "type_add"),
            type_clear: Self::flag(m, "type_clear"),
            type_list: Self::flag(m, "type_list"),
        })
    }

    /// Parses `argv`, handling `--help` and `--version` the way a CLI
    /// should: printed to stdout, exit 0, rather than an error the user
    /// has to read on stderr.
    fn parse_from<I, T>(argv: I) -> Result<Self>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let argv: Vec<String> = argv.into_iter().map(|s| s.as_ref().to_string()).collect();
        match app().parse_from(argv.iter().map(String::as_str)) {
            Ok(m) => Self::from_matches(&m),
            Err(e) => match e.kind {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                    println!("{}", e.message);
                    std::process::exit(0);
                }
                _ => Err(rgx_core::anyhow!("{}", e.message)),
            },
        }
    }

    /// Parses `argv` and reports failures as text, for the --serve path
    /// where the error belongs in a JSON frame rather than on stderr.
    fn try_parse_from<I, T>(argv: I) -> std::result::Result<Self, String>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<str>,
    {
        let argv: Vec<String> = argv.into_iter().map(|s| s.as_ref().to_string()).collect();
        match app().parse_from(argv.iter().map(String::as_str)) {
            Ok(m) => Self::from_matches(&m).map_err(|e| e.to_string()),
            // A query asking for --help gets the help text as its answer
            // rather than a parse failure: it is a well-formed question.
            Err(e) if matches!(e.kind, ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) => {
                Err(e.message)
            }
            Err(e) => Err(e.message),
        }
    }

    fn parse() -> Self {
        // Prepend any `.rgxrc` tokens so CLI args still win at parse time:
        // clap sees the config flags first and the user's flags second,
        // and a flag repeated twice is honoured as the latest one.
        let argv = rc::merge_into(std::env::args().collect());
        match Self::parse_from(argv) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("error: {e}");
                eprintln!();
                eprintln!("For more information, try '--help'.");
                std::process::exit(2);
            }
        }
    }

    fn before(&self) -> usize {
        self.context.unwrap_or(self.before_context)
    }
    fn after(&self) -> usize {
        self.context.unwrap_or(self.after_context)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LineKind {
    Match,
    Before,
    After,
}

/// The streaming text mode of [`HitSink`].
///
/// For the batched text route a `FileHit` is only ever a transport: its
/// lines are formatted into a scratch buffer and the hit is dropped. This
/// mode skips the transport -- `matched`/`context` write the formatted
/// bytes as they arrive, so the line text is copied once (into the output)
/// instead of three times (hit buffer, scratch, batch) and no `Line` or
/// `FileHit` content is built at all. The format is [`push_fmt_line`]'s,
/// shared with the hit formatter, so the bytes are identical by
/// construction.
struct TextStream {
    out: Vec<u8>,
    last_printed: Option<u64>,
    path_printed: bool,
    /// Lines formatted so far; the same budget the collecting path puts on
    /// `self.lines.len()`.
    formatted: usize,
    path: String,
    fmt: LineFmt,
    /// Set by `begin_file`. An unarmed stream falls back to the collecting
    /// path, so a call site that forgot to arm degrades to today's
    /// behaviour instead of printing a prefixless line.
    armed: bool,
}

impl TextStream {
    /// One formatted match line -- or one line of a multi-line match, which
    /// the caller splits and numbers before calling.
    fn push_line(&mut self, number: u64, raw: &[u8], sub: &[Submatch], budget: usize) {
        if self.formatted >= budget {
            return;
        }
        push_fmt_line(
            &mut self.out,
            self.fmt,
            &self.path,
            &mut self.last_printed,
            &mut self.path_printed,
            LineIn {
                number,
                is_match: true,
                raw,
                sub,
            },
        );
        self.formatted += 1;
    }

    /// One formatted context line.
    fn push_ctx(&mut self, number: u64, raw: &[u8], budget: usize) {
        if self.formatted >= budget {
            return;
        }
        push_fmt_line(
            &mut self.out,
            self.fmt,
            &self.path,
            &mut self.last_printed,
            &mut self.path_printed,
            LineIn {
                number,
                is_match: false,
                raw,
                sub: &[],
            },
        );
        self.formatted += 1;
    }
}

/// One submatch span within a [`Line`], captured at search time.
///
/// Offsets are relative to the line's stored bytes (the terminator-stripped
/// slice, i.e. `line.as_bytes(&hit.bytes)`), NOT to the file. The sink
/// captures them at match time by calling `matcher.find_iter(trimmed, ...)`
/// where `trimmed` is the line with the trailing `\n` already stripped, so
/// the `(start, end)` it returns are already relative to what
/// `line.as_bytes(&hit.bytes)` returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Submatch {
    pub start: u32,
    pub end: u32,
}

/// The submatches of a `-U` match, rebased onto one of its physical lines.
///
/// A submatch is a span of the whole multi-line match, and one physical
/// line of it holds only `at..at + len` of those bytes. Each span is moved
/// onto that window and clipped at its end: a span that does not reach the
/// window is dropped, and one that runs past the newline is cut at it,
/// because a span over two lines belongs to no single line whole. The
/// spans used to be cloned un-rebased, and every printer that sliced a
/// one-line buffer with whole-match offsets panicked.
fn rebase_submatches(sub: &[Submatch], at: u32, len: u32) -> Vec<Submatch> {
    let end = at + len;
    sub.iter()
        .filter_map(|s| {
            (s.start < end && s.end > at).then_some(Submatch {
                start: s.start.max(at) - at,
                end: s.end.min(end) - at,
            })
        })
        .collect()
}

struct Line {
    kind: LineKind,
    line_number: u64,
    /// Byte offset of this line's first byte in the searched buffer, which for
    /// the raw path is the file. `--json` reports it as `absolute_offset`.
    offset: u64,
    /// Whether the line ended with the `\n` that `without_newline` took off.
    ///
    /// Every printer here adds its own terminator, so the stored bytes never
    /// carry one. `--json` is the exception: rg reports the line exactly as it
    /// sits in the file, and a last line with no terminator -- or a file whose
    /// lines end in a bare `\r` -- must not be given a `\n` it never had.
    terminated: bool,
    /// Byte range into [`FileHit::bytes`]. `start` is the offset of the first
    /// byte in the per-file buffer; `end` is one past the last. The
    /// terminator (`\n`, if any) was stripped by the sink, so the slice does
    /// NOT include it.
    ///
    /// `u32` because every line fits in 4 GiB in any rgx corpus: the per-file
    /// buffer is bounded by `-M/--max-filesize` (default 1 GiB) and the
    /// conformance suite tops out at 128-deep recursion, so a single line
    /// cannot exceed the file's own ceiling. A search whose per-file buffer
    /// grows past `u32::MAX` would need `u64` start/end and is not one rgx
    /// ships.
    bytes: std::ops::Range<u32>,
    /// All submatch spans for this line, captured at search time.
    ///
    /// `None` for context lines (Before/After) and for match lines in modes
    /// that do not read spans (text mode — anything other than `--json` or
    /// `--only-matching`). `Some(empty Vec)` is reserved for a match line
    /// whose pattern matched zero spans: the searcher still called
    /// `matched`, the read site gates on `kind == Match` and then reads
    /// `submatches().len()`, so it matters the empty `Some` arms exist
    /// independently of the `None` ones. The 24-byte size is unchanged —
    /// `None` and `Some(Vec::new())` are the same inline layout — but the
    /// `None` arm lets the sink skip both the `Vec::new()` (context lines,
    /// today) and the `find_iter` that fills it (text mode, today) at the
    /// point the searcher reports the line. `print_json` and `count_matches`
    /// never re-run the matcher regardless.
    submatches: Option<Vec<Submatch>>,
}

impl Line {
    /// Resolve the `bytes` range against the per-file buffer the [`FileHit`]
    /// owns. Every reader of the line text goes through this so the
    /// `Vec<u8>` lives in exactly one place regardless of how many lines
    /// the file matched.
    #[inline]
    fn as_bytes<'a>(&self, buffer: &'a [u8]) -> &'a [u8] {
        &buffer[self.bytes.start as usize..self.bytes.end as usize]
    }

    /// Submatch spans captured at search time, relative to the line's bytes.
    /// Empty for context lines and for match lines in text mode (the two
    /// empty cases are indistinguishable here, and the readers do not need
    /// to tell them apart).
    #[inline]
    fn submatches(&self) -> &[Submatch] {
        self.submatches.as_deref().unwrap_or(&[])
    }
}

struct FileHit {
    path: String,
    /// adapter that produced the hit ("raw" = straight off disk)
    via: &'static str,
    /// Per-file buffer the [`Line::bytes`] ranges reference. Owned here so
    /// the ranges stay valid for the lifetime of the `FileHit` (and through
    /// the printer's `for line in &hit.lines` iteration). The sink grows
    /// one of these per file and moves it into the produced `FileHit` in
    /// `into_hit`.
    bytes: Vec<u8>,
    lines: Vec<Line>,
    /// matching lines (even those beyond the printed cap)
    count: u64,
    /// rg semantics: the file contains NUL bytes; matches were counted but
    /// line output is suppressed
    binary: bool,
    /// Where the NUL was, when one was found. rg prints this in place of the
    /// lines it will not print; without it a binary file that matched and a
    /// binary file that did not are the same silence.
    binary_offset: Option<u64>,
    /// Bytes this unit came from, when the producer already knew them.
    ///
    /// `--json` reports `bytes_searched`, and the obvious way to get it is
    /// `std::fs::metadata(&hit.path)` inside the printer -- which is one
    /// syscall per MATCHED FILE, re-deriving a number the walker already had.
    ///
    /// **It cannot be inferred from `via`.** A member carved out of an archive
    /// is tagged by its adapter, but an `.a`'s object members come back tagged
    /// `"raw"` while the size the walker holds is the CONTAINER's, and
    /// `metadata()` on the member's virtual path (`lib.a/inner.txt`) fails and
    /// answers 0. So `via` distinguishes nothing useful here.
    ///
    /// Carrying the value instead fixes it without guessing: each producer
    /// sets the size it actually had, and the printer falls back to the stat
    /// only where nobody knew one -- which is exactly where the stat was the
    /// only source before.
    bytes_searched: Option<u64>,
    /// The formatted text output of the streaming mode (see
    /// [`TextStream`]); `None` when the sink collected lines instead. The
    /// batched text route pushes these bytes and drops the hit; every
    /// other route ignores them.
    formatted: Option<Vec<u8>>,
}

/// One context chunk: a paragraph-aware window of bytes around one or more
/// matches, ready to be dropped into a model's context window.
struct Chunk {
    line_number: u64,
    bytes: Vec<u8>,
}

/// Chunk-mode counterpart of FileHit: instead of individual lines, the
/// worker ships whole windows of surrounding text.
struct ChunkHit {
    path: String,
    via: &'static str,
    count: u64,
    binary: bool,
    chunks: Vec<Chunk>,
}

/// Walk the line's submatches with the in-house byte regex, returning
/// `Some(Vec<Submatch>)` for a reader that wants them and `None` when
/// the byte regex was refused or the line held nothing to iterate. The
/// `grep-searcher` API used to do this through `matcher.find_iter` with
/// a callback; here it is a manual loop on `ByteRegex::search`, which
/// hands back the leftmost `(start, end)` pair at or after `at` and lets
/// the caller skip past it. An empty match advances one byte (the loop
/// only stops when `search` returns `None` or the cursor reaches the
/// line's end), so a pattern that matches the empty string at every
/// position still terminates.
fn collect_submatches(byte: Option<&ByteRegex>, trimmed: &[u8]) -> Option<Vec<Submatch>> {
    let byte = byte?;
    // `captures_iter` walks the line in a single Pike VM pass, advancing
    // past each match and stopping at the line's end (an empty match
    // advances by one byte, the same convention the `regex` crate uses).
    // The previous shape looped on `byte.search(trimmed, at)`, returning
    // one span per call and paying a fresh Rust function-call frame per
    // span: ~13 M calls on the `-o` corpus where the regex fires often.
    // The same VM work, less Rust overhead, no behavior change.
    let mut subs = Vec::new();
    for caps in byte.captures_iter(trimmed) {
        subs.push(Submatch {
            start: caps.start as u32,
            end: caps.end as u32,
        });
    }
    Some(subs)
}

/// Collects search results: exact line numbers, context lines, binary
/// detection and early quit for `-q`.
///
/// `byte` is the in-house compiled pattern, held as an `Arc` so the searcher
/// and the sink can both own it. When it is `None` the engine refused the
/// pattern (outside the byte-regex subset); the sink still records lines for
/// the binary and count paths, but stores `submatches = None` because there
/// is no matcher to walk.
///
/// Submatch capture at search time is what lets `print_json` and
/// `count_matches` skip their own `find_iter` re-runs.
struct HitSink {
    max_lines: usize,
    quiet: bool,
    /// -m NUM: stop the searcher after this many matching lines
    max_count: Option<usize>,
    count: u64,
    /// The compiled pattern. `None` when the in-house engine refused the
    /// pattern (outside its byte-mode subset). The sink walks submatches
    /// through this handle when `need_submatches` is true; when it is
    /// false the field is unused.
    byte: Option<Arc<ByteRegex>>,
    /// The streaming text mode, `Some` only for a run whose output is the
    /// batched text route (see [`TextStream`]). Lines are formatted as
    /// they arrive and carried out on the `FileHit` in `formatted`.
    stream: Option<TextStream>,
    /// Whether the sink has to populate `Line::submatches` at search time.
    /// True for `--json` and `--only-matching` (both read the spans —
    /// `print_json` writes the `submatches` array and the `-o` printer
    /// iterates them), false for everything else. When false the `matched`
    /// callback skips the match walk entirely and stores `None`, which is
    /// the bigger of the two wins this struct was restructured for: text
    /// mode is the common path, and walking submatches over the line bytes
    /// was paid per match even when no reader was going to look.
    need_submatches: bool,
    /// Per-file buffer the [`Line::bytes`] ranges reference. Grows as
    /// `matched` and `context` are called; `into_hit` moves it into the
    /// produced [`FileHit`]. A file with N matching lines goes from N
    /// `Vec<u8>` allocations to 1, the per-file buffer.
    bytes: Vec<u8>,
    lines: Vec<Line>,
    binary: bool,
    binary_offset: Option<u64>,
}

/// The line's text without the newline that `writeln!` is about to add.
///
/// The searcher face hands the newline back as part of the line (the
/// `grep-searcher` contract it keeps), and every printer here adds its
/// own, so left in place each line of output
/// carried two: a blank line between every result, and a doubled
/// newline inside the JSON `text` field, which appends one of its own.
/// rg strips it in its printer for the same reason.
///
/// Only the `\n` goes. A CRLF file keeps its `\r`, so the line still
/// ends CRLF exactly as it does on disk and as rg prints it -- stripping
/// the carriage return too would silently rewrite the caller's bytes.
fn without_newline(bytes: &[u8]) -> &[u8] {
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}

/// A path with the separators rg prints, whatever the platform handed us.
///
/// The walker builds its paths one way and the command line spells them
/// another, so anything that compares the two (the explicit-path set in
/// `run_query`) has to put both in the same shape first.
fn slash_path(p: &str) -> String {
    if p.contains('\\') {
        p.replace('\\', "/")
    } else {
        p.to_string()
    }
}

/// The path that goes on a `FileHit` (and therefore into the printer).
///
/// When `--no-filename` is set the path is never read; an empty `String`
/// saves the `slash_path` allocation on every hit. The closure passed to
/// `sink::into_hit` / `take_hit` is its own file's worth, and a tree-mode
/// bench hit rate is in the millions, so the saving is the same shape as
/// Phase 1.3's HitSink reuse.
#[inline]
fn path_for_hit(no_filename: bool, path_str: &str) -> String {
    if no_filename {
        String::new()
    } else {
        slash_path(path_str)
    }
}

/// Whether a walked file keeps its binary hits instead of being dropped whole.
///
/// This is rg's rule, and it is a rule about *provenance*: rg sets
/// `BinaryDetection::none` for a path the user named, so a binary file given
/// explicitly is searched as text and reported (`-c` counts it, `-l` lists
/// it, the exit status is set) with only the line output suppressed. A binary
/// file found by traversal keeps `BinaryDetection::quit`, which drops it
/// before it is ever reported -- out of `-c`, out of `-l`, out of `-L`'s list
/// of the misses, and out of the exit status.
///
/// Measured against ripgrep 15.0.0 before writing it, over a directory
/// holding one NUL-bearing `.rs` and two ordinary `.txt`:
///
/// ```text
/// $ rg -c 'fn ' dir/        # 307.rs is absent
/// dir/ok.txt:1
/// dir/sub/other.txt:1
/// $ rgx -c 'fn ' dir/       # before: 307.rs counted, and exit 0 where rg exits 1
/// dir/ok.txt:1
/// dir/sub/307.rs:5
/// dir/sub/other.txt:1
/// ```
///
/// `-a` clears it, which is rg's `--text` doing the same thing.
fn keeps_binary_walk_hits(
    args: &Args,
    explicit: &std::collections::HashSet<String>,
    path: &Path,
) -> bool {
    args.text || is_explicit_path(explicit, path)
}

/// True when the user named this exact path on the command line, as opposed
/// to the walker discovering it.
///
/// rg treats the two differently in more than one place --- binary detection
/// is off for a named file, and `--max-filesize` does not apply to one ---
/// and this is the question both of those ask. Naming a file is an
/// instruction to search it; the caps exist to keep the walk from opening
/// things nobody asked for.
fn is_explicit_path(explicit: &std::collections::HashSet<String>, path: &Path) -> bool {
    !explicit.is_empty() && explicit.contains(&slash_path(&path.to_string_lossy()))
}

// rgx_core::extension_candidates borrows straight from the path it is
// given, so the walk hands it the slash-normalised string it already built
// rather than paying a second lowercase allocation per file. The helper
// that used to do that (`lowercased_ext`) existed only to feed two
// extension-only lookups; both are path-based now.

/// How many lines per file a [`HitSink`] buffers, from the output mode.
///
/// A buffered line is one slot in `lines: Vec<Line>`, the `Line` carrying
/// only a `(start, len)` range into the per-file `bytes` buffer, so the text
/// is not copied twice — the printer resolves it against `FileHit::bytes` via
/// `Line::as_bytes`. In the modes below nothing downstream reads
/// `hit.lines`: the printer takes `hit.count` for `-c`, the path for `-l`,
/// and `-q` stops at the first match — so each `Line` is allocated and
/// discarded on a walk that already spends ~5 µs per file.
///
/// `-o -c` is deliberately NOT in the list: there the unit is the match, and
/// `count_matches` reads the per-line `submatches` the sink captured at
/// search time, so the buffer is the input rather than dead weight.
///
/// Everywhere else the answer is "all of them", and that is ripgrep's answer.
/// The 1000-line ceiling this used to carry was a local invention that
/// truncated ordinary output: `-n`, `-o` and `--json` all stopped at 1000
/// matching lines per file too, and a truncation visible only on big files is
/// indistinguishable from a searcher bug.
///
/// Memory is bounded by the walk rather than by this function: the walker
/// refuses files over `--max-filesize` (1G default) and the printer drains
/// each `Msg::Hit` off the channel as it arrives, so only one file's matching
/// lines are ever resident.
fn line_budget(args: &Args) -> usize {
    const NONE: usize = 0;
    if args.files_with_matches || args.quiet || (args.count && !args.only_matching) {
        NONE
    } else {
        usize::MAX
    }
}

/// One compiled `Arc<ByteRegex>` per (pattern, ignore_case) pair, looked up
/// across every walk, every serve-mode query and every unit the adapters
/// produced. The pattern is fixed for the lifetime of the process between two
/// different queries, and recompiling it on every file is pure overhead —
/// over the 20,027-file tree benchmark, each `HitSink::new` triggered a
/// `build_byte_regex` that parsed the pattern, built NFA→DFA tables and
/// allocated the VM, and a 20k-file walk spent the better part of its 7 µs/file
/// budget on that. The `OnceLock` is process-global so a `--serve` query and
/// the next one share the same compiled regex.
///
/// A `Mutex` (not a `RwLock`) because the hot path is read-dominant and the
/// lock is only taken on a miss — every miss is a single regex build, which
/// is the same cost as a `build_byte_regex` call today, so a miss is no
/// worse than the uncached path and every hit is a hash lookup.
///
/// `dot_all` is part of the key: `-U` reaches the compiled pattern, not just
/// the searcher, so a `-U` query and an ordinary one sharing one `ByteRegex`
/// would get each other's semantics with nothing saying so.
type CompiledRegexCache = std::sync::Mutex<HashMap<(&'static str, bool, bool), Arc<ByteRegex>>>;

pub(crate) fn compiled_byte_arc(args: &Args) -> Option<Arc<ByteRegex>> {
    let pattern = byte_pattern(args)?;
    let ignore_case =
        args.ignore_case || (args.smart_case && !pattern.chars().any(char::is_uppercase));
    let dot_all = args.multiline_dotall;
    static CACHE: std::sync::OnceLock<CompiledRegexCache> = std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    // `Box::leak` puts the pattern in static memory so the cache key is a
    // pair of `&'static str` + bool, stable across calls and across threads.
    // The pattern is a small string and the leak is bounded by the number of
    // distinct patterns the process ever sees (typically one). We memo the
    // leak itself by `pattern_string` so a 20k-file walk does not allocate
    // 20k copies of the same `&str`: the leak happens once per distinct
    // pattern, the lookup returns the cached static ref.
    static LEAKED: std::sync::OnceLock<std::sync::Mutex<HashMap<String, &'static str>>> =
        std::sync::OnceLock::new();
    let leaked_cache = LEAKED.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    let key: (&'static str, bool, bool) = {
        let mut lc = leaked_cache.lock().unwrap();
        let pat_static: &'static str = lc
            .entry(pattern.clone())
            .or_insert_with(|| Box::leak(pattern.into_boxed_str()));
        (pat_static, ignore_case, dot_all)
    };
    if let Some(arc) = cache.lock().unwrap().get(&key).cloned() {
        return Some(arc);
    }
    let arc = {
        let r = engine::build_byte_regex_flags(Some(key.0), key.1, key.2)?;
        Arc::new(r)
    };
    cache.lock().unwrap().insert(key, Arc::clone(&arc));
    Some(arc)
}

impl HitSink {
    /// Build the in-house byte regex the sink will use to capture
    /// submatches when `-o` or `--json` is set. Centralised so every
    /// call site that builds a `HitSink` agrees on the same regex
    /// (the previous versions all passed `None`, which left
    /// `line.submatches()` empty for every match and broke `-o`).
    fn build_byte(args: &Args) -> Option<Arc<ByteRegex>> {
        // The pattern+ignore_case pair is constant for the whole query, and
        // `build_byte_regex` does a full NFA→DFA build + VM-table alloc every
        // time. A 20k-file walk therefore paid 20k regex compiles for one
        // pattern; the cache fixes that without touching the call sites.
        compiled_byte_arc(args)
    }

    fn new(args: &Args, byte: Option<Arc<ByteRegex>>) -> Self {
        HitSink {
            max_lines: line_budget(args),
            quiet: args.quiet,
            max_count: args.max_count,
            count: 0,
            byte,
            need_submatches: args.json
                || args.only_matching
                || args.column
                || color_resolved(args.color.as_deref()),
            // The streaming mode replaces the collect-then-format pair for
            // exactly the route `text_msg_into` serves: the batched text
            // output. Every other mode (`--json`, `-o`, `-r`, `-c`, `-l`,
            // `--sort`, `--context`, quiet) keeps the collecting sink --
            // the printer's arms read `Line`s or the runs produce no text
            // lines at all. The condition mirrors the worker's dispatch;
            // a mismatch only costs the streaming win, never correctness
            // (`FileHit::formatted` is optional and the fallback formats
            // from the hit).
            stream: if !args.json
                && !args.only_matching
                && args.replace.is_none()
                && !args.count
                && !args.files_with_matches
                && !args.quiet
                && args.sort.is_none()
                && !(args.before() > 0 || args.after() > 0 || args.context.is_some())
            {
                Some(TextStream {
                    out: Vec::with_capacity(8192),
                    last_printed: None,
                    path_printed: false,
                    formatted: 0,
                    path: String::new(),
                    armed: false,
                    fmt: LineFmt {
                        multi: false,
                        lines: false,
                        context: false,
                        heading: false,
                        color: false,
                        column: false,
                    },
                })
            } else {
                None
            },
            // Pre-sized at 8 KiB: an average line is ~30 bytes, so this is
            // ~270 lines of headroom before the first reallocation. A file
            // with N matching lines goes from N `Vec<u8>` allocations to
            // at most `ceil(total_bytes / 8KiB)` for this one.
            bytes: Vec::with_capacity(8192),
            // `lines` is only read when the user wants line output; `-c`,
            // `-l` and `-q` skip it. Allocating nothing in those modes
            // saves an empty `Vec` per file -- 20k of them on the bench's
            // tree corpus.
            lines: if line_budget(args) == 0 {
                Vec::new()
            } else {
                Vec::with_capacity(64)
            },
            binary: false,
            binary_offset: None,
        }
    }

    /// Reset a sink to a per-file start state without dropping the backing
    /// `Vec` capacities. Used by the walker closure, which owns one sink per
    /// worker and resets it between files; 20k fresh `Vec<u8>` allocations
    /// collapse to zero. `bytes` is also cleared but its capacity is kept
    /// because the per-line bytes grow into it across matches.
    fn reset(&mut self) {
        self.count = 0;
        self.binary = false;
        self.binary_offset = None;
        self.bytes.clear();
        self.lines.clear();
        if let Some(ts) = self.stream.as_mut() {
            // Deliberately NOT disarming and NOT clearing `path`/`fmt`:
            // `begin_file` arms and fills them before the search, and the
            // searcher resets the sink at its entry points -- a reset that
            // disarmed would undo the arming, and one that cleared the
            // path would forget the file mid-search. `take_hit` disarms at
            // the end of a file instead.
            ts.out.clear();
            ts.last_printed = None;
            ts.path_printed = false;
            ts.formatted = 0;
        }
    }

    /// Tell the streaming mode which file the next lines belong to and how
    /// to format them. One call per file, before the search; the path is
    /// the display form the prefix prints. No-op outside streaming mode,
    /// and reuses `ts.path`'s backing buffer across files so the walk pays
    /// zero per-file `String` allocations.
    fn begin_file(&mut self, no_filename: bool, path: &str, fmt: LineFmt) {
        if let Some(ts) = self.stream.as_mut() {
            ts.path.clear();
            if !no_filename {
                if path.contains('\\') {
                    ts.path.reserve(path.len());
                    for (i, seg) in path.split('\\').enumerate() {
                        if i > 0 {
                            ts.path.push('/');
                        }
                        ts.path.push_str(seg);
                    }
                } else {
                    ts.path.push_str(path);
                }
            }
            ts.fmt = fmt;
            ts.armed = true;
        }
    }

    /// End of file for a search that produced no hit to carry one: the
    /// size-cap and binary-cut skips. Disarms the stream exactly as
    /// `take_hit` does -- end of file is the only thing that may disarm --
    /// so the next file cannot inherit this one's path through a call
    /// site that has no `begin_file`.
    fn end_file(&mut self) {
        if let Some(ts) = self.stream.as_mut() {
            ts.armed = false;
        }
        self.reset();
    }
    fn into_hit(self, path: impl FnOnce() -> String, via: &'static str) -> Option<FileHit> {
        (self.count > 0).then(|| FileHit {
            path: path(),
            via,
            bytes: self.bytes,
            lines: self.lines,
            count: self.count,
            binary: self.binary,
            binary_offset: self.binary_offset,
            bytes_searched: None,
            formatted: self.stream.map(|ts| ts.out),
        })
    }

    /// Same as `into_hit`, but reuses the sink's backing buffers: the
    /// `bytes` and `lines` `Vec`s are swapped out for fresh ones, and the
    /// caller can call `reset()` and reuse the sink for the next file. The
    /// 8 KiB pre-allocation in `bytes` therefore survives across files --
    /// 20k fresh allocations collapse to one per worker.
    fn take_hit(&mut self, path: impl FnOnce() -> String, via: &'static str) -> Option<FileHit> {
        // End of file, on EVERY path through here: the hit branch and the
        // no-hit one. A take_hit that disarmed only when a hit existed
        // left the stream armed with this file's path after a search that
        // matched nothing, and the next file through the pre-read route --
        // which has no `begin_file` of its own -- streamed its hit under
        // this file's name. The `-i` battery caught exactly that
        // (`zstd_noise.bin`'s hit printed as `zstd_longrange.plain`).
        let streamed = match self.stream.as_mut() {
            Some(ts) if ts.armed => {
                ts.armed = false;
                Some(std::mem::take(&mut ts.out))
            }
            _ => None,
        };
        if self.count == 0 {
            self.reset();
            return None;
        }
        let count = self.count;
        let binary = self.binary;
        let binary_offset = self.binary_offset;
        let path = path();
        // Move the populated buffers out. If no lines or bytes were captured
        // (such as under -c, -l, or -q), avoid allocating 8 KiB + 64 slots per hit.
        let (bytes, lines) = if self.bytes.is_empty() && self.lines.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            (
                std::mem::replace(&mut self.bytes, Vec::with_capacity(8192)),
                std::mem::replace(&mut self.lines, Vec::with_capacity(64)),
            )
        };
        let formatted = streamed;
        self.reset();
        Some(FileHit {
            path,
            via,
            bytes,
            lines,
            count,
            binary,
            binary_offset,
            bytes_searched: None,
            formatted,
        })
    }
}

/// Chunk-mode sink: records the byte range of every match (relative to the
/// searched buffer) instead of whole lines, so the chunk builder can cut
/// paragraph-aware windows around them. Same early-stop contract as
/// HitSink for -q and -m.
///
/// **The range is the MATCH's, not the line's.** `SinkMatch::bytes_range_in_buffer`
/// is the line, and recording that made `--chunk` centre its window on the
/// line: a match in a one-line multi-megabyte file dragged the whole file
/// into the chunk, which is the exact case `build_chunks`'s hard cut exists
/// for. The match span is found the same way [`HitSink`] finds it -- the
/// in-house sink does not carry submatches, so the sink asks the matcher.
struct RangeSink {
    quiet: bool,
    max_count: Option<usize>,
    count: u64,
    ranges: Vec<std::ops::Range<usize>>,
    binary: bool,
    byte: Option<Arc<ByteRegex>>,
}

impl RangeSink {
    fn new(quiet: bool, max_count: Option<usize>, byte: Option<Arc<ByteRegex>>) -> Self {
        RangeSink {
            quiet,
            max_count,
            count: 0,
            ranges: Vec::new(),
            binary: false,
            byte,
        }
    }
}

/// The in-house engine's sink face for [`HitSink`].
///
/// The body keeps the shape the removed `grep-searcher` impl had, with the
/// searcher argument gone (the in-house trait does not pass it) and the
/// context kind mapped across. There is no second body to stay parallel to
/// any more -- the crate and the `rgx-core` differential tests that held the
/// two to the same answers are both deleted -- so what holds the engine's
/// answers now is `crates/rgx-core/src/searcher/oracle.rs` against the
/// `regex` crate.
///
/// **Submatches on the in-house path.** `RgxSinkMatch` does not expose
/// submatches directly -- the in-house searcher only tells the sink "this
/// line matched" -- so this impl calls `matcher.find_iter` on the line
/// bytes. That is still one walk per match (this is the only `find_iter`
/// the buffered line sees), and what the printer used to do was the
/// same walk *twice* -- once in `print_json`, once in `count_matches`.
impl RgxSink for HitSink {
    type Error = std::io::Error;

    fn matched(&mut self, mat: &RgxSinkMatch<'_>) -> Result<bool, std::io::Error> {
        self.count += 1;
        if let Some(ts) = self.stream.as_mut().filter(|ts| ts.armed) {
            let raw = mat.bytes;
            let trimmed = without_newline(raw);
            let sub_owned = if self.need_submatches {
                collect_submatches(self.byte.as_deref(), trimmed)
            } else {
                None
            };
            let sub: &[Submatch] = sub_owned.as_deref().unwrap_or(&[]);
            let budget = self.max_lines;
            // A `-U` match can hold several physical lines; rg prints each
            // with its own number counting up from the start line, so the
            // split mirrors the collecting arm exactly.
            match rgx_core::memchr::memchr(b'\n', trimmed) {
                Some(_) => {
                    let base = mat.line_number.unwrap_or(0);
                    let mut rest = trimmed;
                    let mut n = 0u64;
                    let mut at = 0usize;
                    while let Some(i) = rgx_core::memchr::memchr(b'\n', rest) {
                        let line_sub = rebase_submatches(sub, at as u32, i as u32);
                        ts.push_line(base + n, &rest[..i], &line_sub, budget);
                        at += i + 1;
                        rest = &rest[i + 1..];
                        n += 1;
                    }
                    if !rest.is_empty() {
                        let line_sub = rebase_submatches(sub, at as u32, rest.len() as u32);
                        ts.push_line(base + n, rest, &line_sub, budget);
                    }
                }
                None => {
                    ts.push_line(mat.line_number.unwrap_or(0), trimmed, sub, budget);
                }
            }
            return Ok(!(self.quiet || self.max_count.is_some_and(|m| self.count >= m as u64)));
        }
        if self.lines.len() < self.max_lines {
            let raw = mat.bytes;
            let trimmed = without_newline(raw);
            let terminated = trimmed.len() < raw.len();
            // The in-house `RgxSinkMatch` carries no submatches, so the
            // sink asks the byte regex for them itself when a reader is
            // waiting. `self.byte` is the same matcher the hybrid delegate
            // handed the line to, and the in-house engine's differential
            // tests hold it to the same matches as the byte regex on ASCII
            // lines. The submatches' `(start, end)` are relative to
            // `trimmed` (the line with its terminator stripped), which is
            // exactly what `line.as_bytes(&hit.bytes)` returns -- no
            // translation needed. Text mode skips the walk entirely and
            // stores `None`; see the grep-searcher `Sink::matched` for
            // the structural argument.
            let submatches = if self.need_submatches {
                collect_submatches(self.byte.as_deref(), trimmed)
            } else {
                None
            };
            // `-U` hands the whole match here, so it can hold several physical
            // lines. rg prints each of them with its own number, counting up
            // from where the match began -- `3:THREE` / `4:four` for a match
            // over lines 3-4 -- so one event becomes several `Line`s. Without
            // this the sink emitted one line carrying only the first number,
            // and rgx printed `4:four` where rg prints both.
            let mut push = |bytes: &[u8], number: u64, terminated: bool, at: u32| {
                let from = self.bytes.len() as u32;
                self.bytes.extend_from_slice(bytes);
                let to = self.bytes.len() as u32;
                // The spans are of the whole `-U` match; this line holds
                // only its own window of it, so each span is rebased and
                // clipped before it is stored against this line's bytes.
                let line_sub = submatches
                    .as_deref()
                    .map(|sub| rebase_submatches(sub, at, bytes.len() as u32));
                self.lines.push(Line {
                    kind: LineKind::Match,
                    line_number: number,
                    offset: mat.absolute_byte_offset,
                    terminated,
                    bytes: from..to,
                    submatches: line_sub,
                });
            };
            match rgx_core::memchr::memchr(b'\n', trimmed) {
                // More than one line: split, numbering from the start line.
                Some(_) => {
                    let base = mat.line_number.unwrap_or(0);
                    let mut rest = trimmed;
                    let mut n = 0u64;
                    let mut at = 0u32;
                    while let Some(i) = rgx_core::memchr::memchr(b'\n', rest) {
                        push(&rest[..i], base + n, true, at);
                        at += i as u32 + 1;
                        rest = &rest[i + 1..];
                        n += 1;
                    }
                    if !rest.is_empty() {
                        push(rest, base + n, terminated, at);
                    }
                }
                // One line: the ordinary path, unchanged.
                None => push(trimmed, mat.line_number.unwrap_or(0), terminated, 0),
            }
        }
        Ok(!(self.quiet || self.max_count.is_some_and(|m| self.count >= m as u64)))
    }

    fn context(&mut self, ctx: &RgxSinkContext<'_>) -> Result<bool, std::io::Error> {
        let kind = match ctx.kind {
            RgxContextKind::Before => LineKind::Before,
            RgxContextKind::After => LineKind::After,
            RgxContextKind::Other => return Ok(true),
        };
        if let Some(ts) = self.stream.as_mut().filter(|ts| ts.armed) {
            // Streaming runs have no `--context` (the mode's condition
            // excludes it); this arm exists so the two sinks cannot
            // diverge if that ever changes.
            let trimmed = without_newline(ctx.bytes);
            let budget = self.max_lines;
            ts.push_ctx(ctx.line_number.unwrap_or(0), trimmed, budget);
            return Ok(true);
        }
        if self.lines.len() < self.max_lines {
            let raw = ctx.bytes;
            let trimmed = without_newline(raw);
            let terminated = trimmed.len() < raw.len();
            let start = self.bytes.len() as u32;
            self.bytes.extend_from_slice(trimmed);
            let end = self.bytes.len() as u32;
            self.lines.push(Line {
                kind,
                line_number: ctx.line_number.unwrap_or(0),
                offset: ctx.absolute_byte_offset,
                terminated,
                bytes: start..end,
                submatches: None,
            });
        }
        Ok(true)
    }

    fn finish(&mut self, finish: &RgxSinkFinish) -> Result<(), std::io::Error> {
        // `binary` may already be true because the caller searched a prefix it
        // knows is binary; never downgrade it, and never downgrade the offset
        // either -- the in-house engine knows WHERE the NUL was, and that is
        // the number rg prints. Without this line a named binary file matched,
        // counted and listed correctly, and then printed nothing at all.
        self.binary_offset = self.binary_offset.or(finish.binary_byte_offset);
        self.binary = self.binary || self.binary_offset.is_some();
        Ok(())
    }
}

/// The in-house engine's sink face for [`RangeSink`], keeping the shape the
/// removed `grep-searcher` impl had.
impl RgxSink for RangeSink {
    type Error = std::io::Error;

    /// Kept do-nothing, as the `grep-searcher` face defaulted it: `RangeSink`
    /// never used `context`, so it records nothing here either. It is only
    /// ever used without context flags.
    fn context(&mut self, _ctx: &RgxSinkContext<'_>) -> Result<bool, std::io::Error> {
        Ok(true)
    }

    fn matched(&mut self, mat: &RgxSinkMatch<'_>) -> Result<bool, std::io::Error> {
        self.count += 1;
        if self.ranges.len() < 4096 {
            // The MATCH's range, not the line's. `bytes_range_in_buffer` is
            // the line; the chunk window is centred on the match, so the
            // first submatch's span is what the budget cuts around. Offsets
            // from `collect_submatches` are relative to the line with its
            // terminator stripped, and the line starts at
            // `bytes_range_in_buffer.start`, so the two add.
            let line_start = mat.bytes_range_in_buffer.start;
            let trimmed = without_newline(mat.bytes);
            let span = collect_submatches(self.byte.as_deref(), trimmed)
                .and_then(|subs| subs.first().map(|s| (s.start as usize, s.end as usize)))
                .map(|(s, e)| (line_start + s)..(line_start + e));
            self.ranges
                .push(span.unwrap_or_else(|| mat.bytes_range_in_buffer.clone()));
        }
        Ok(!(self.quiet || self.max_count.is_some_and(|m| self.count >= m as u64)))
    }

    fn finish(&mut self, finish: &RgxSinkFinish) -> Result<(), std::io::Error> {
        self.binary = finish.binary_byte_offset.is_some();
        Ok(())
    }
}

/// The pattern the in-house engine should compile, as text.
///
/// `-F` escapes and `-w` wraps, the same way `build_replace_regex` does, so the
/// in-house engine sees the same pattern `grep-regex` was handed. `-S` resolves
/// to plain case-insensitive when the pattern has no upper-case character,
/// which is rg's own rule.
/// Refuse a pattern the in-house engine cannot compile, the way rg does.
///
/// `build_byte` answers `None` for a pattern outside the byte-mode subset, and
/// every caller reads that as "no matcher" and searches nothing: exit 1, no
/// output, no explanation. rg exits 2 with a parse error. On a terminal the two
/// are indistinguishable — "no match" and "I could not read your question" look
/// identical — and the second is the wrong answer to give.
///
/// Compiled once, here, with the same three flags `compiled_byte_arc` uses, so
/// the check and the search cannot disagree about what compiles.
fn reject_uncompilable_pattern(args: &Args) {
    let Some(pat) = byte_pattern(args) else {
        return;
    };
    let ci = args.ignore_case || (args.smart_case && !pat.chars().any(char::is_uppercase));
    if let Err(e) =
        ByteRegex::new_multiline(pat.as_bytes(), ci, args.multiline || args.multiline_dotall)
    {
        eprintln!("error: {e}");
        eprintln!();
        eprintln!("For more information, try '--help'.");
        std::process::exit(2);
    }
}

fn byte_pattern(args: &Args) -> Option<String> {
    let mut pat = args.pattern.clone()?;
    let _smart_ci = args.smart_case && !pat.chars().any(char::is_uppercase);
    if args.fixed_strings {
        // The in-house `escape`, not the `regex` crate's: it quotes what
        // THIS engine's parser treats as syntax, which is what this
        // pattern is about to be compiled with. The round-trip test in
        // rgx-core pins that the result matches the input and nothing
        // resembling it.
        pat = core::str::from_utf8(&rgx_core::regex::escape(pat.as_bytes()))
            .map(Cow::Borrowed)
            .unwrap_or_else(|_| {
                Cow::Owned(
                    String::from_utf8_lossy(&rgx_core::regex::escape(pat.as_bytes())).into_owned(),
                )
            })
            .into_owned();
    }
    if args.word_regexp {
        pat = format!(r"\b(?:{pat})\b");
    }
    Some(pat)
}

fn needs_line_numbers(args: &Args) -> bool {
    if args.count
        || args.quiet
        || args.files_with_matches
        || args.files_without_match
        || args.no_line_number
    {
        false
    } else {
        // `--column`/`--vimgrep` prints `{path}:{line}:{col}:{text}`, so the
        // line number is in every output line whether or not `-n` was given.
        args.line_number || args.column || args.json || std::io::stdout().is_terminal()
    }
}

/// Build the searcher the binary drives.
///
/// The engine is chosen by `RGX_ENGINE`; see [`engine::Mode`]. The in-house
/// matcher is built only when the mode can use it, so the default path does no
/// extra work.
fn make_searcher(args: &Args) -> CompatSearcher {
    let _ = args.engine.as_deref();
    let mode = engine::Mode::from_env();
    let config = RgxConfig {
        before: args.before(),
        after: args.after(),
        invert: args.invert_match,
        multi_line: args.multiline || args.multiline_dotall,
        line_numbers: needs_line_numbers(args),
        forced_bom: forced_bom_of(args),
        binary: if args.text {
            engine::RgxBinaryDetection::None
        } else {
            engine::RgxBinaryDetection::Quit(0)
        },
        // The library default 64 KiB stands: raising it to 256 KiB to cut
        // ReadFile syscalls measured *slower* (50 ms against 43 on the
        // 246 MB corpus for an absent literal) — the two bit maps grow
        // with the fill and evict the haystack from L2. Filed as a negative.
        ..RgxConfig::default()
    };
    // The pattern comes from the process-wide memo rather than a compile of its
    // own; `build_byte` resolves the same `(pattern, ignore_case)` key the
    // `ignore_case` arithmetic above used to build.
    let byte = HitSink::build_byte(args);
    CompatSearcher::new(config, byte, mode)
}

/// Per-worker reusable state for the raw path. Building a `Searcher`
/// allocates internal line buffers; creating one per file (thousands of
/// times per corpus walk) is pure overhead. Same for the head-sniff
/// scratch buffer.
struct RawState {
    /// The length `raw_search_inner` derived for the file it just searched
    /// (the fill-derived length). It lives here rather than in an
    /// out-parameter so the call stays within the argument count the lint
    /// allows -- the state is per worker, so there is nothing to race.
    last_len: u64,
    searcher: CompatSearcher,
    /// Binary detection off, for the two places where the bytes handed to the
    /// searcher are not the file's own: the binary-prefix path, where the
    /// caller already cut the buffer at the NUL and `grep-searcher` would
    /// stop again inside it; and the adapter path, where the unit is text an
    /// adapter produced. The NUL heuristic describes the *container* — a DER
    /// certificate is binary whatever its description says — and applying it
    /// to the description loses the file: `BinaryDetection::Quit` reports
    /// nothing at all once a NUL sits in the first 64 KiB, so a single stray
    /// NUL in a rendered field took the whole `.crt` out of `-c`, out of `-l`
    /// and out of the exit status, where `rg` had counted it. See
    /// `x509`'s `iPAddress`, which is how that NUL got there.
    text_searcher: CompatSearcher,
    /// ripgrep's rule for a path the user NAMED, which is not the rule for a
    /// path the walk turned up. See `raw_search`.
    convert_searcher: CompatSearcher,
    sink: HitSink,
    head: Vec<u8>,
}

impl RawState {
    fn new(args: &Args) -> Self {
        // See `text_searcher`: this one never treats a NUL as binary, for
        // either of the two callers that need bytes the file's own binary
        //-ness says nothing about.
        let convert = RgxConfig {
            before: args.before(),
            after: args.after(),
            invert: args.invert_match,
            multi_line: args.multiline || args.multiline_dotall,
            line_numbers: needs_line_numbers(args),
            forced_bom: forced_bom_of(args),
            binary: engine::RgxBinaryDetection::Convert(0),
            ..RgxConfig::default()
        };
        let no_binary = RgxConfig {
            before: args.before(),
            after: args.after(),
            invert: args.invert_match,
            multi_line: args.multiline || args.multiline_dotall,
            line_numbers: needs_line_numbers(args),
            forced_bom: forced_bom_of(args),
            binary: engine::RgxBinaryDetection::None,
            ..RgxConfig::default()
        };
        let _ = args.engine.as_deref();
        let mode = engine::Mode::from_env();
        // All three searchers this worker builds share ONE compiled pattern,
        // from the process-wide memo `HitSink::build_byte` reads. They used to
        // each call `engine::build_byte_regex`, which is a full NFA->DFA build
        // plus its VM tables, so a `-j32` run compiled one pattern 96 times
        // (3 searchers x 32 workers) before searching a byte.
        let byte = HitSink::build_byte(args);
        Self {
            last_len: 0,
            searcher: make_searcher(args),
            text_searcher: CompatSearcher::new(no_binary, byte.clone(), mode),
            convert_searcher: CompatSearcher::new(convert, byte, mode),
            sink: HitSink::new(args, HitSink::build_byte(args)),
            head: vec![0u8; SNIFF],
        }
    }
}

const SNIFF: usize = 64 * 1024;

/// How large the per-worker read buffer may grow before it is given back.
///
/// Grown, never shrunk. `raw_search` grows `st.head` to the file's length and
/// reads into it; past this threshold it `truncate`s back to `SNIFF` and
/// `shrink_to`s the allocation away, and the next medium file grows it again —
/// `Vec::resize(n, 0)` zero-fills every byte from `SNIFF` to `n` immediately
/// before the read overwrites all of it. A corpus of larger files therefore
/// pays a full memset of every file on top of the read, plus a malloc/free
/// pair each.
///
/// Measured on 12 x 4 MiB files (48 MiB), `-c 'pub fn'`, best of 5 after a
/// warmup:
///
/// ```text
///   threshold   1 MiB (was)   56.0 ms
///   threshold   4 MiB (now)   50.4 ms    -10%
///   threshold   8 MiB (tried) 49.6 ms    -11.4%, and 8x the retained memory
/// ```
///
/// 4 MiB is the setting because it captures the whole win on this corpus — a
/// 4 MiB file is not `>` 4 MiB, so it is never given back — at half the
/// retention of the 8 MiB that measured 0.8 ms better still.
///
/// **What this costs.** Retention is the largest file a worker saw, capped by
/// this, times the worker count: at `-j32` a corpus of 4 MiB files retains
/// ~128 MiB instead of ~32 MiB. That is a deliberate memory-for-time trade and
/// it is the only reason the number is 4 and not 1. A worker that never sees a
/// file this size is unaffected, so a source tree of normal files pays nothing
/// either way.
const HEAD_KEEP_MAX: usize = 4 * 1024 * 1024;

/// Which searcher reads a unit an adapter chain produced.
///
/// The NUL heuristic describes the *file on disk*, and a unit is not always the
/// file on disk. Anything a container produced must be read without it: the
/// container's binary-ness says nothing about the bytes the adapter rendered.
///
/// **Neither field on `Found` carries that alone, so the test is the pair.**
/// `path` alone cannot: an adapter's `Outcome::Text` keeps the container's own
/// path, so every rendering adapter looked like a plain file and the container's
/// NULs decided its fate. `fbx` copied 287,991 of them out of `duck.fbx` and
/// `Quit` reported nothing at all, on a file whose 1,987 node names `rg` counts.
/// `via` alone cannot either: it says `"raw"` both for the passthrough and for
/// the extensionless member a single-file decompressor leaves behind, and that
/// member's bytes are the container's, not the file's. `brotli_big.plain` has a
/// 40 KB random section whose first NUL is at offset 305, so `rgx -c hello
/// crates/rgx-adapters-archive/testdata/brotli_big_q0.br` reported nothing while
/// the same file uncompressed reported 20: the decoder produced all 120,552
/// bytes and the budget was not close — the searcher quit at a NUL the payload
/// legitimately contains.
///
/// The conjunction separates all three cases. A unit is the file's own bytes
/// only when the path is the walked file's AND no adapter produced it:
/// passthrough passes both, a rendered unit fails `via`, and a decompressed
/// member fails `path`.
///
/// This is not cosmetic. `BinaryDetection::Quit` reports **nothing at all**
/// once a NUL sits in the first 64 KiB — not the lines before it — so one
/// stray NUL in a rendered field dropped the whole file from `-c`, from `-l`
/// and from the exit status, on a file `rg` had counted. The x509 adapter's
/// `iPAddress` is the concrete case: tag `0x87` is an OCTET STRING,
/// `str::from_utf8` accepts it, and a zero-address SAN printed twenty NULs
/// into a text description of a certificate `rg` reads perfectly well.
///
/// `raw.searcher` is untouched, so a real binary file that no adapter claims
/// keeps `rg`'s behaviour byte for byte. That is the whole point of asking the
/// pair and not the union.
fn unit_searcher<'a>(
    raw: &'a mut RawState,
    found: &rgx_core::Found,
    path_str: &str,
    named_binary: bool,
) -> &'a mut CompatSearcher {
    if found.path == path_str && found.via == "raw" {
        // The unit IS the file's own bytes, so it carries the file's binary
        // rule -- and the rule is about where the path came from. rg sets
        // `convert` for a path the user NAMED: the whole buffer is searched
        // and the NUL is reported. A path the walk turned up keeps `quit`,
        // which drops the file whole. The raw path draws the same line, and
        // a unit that is the file's own bytes has to draw it too: a file
        // that carries a note beside its bytes is searched here, and a
        // binary one that `rg` counts must be counted here as well.
        if named_binary {
            &mut raw.convert_searcher
        } else {
            &mut raw.searcher
        }
    } else {
        &mut raw.text_searcher
    }
}

/// The file's own binary rule, for a unit that IS the file's own bytes.
///
/// The raw path sniffs the head and drops the whole file when it finds a
/// NUL, and `rg` does not count a binary file it never looked at as a file
/// without a match. The unit path had no such rule: a file that carries a
/// note beside its bytes was searched as a unit, so a binary one was
/// counted as a miss in `--files-without-match` -- and `rg` does not list
/// the binary files it never looked at.
///
/// The sniff is the file's, so it runs on the unit that IS the file's bytes.
/// A note is text by construction, and the rule below does not fire on it.
fn unit_is_binary(args: &Args, bytes: &[u8]) -> bool {
    if args.text {
        return false;
    }
    let head = &bytes[..SNIFF.min(bytes.len())];
    binary_cut(head, forced_bom_of(args)).is_some()
}

/// Files at or below this are slurped into the reusable scratch buffer
/// instead of being mmap'd: mmap page faults lose to a single read() for
/// small files (this is also rg's own conclusion — see the ripgrep FAQ on
/// why directory search avoids mmap). Large files keep the mmap path.
const BUFFER_PATH_MAX: u64 = 16 * 1024 * 1024;

/// Where to cut `head` for the binary branch, or `None` when the NUL
/// heuristic does not fire at all.
///
/// The index is a raw offset into `head` only when there is no mark. With a
/// mark the heuristic runs on the DECODED head, so the NUL that decided it is
/// a byte of the text and not an offset into the file, and the answer is
/// `Some(head.len())` — no cut, because no prefix of the raw file separates
/// the text before that NUL from the text after it.
///
/// `rg`'s binary detection lives inside its searcher, so it runs on what the
/// searcher hands the matcher, and a byte-order mark has already been decoded
/// by that point: `Searcher::search_slice` settles the mark and switches to
/// the decoding reader *before* it looks for the binary byte. This head sniff
/// runs earlier and outside the searcher, so on a marked buffer it was
/// reading a different stream than the reference was.
///
/// That is the whole of the PowerShell `.psd1` divergence. UTF-16LE
/// interleaves `00` after every ASCII character, so a data file holding an
/// ordinary `@{ ... }` hashtable is `00`-dense from its first byte; sniffing
/// the raw file called every one of them binary, line output was suppressed,
/// and `rgx` printed nothing at all where ripgrep printed the line. Decoding
/// the head first is what makes the two agree, and it is the same order the
/// searcher uses (`searcher.rs`, `bom_sniffing`).
///
/// The unmarked arm is the whole corpus and stays a single `memchr`, which is
/// why the decode sits behind the mark: only a file opening with `ef bb bf`,
/// `ff fe` or `fe ff` pays for it, and that is a handful of files in any tree.
fn binary_cut(head: &[u8], forced: Option<rgx_core::encoding::Bom>) -> Option<usize> {
    // A declared `-E` encoding: the heuristic runs on the decoded head,
    // exactly as it does behind a mark. NUL-dense UTF-16 is binary before
    // that decode and text after it, and the decode is what the matcher
    // will see, so asking the raw bytes is asking a different question.
    if let Some(bom) = forced {
        let decoded = rgx_core::encoding::force_decode(bom, head);
        return rgx_core::memchr::memchr(b'\x00', &decoded).map(|_| head.len());
    }
    let Some(bom) = rgx_core::encoding::sniff(head) else {
        return rgx_core::memchr::memchr(b'\x00', head);
    };
    // UTF-8 (with or without BOM) is a no-op copy past the BOM, so a
    // borrowed slice is enough. UTF-16/UTF-16BE has to be expanded into a
    // fresh buffer first; the head may end mid-code-unit, so the
    // decoder emits a replacement character (which is never NUL) and
    // a truncated head can neither invent nor hide one.
    let to_scan: Cow<[u8]> = if bom == rgx_core::encoding::Bom::Utf8 {
        Cow::Borrowed(rgx_core::encoding::strip_bom(bom, head))
    } else {
        Cow::Owned(rgx_core::encoding::decode(bom, head))
    };
    if rgx_core::memchr::memchr(b'\x00', to_scan.as_ref()).is_some() {
        Some(head.len())
    } else {
        None
    }
}

/// Search a file that no adapter claims. Files ≤16 MB are read once into a
/// reusable buffer; bigger files are searched through the mmap path and
/// never slurped into heap memory.
///
/// rg semantics for binary data: matches *before* the first NUL byte count
/// for the exit code, `-l` and `-c`, but line output is suppressed unless
/// `-a` is given. `BinaryDetection::quit` alone cannot deliver that — when
/// the NUL shares the first buffer with a match it reports nothing — so the
/// head sniff finds an early NUL and we search only the prefix before it.
///
/// `keep_binary` is [`keeps_binary_walk_hits`] for this path, and it decides
/// whether a binary file is searched past the NUL at all. See the branch
/// below; the short version is that a walked binary file is dropped whole by
/// the caller, so searching the rest of it cannot reach any output.
/// Read whatever the head read did not already take, if anything.
///
/// The head read is `take(SNIFF)`, so a file under the sniff window arrives
/// whole and the second read is a syscall that returns zero. That is not a
/// detail: measured over the same 4,000 files with no rgx code in the loop,
/// `open` plus two reads costs 38.0 us a file and `open` plus `close` costs
/// 26.6 us, so the wasted call is a quarter of what it takes to open the
/// file at all. On the 56,407-file registry walk it is 56,407 wasted
/// syscalls, and the per-file search cost is 36.8 us in total -- this is
/// five of those.
#[cfg(windows)]
#[inline]
fn open_file_for_search(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x08000000;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_SEQUENTIAL_SCAN)
        .open(path)
}

#[cfg(not(windows))]
#[inline]
fn open_file_for_search(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

/// How many bytes the magic probe reads.
///
/// The longest magic in the registry is eight bytes (`BORG_SEG`) and the
/// probe reads a window rather than exactly the magic, so a longer prefix
/// added later still fits without touching this. Sixteen bytes is one read.
const MAGIC_PROBE: usize = 16;

/// true if the file's first bytes claim an adapter that its name does not.
///
/// **This is the one read the raw path does not need, and it buys the reach
/// of the formats that do not name themselves.** A file no adapter claims by
/// extension is searched raw, and the raw path opens the file anyway; this
/// is the second open, and it is paid only for the files that reach it. It
/// reads a window, not the file: the answer needs the head, and the head is
/// the whole of the claim.
fn claims_magic(path: &std::path::Path, reg: &Registry) -> bool {
    use std::io::Read as _;
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut buf = [0u8; MAGIC_PROBE];
    let mut got = 0usize;
    while got < buf.len() {
        match file.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    reg.claims_magic(&buf[..got])
}

/// Reads up to `buf.len()` bytes into `buf`.
///
/// Unlike `read_to_end`, this completes as soon as `buf.len()` bytes are read,
/// avoiding the redundant 0-byte EOF syscall for files whose size is known from
/// directory enumeration metadata.
fn read_exact_or_all(file: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    use std::io::Read;
    let mut total = 0;
    while total < buf.len() {
        match file.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

#[allow(clippy::too_many_arguments)]
/// Search one file that no adapter claims, and stamp the size we already had
/// onto the hit so `--json` does not have to `stat` it again.
///
/// `len` is this file's OWN length -- the caller's `meta.len()`, already
/// compared against `-M` a few lines earlier -- so this is the same number
/// `std::fs::metadata(&hit.path)` would have re-derived, minus a syscall per
/// matched file. It is set here rather than at the walk's call site because
/// this is the only producer whose hit is unambiguously the file itself: the
/// walk closure also builds hits for adapter units, and those must not
/// inherit the container's size.
fn raw_search(
    st: &mut RawState,
    path: &std::path::Path,
    args: &Args,
    keep_binary: bool,
    is_binary: &mut bool,
    max_file_size: u64,
    explicit_paths: &std::collections::HashSet<String>,
) -> Result<Option<FileHit>> {
    let mut hit = raw_search_inner(
        st,
        path,
        args,
        keep_binary,
        is_binary,
        max_file_size,
        explicit_paths,
    )?;
    if let Some(h) = &mut hit {
        h.bytes_searched = Some(st.last_len);
    }
    Ok(hit)
}

fn raw_search_inner(
    st: &mut RawState,
    path: &std::path::Path,
    args: &Args,
    keep_binary: bool,
    is_binary: &mut bool,
    max_file_size: u64,
    explicit_paths: &std::collections::HashSet<String>,
) -> Result<Option<FileHit>> {
    let mut file = open_file_for_search(path)?;
    // Fill-derived length. The sniff window is read before anything asks
    // how big the file is, and a SHORT read is the answer: it means EOF
    // was reached inside the window, so what was read is the whole file
    // and its length. Every file under SNIFF -- the many-small-files
    // shape, 20k of them on the bench tree -- therefore pays no size
    // syscall at all, where the walk used to answer with a path `stat`
    // per file. Only a file that FILLS the window asks the handle
    // (`file_len`, one fstat) and only it continues the old reads from
    // the offset the window left off at.
    if st.head.len() < SNIFF {
        st.head.resize(SNIFF, 0);
    }
    // ONE read, not `read_exact_or_all`: the probe must not discover EOF
    // with a second call, or the small file trades its stat for a read and
    // gains nothing. A short read from a regular file IS EOF -- `File::read`
    // retries `Interrupted` internally, so the only short read left is the
    // end of the file -- and the raw path only ever sees regular files.
    let n = {
        use std::io::Read as _;
        file.read(&mut st.head[..SNIFF])?
    };
    let len = if (n as u64) < SNIFF as u64 {
        n as u64
    } else {
        crate::engine::mmap::file_len(&file)?
    };
    st.last_len = len;
    // `--max-filesize` caps what gets searched. rg does not apply it to a
    // path named on the command line, and neither does this: naming a file
    // is an instruction to search it. The explicit-path test stays behind
    // the size comparison's short circuit -- it runs only for the rare
    // file that is over the cap, which is exactly what the walk's filter
    // did before the length moved here.
    if len > max_file_size && !is_explicit_path(explicit_paths, path) {
        st.sink.end_file();
        return Ok(None);
    }
    // `--json` reports each line's byte offset in the file. Both sink faces
    // hand a sink that offset directly -- `SinkMatch::absolute_byte_offset`
    // and `SinkContext::absolute_byte_offset`, names and semantics kept from
    // `grep-searcher` -- and both define it as relative to the start of the
    // searched input rather than to the rolling buffer, which is why the
    // mmap branch below needs no special case.
    let buffered = len <= BUFFER_PATH_MAX;
    if !args.text && keep_binary {
        // A path the user NAMED. ripgrep does not use `quit` here, and this is
        // the whole of the difference: `BinaryDetection::from_low_args` in
        // ripgrep 15.0.0 gives `convert` for an explicit path and `quit` for
        // one the walk turned up. `convert` replaces every NUL with the line
        // terminator and keeps going, so the count covers the whole file
        // while the sink still learns where the binary data started and the
        // printer suppresses the line output -- which is what rg does with a
        // binary file it was handed on the command line.
        //
        // The head sniff is not consulted on this path and does not need to
        // be: the searcher reports the offset itself. It used to be the whole
        // of the binary decision, over a 64 KiB window, so a NUL at byte
        // 100,000 read as "not binary", the file went to the ordinary `quit`
        // searcher, and every match after the NUL was dropped. Concatenating
        // the 56,408-file registry into one 1.24 GB file, ripgrep counted
        // 17,654,305 lines and rgx counted 6,782,043 -- a strict subset, on
        // the shape the harness gates on, from a file the user named.
        st.sink.reset();
        if buffered {
            // The sniff window at the top already holds the whole file
            // when `len <= SNIFF`; only a longer one reads the rest, and
            // it continues from where the window stopped.
            if len > SNIFF as u64 {
                let full_len = len as usize;
                if st.head.len() < full_len {
                    st.head.resize(full_len, 0);
                }
                let rest = read_exact_or_all(&mut file, &mut st.head[n..full_len])?;
                let total = n + rest;
                st.convert_searcher
                    .search_slice(&st.head[..total], &mut st.sink)?;
            } else {
                st.convert_searcher
                    .search_slice(&st.head[..n], &mut st.sink)?;
            }
            if st.head.len() > HEAD_KEEP_MAX {
                st.head.truncate(SNIFF);
                st.head.shrink_to(SNIFF);
            }
        } else {
            // The handle opened at the top of this function, still unread on this
            // branch and carrying FILE_FLAG_SEQUENTIAL_SCAN. Handing it over
            // is the point: search_path used to re-stat the path and open
            // it a second time without the hint.
            let _ = st.convert_searcher.search_path(file, len, &mut st.sink);
        }
        // The file was searched as text -- rg's rule for a path the user
        // NAMED -- so it was looked at, and a file that was looked at and
        // did not match is a miss. `is_binary` here is the FILE's verdict
        // ("rg would never have looked at this"), and rg did look: it
        // listed the named binary file in `--files-without-match` while
        // rgx kept it out, because the convert rule reports the NUL and
        // the report was read as "never looked at". The hit keeps its own
        // binary flag, so the line output is still suppressed.
        *is_binary = false;
        return Ok(st.sink.take_hit(
            || path_for_hit(args.no_filename, &path.to_string_lossy()),
            "raw",
        ));
    }
    if !args.text {
        // The sniff window was already read at the top as the fill-derived
        // length probe: `n` is its fill, and for files <= SNIFF it is the
        // entire file content, read in a single syscall with zero extra
        // EOF reads -- the property this branch always wanted. The binary
        // classification runs on it.
        // The head sniff runs on every file walked, so a byte-at-a-time
        // scan of 64 KiB per file is a cost on the whole corpus, not on
        // the binaries. `memchr` is the word-at-a-time scan the rest of
        // this file already uses; only this one call was still a loop.
        if binary_cut(&st.head[..n], forced_bom_of(args)).is_some() {
            // Binary by the NUL heuristic. Whether the file is searched past
            // the NUL depends on where the path came from.
            //
            // A walked file is dropped whole by the caller -- out of
            // `-c`, out of `-l`, out of the exit status, with only
            // `is_binary` surviving to keep it out of
            // `--files-without-match`. No hit past the NUL can change
            // any of that, so there is nothing to search for and no
            // reason to read the rest. This is the cut ripgrep makes
            // without meaning to: `grep-searcher`'s `LineBuffer::fill`
            // truncates at the first binary byte and reports EOF
            // (`line_buffer.rs`, the `BinaryDetection::Quit` arm).
            //
            // A file named on the command line is different: it keeps
            // its hit, so matches after the NUL are the answer. rg
            // counts them, so must we, or `-c` and `-l` report nothing
            // for every binary file whose match is not in the first few
            // kilobytes. What the NUL suppresses is line output, and the
            // printer already drops that on `hit.binary` unless `-a`.
            *is_binary = true;
            if !keep_binary {
                st.sink.end_file();
                return Ok(None);
            }
            st.sink.reset();
            st.sink.binary = true;
            if buffered {
                if len > SNIFF as u64 {
                    let full_len = len as usize;
                    if st.head.len() < full_len {
                        st.head.resize(full_len, 0);
                    }
                    let rest = read_exact_or_all(&mut file, &mut st.head[n..full_len])?;
                    let total = n + rest;
                    st.text_searcher
                        .search_slice(&st.head[..total], &mut st.sink)?;
                    if st.head.len() > HEAD_KEEP_MAX {
                        st.head.truncate(SNIFF);
                        st.head.shrink_to(SNIFF);
                    }
                } else {
                    st.text_searcher.search_slice(&st.head[..n], &mut st.sink)?;
                }
            } else {
                let _ = st.text_searcher.search_path(file, len, &mut st.sink);
            }
            return Ok(st.sink.take_hit(
                || path_for_hit(args.no_filename, &path.to_string_lossy()),
                "raw",
            ));
        }
        if buffered {
            // small file: append the rest to the bytes already sniffed —
            // no seek, no rereading the head
            if len > SNIFF as u64 {
                let full_len = len as usize;
                if st.head.len() < full_len {
                    st.head.resize(full_len, 0);
                }
                let rest = read_exact_or_all(&mut file, &mut st.head[n..full_len])?;
                let total = n + rest;
                st.sink.reset();
                st.searcher.search_slice(&st.head[..total], &mut st.sink)?;
                *is_binary = st.sink.binary;
                if st.head.len() > HEAD_KEEP_MAX {
                    st.head.truncate(SNIFF);
                    st.head.shrink_to(SNIFF);
                }
                return Ok(st.sink.take_hit(
                    || path_for_hit(args.no_filename, &path.to_string_lossy()),
                    "raw",
                ));
            } else {
                st.sink.reset();
                st.searcher.search_slice(&st.head[..n], &mut st.sink)?;
                *is_binary = st.sink.binary;
                return Ok(st.sink.take_hit(
                    || path_for_hit(args.no_filename, &path.to_string_lossy()),
                    "raw",
                ));
            }
        }
        // large file: mmap search on disk
        st.sink.reset();
        let _ = st.searcher.search_path(file, len, &mut st.sink);
        *is_binary = st.sink.binary;
        return Ok(st.sink.take_hit(
            || path_for_hit(args.no_filename, &path.to_string_lossy()),
            "raw",
        ));
    }
    if buffered {
        // Same fill-derived shape as the named branch: the sniff window
        // at the top is the whole file when `len <= SNIFF`.
        let n = if len > SNIFF as u64 {
            let full_len = len as usize;
            if st.head.len() < full_len {
                st.head.resize(full_len, 0);
            }
            let rest = read_exact_or_all(&mut file, &mut st.head[n..full_len])?;
            n + rest
        } else {
            n
        };
        st.sink.reset();
        st.searcher.search_slice(&st.head[..n], &mut st.sink)?;
        *is_binary = st.sink.binary;
        if st.head.len() > HEAD_KEEP_MAX {
            st.head.truncate(SNIFF);
            st.head.shrink_to(SNIFF);
        }
        Ok(st.sink.take_hit(
            || path_for_hit(args.no_filename, &path.to_string_lossy()),
            "raw",
        ))
    } else {
        st.sink.reset();
        let _ = st.searcher.search_path(file, len, &mut st.sink);
        *is_binary = st.sink.binary;
        Ok(st.sink.take_hit(
            || path_for_hit(args.no_filename, &path.to_string_lossy()),
            "raw",
        ))
    }
}

/// Last paragraph break (a `\n`, optional horizontal whitespace, `\n`) at
/// or before `at`, searched back at most `tol` bytes; returns the index
/// just past the break. `None` = no blank line within tolerance.
fn last_para_break(data: &[u8], at: usize, tol: usize) -> Option<usize> {
    let at = at.min(data.len());
    let lo = at.saturating_sub(tol);
    let mut found = None;
    for i in rgx_core::memchr::memchr_iter(b'\n', &data[lo..at]) {
        let mut j = lo + i + 1;
        while j < data.len() && matches!(data[j], b' ' | b'\t' | b'\r') {
            j += 1;
        }
        if j < data.len() && data[j] == b'\n' {
            found = Some(j + 1);
        }
    }
    found
}

/// Symmetric forward version of last_para_break: first paragraph break at
/// or after `at`, within `tol` bytes.
fn next_para_break(data: &[u8], at: usize, tol: usize) -> Option<usize> {
    let at = at.min(data.len());
    let hi = at.saturating_add(tol).min(data.len());
    for i in rgx_core::memchr::memchr_iter(b'\n', &data[at..hi]) {
        let mut j = at + i + 1;
        while j < data.len() && matches!(data[j], b' ' | b'\t' | b'\r') {
            j += 1;
        }
        if j < hi && data[j] == b'\n' {
            return Some(j + 1);
        }
    }
    None
}

/// Build paragraph-aware context chunks around sorted, non-overlapping
/// match ranges: each window is `budget` bytes centered on its match. The
/// cut snaps to the paragraph containing the match (a blank line within
/// half+quarter budget of the match edge), then to a plain line boundary
/// if one is within a quarter budget, and finally hard-cuts at the budget
/// edge — so a match in a one-line-megabyte file cannot drag the whole
/// file into the chunk. Overlapping windows merge, cuts land on UTF-8
/// char boundaries, and line numbers are counted incrementally in one
/// pass regardless of chunk count.
fn build_chunks(data: &[u8], ranges: &[std::ops::Range<usize>], budget: usize) -> Vec<Chunk> {
    let half = budget / 2;
    let tol = budget / 4;
    let mut wins: Vec<std::ops::Range<usize>> = Vec::with_capacity(ranges.len());
    for r in ranges {
        let raw_s = r.start.saturating_sub(half);
        let raw_e = r.end.saturating_add(half).min(data.len());
        let s = last_para_break(data, r.start, half + tol)
            .or_else(|| {
                let ls = data[..r.start.min(data.len())]
                    .iter()
                    .rposition(|&b| b == b'\n')
                    .map(|p| p + 1)
                    .unwrap_or(0);
                (r.start - ls <= tol).then_some(ls)
            })
            .unwrap_or(raw_s);
        let e = next_para_break(data, r.end, half + tol)
            .or_else(|| {
                data[r.end.min(data.len())..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .and_then(|p| {
                        let le = r.end + p + 1;
                        (le - r.end <= tol && le <= data.len()).then_some(le)
                    })
            })
            .unwrap_or(raw_e);
        let e = e.min(data.len());
        if let Some(last) = wins.last_mut() {
            if s <= last.end {
                last.end = last.end.max(e);
                continue;
            }
        }
        wins.push(s..e);
    }
    let mut chunks = Vec::with_capacity(wins.len());
    let mut line: u64 = 1;
    let mut pos = 0usize;
    for w in wins {
        line += data[pos..w.start.min(data.len())]
            .iter()
            .filter(|&&b| b == b'\n')
            .count() as u64;
        pos = w.start;
        let mut s = w.start.min(data.len());
        let mut e = w.end.min(data.len());
        // UTF-8 char boundary = not a continuation byte (10xxxxxx)
        while s < e && s > 0 && (data[s] & 0xC0) == 0x80 {
            s += 1;
        }
        while e > s && e < data.len() && (data[e] & 0xC0) == 0x80 {
            e -= 1;
        }
        let text = {
            let mut end = e;
            while end > s && data[end - 1].is_ascii_whitespace() {
                end -= 1;
            }
            data[s..end].to_vec()
        };
        chunks.push(Chunk {
            line_number: line,
            bytes: text,
        });
    }
    chunks
}

/// Chunk mode for the raw path: mmap the file (no heap copy even for
/// multi-GB inputs), collect match ranges with the same searcher the line
/// mode uses, cut chunks. Deliberately opt-in — harness use buffers the
/// address space, not the heap.
fn chunk_search(
    path: &Path,
    path_str: &str,
    args: &Args,
    budget: usize,
    explicit_paths: &std::collections::HashSet<String>,
) -> Result<Option<ChunkHit>> {
    let file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    // `--max-filesize` caps the chunk path as it caps the line path: the
    // check that moved out of the walker lives in `raw_search_inner`, and
    // this branch never went through it — a walked file of any size was
    // read whole into memory. A path the user named is exempt, the same
    // rule the line path holds.
    if len > parse_size(&args.max_filesize)? as u64 && !is_explicit_path(explicit_paths, path) {
        return Ok(None);
    }
    // Chunk extraction needs random access to the matched ranges, so the
    // file is read once — the walker's --max-filesize cap has already
    // bounded it, the same trade the <=16 MB branch above makes.
    let data = std::fs::read(path)?;
    let mut searcher = make_searcher(args);
    let mut sink = RangeSink::new(args.quiet, args.max_count, compiled_byte_arc(args));
    let _ = searcher.search_slice(&data, &mut sink);
    if sink.count == 0 {
        return Ok(None);
    }
    let chunks = build_chunks(&data, &sink.ranges, budget);
    if chunks.is_empty() {
        return Ok(None);
    }
    Ok(Some(ChunkHit {
        path: path_str.to_string(),
        via: "raw",
        count: sink.count,
        binary: sink.binary,
        chunks,
    }))
}

/// Resolve `-E/--encoding` to a forced [`rgx_core::encoding::Bom`].
///
/// Only UTF-8, UTF-16LE and UTF-16BE are wired up; any other name
/// falls through to `Utf8` (the BOM detection path) so the searcher
/// keeps working and the user gets a sensible default rather than an
/// error. The CLI parser accepts any value to keep the surface stable
/// for future encodings.
fn resolve_forced_bom(name: Option<&str>) -> rgx_core::encoding::Bom {
    match name.map(str::to_ascii_lowercase).as_deref() {
        Some("utf-16le") | Some("utf16le") => rgx_core::encoding::Bom::Utf16Le,
        Some("utf-16be") | Some("utf16be") => rgx_core::encoding::Bom::Utf16Be,
        // utf-8, ascii, latin-1, and any unknown name fall through to
        // the BOM-detection path; the user can still discover the
        // active encoding via `rg --help` once we wire those tables.
        _ => rgx_core::encoding::Bom::Utf8,
    }
}

/// The encoding `-E` forces onto the searchers, or `None` when the flag
/// leaves them to sniff the mark as usual.
///
/// `-E utf-8` is `None` on purpose: the bytes pass through either way and
/// a mark is still the better answer for a marked file. `None` is also the
/// no-flag case, so this is one `Option` where `None` means "sniff" and
/// `Some` means "the caller said" -- `searcher::Config::forced_bom`'s rule.
fn forced_bom_of(args: &Args) -> Option<rgx_core::encoding::Bom> {
    let bom = resolve_forced_bom(args.encoding.as_deref());
    (bom != rgx_core::encoding::Bom::Utf8).then_some(bom)
}

/// In-memory twin of `raw_search` for files the walker already read (the
/// adapter path that ended in a total bail): same NUL-prefix binary
/// semantics, but no second open+read of the file.
fn raw_search_buf(
    st: &mut RawState,
    data: &[u8],
    path_str: &str,
    args: &Args,
    keep_binary: bool,
    is_binary: &mut bool,
) -> Result<Option<FileHit>> {
    // `-E` / `--encoding` reaches the searcher as `Config::forced_bom`,
    // which decodes before any line is looked for -- one rule for every
    // raw-input surface (this buffer, a file's reads, a map, stdin). The
    // binary heuristic below asks the same question of the same decoded
    // view; see `binary_cut`.
    raw_search_buf_inner(st, data, path_str, args, keep_binary, is_binary)
}

fn raw_search_buf_inner(
    st: &mut RawState,
    data: &[u8],
    path_str: &str,
    args: &Args,
    keep_binary: bool,
    is_binary: &mut bool,
) -> Result<Option<FileHit>> {
    if !args.text && keep_binary {
        // The in-memory twin of the explicit branch in `raw_search`, and the
        // same ripgrep rule: `convert`, the whole buffer, and the offset left
        // for the sink to report.
        st.sink.reset();
        st.convert_searcher.search_slice(data, &mut st.sink)?;
        // The file was searched as text -- rg's rule for a path the user
        // NAMED -- so it was looked at, and a file that was looked at and
        // did not match is a miss. See the same line in `raw_search`.
        *is_binary = false;
        return Ok(st.sink.take_hit(|| path_str.to_string(), "raw"));
    }
    if !args.text {
        let head = &data[..SNIFF.min(data.len())];
        if binary_cut(head, forced_bom_of(args)).is_some() {
            // The whole buffer, not the prefix before the NUL, when the path
            // was named on the command line -- rg counts the matches that sit
            // after the NUL, and an explicit file is searched as text -- but
            // the cut is free for a walked one, which the caller drops whole
            // anyway. See `raw_search`.
            *is_binary = true;
            if !keep_binary {
                st.sink.end_file();
                return Ok(None);
            }
            st.sink.reset();
            st.sink.binary = true;
            st.text_searcher.search_slice(data, &mut st.sink)?;
            return Ok(st.sink.take_hit(|| path_str.to_string(), "raw"));
        }
    }
    st.sink.reset();
    st.searcher.search_slice(data, &mut st.sink)?;
    *is_binary = st.sink.binary;
    Ok(st.sink.take_hit(|| path_str.to_string(), "raw"))
}

/// In-memory twin of `chunk_search` for already-read buffers.
fn chunk_search_buf(
    data: &[u8],
    path_str: &str,
    args: &Args,
    budget: usize,
) -> Result<Option<ChunkHit>> {
    if data.is_empty() {
        return Ok(None);
    }
    let mut searcher = make_searcher(args);
    let mut sink = RangeSink::new(args.quiet, args.max_count, compiled_byte_arc(args));
    let _ = searcher.search_slice(data, &mut sink);
    if sink.count == 0 {
        return Ok(None);
    }
    let chunks = build_chunks(data, &sink.ranges, budget);
    if chunks.is_empty() {
        return Ok(None);
    }
    Ok(Some(ChunkHit {
        path: path_str.to_string(),
        via: "raw",
        count: sink.count,
        binary: sink.binary,
        chunks,
    }))
}

fn parse_size(s: &str) -> Result<u64> {
    let (num, mult) = s
        .trim()
        .split_at(s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len()));
    // The number side fails on anything non-numeric, and the raw parse error
    // is not what a user of `-M huge` needs to read: "cannot parse float
    // from empty string" describes the split, not the input.
    let n: f64 = match num.trim().parse::<f64>() {
        Ok(n) => n,
        Err(_) => {
            rgx_core::bail!("invalid size {s:?}: expected a byte count like 512, 100K, 20M or 1G")
        }
    };
    let m = match mult.trim().to_lowercase().as_str() {
        "" | "b" => 1.0,
        "k" | "kb" | "kib" => 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        other => {
            rgx_core::bail!("unknown size suffix {other} in {s:?}: expected k, m or g")
        }
    };
    Ok((n * m) as u64)
}

/// The structured filter `--filter` asked for, parsed.
///
/// A filter that does not parse is the user's mistake and the message says
/// what was expected: a filter that silently matched nothing would look
/// like a corpus with nothing in it.
fn filter_of(args: &Args) -> Result<Option<rgx_core::filter::Filter>> {
    let Some(text) = args.filter.as_deref() else {
        return Ok(None);
    };
    match rgx_core::filter::Filter::parse(text) {
        Ok(f) => Ok(Some(f)),
        Err(e) => rgx_core::bail!("invalid --filter {text:?}: {e}"),
    }
}

/// The compiled pattern `-r` replacement output runs against, on the
/// in-house byte engine. Mirrors `byte_pattern`'s flag semantics
/// (fixed-strings escape, word wrap, smart case) so the replacement sees
/// exactly the matches the searcher found; capture references ($1,
/// ${name}) expand against the same engine's groups.
///
/// This used to be a `regex::bytes::Regex`, which was the last runtime
/// dependency the binary linked. The engine answers the two questions it
/// asks -- find the leftmost match, expand a `$`-template against its
/// groups -- and the template language is differential against that
/// crate's `expand` in `replacement_templates_expand_like_the_oracle`.
/// The flags line up: the crate's `multi_line(true)` over a single LINE
/// is what this engine's default anchors already mean, and its
/// `dot_matches_new_line(false)` is the default on both sides.
fn build_replace_regex(args: &Args) -> Option<rgx_core::regex::ByteRegex> {
    args.replace.as_ref()?;
    let mut pat = args.pattern.clone().unwrap_or_default();
    let smart_ci = args.smart_case && !pat.chars().any(char::is_uppercase);
    if args.fixed_strings {
        pat = core::str::from_utf8(&rgx_core::regex::escape(pat.as_bytes()))
            .map(Cow::Borrowed)
            .unwrap_or_else(|_| {
                Cow::Owned(
                    String::from_utf8_lossy(&rgx_core::regex::escape(pat.as_bytes())).into_owned(),
                )
            })
            .into_owned();
    }
    if args.word_regexp {
        pat = format!("(?:\\b(?:{pat})\\b)");
    }
    rgx_core::regex::ByteRegex::new_flags(pat.as_bytes(), args.ignore_case || smart_ci).ok()
}

/// What flows from the workers to the printer: real hits, chunk-mode hits,
/// plus plain path listings (`--files` and `-L`) that never carry data.
enum Msg {
    Hit(FileHit),
    Chunks(ChunkHit),
    Listed(String),
    ListedBatch(Vec<u8>),
    /// One file's `--json` records, already formatted, plus the counters rg
    /// reports for that file. Formatted where the file was searched: the
    /// printer used to do it, one thread formatting every record of every
    /// file while the rest waited on it, and `rg` formats in its search
    /// threads -- on a flat 20,000-file tree at `-j32` that was `fn main` in
    /// 1531 ms against rg's 134, and `pub fn` over the tree 1358 against 149.
    Json(Vec<u8>, JsonStats),
    /// One file's plain-text output, formatted where the file was searched.
    /// Same reason as `Json`: the printer formatted every line of every file
    /// on one thread, and printing lines cost rgx 189 ms over its own `-c`
    /// where it costs rg 5.
    Text(Vec<u8>),
    /// Several files' plain-text records concatenated into one buffer, so
    /// the worker sends one MPSC message per ~8 KiB of output instead of
    /// one per file. Same batching win as `ListedBatch`: a 20,000-file
    /// tree at `-j32` with a dense pattern was 20,000 single-message sends,
    /// and each one is a mutex acquisition on the channel. Batching is the
    /// same fix that took `walk --files` from 31 ms (one message per path,
    /// rgx 1.41x slower than rg) to 15 ms (8 KiB blocks, rgx 1.46x faster).
    TextBatch(Vec<u8>),
}

/// Output sink shared by every walker thread. Workers format each
/// listing into their own [`Vec<u8>`] scratch and hand the full
/// scratch to a single `BufWriter<Stdout>` under a `Mutex` only when
/// the scratch fills. Compared to streaming each path through an
/// `mpsc::Sender` (the previous design) this collapses 20 000 channel
/// sends on a 20 000-file tree into ~50 lock acquisitions, the same
/// number the `BufWriter` would issue anyway on a single writer.
struct DirectBatcher {
    /// Per-worker scratch; one Vec reused across all paths the worker
    /// pushes, flushed to the shared writer at 8 KiB or on drop.
    scratch: Vec<u8>,
    /// `Arc` shared with every other worker; `BufWriter` keeps the
    /// 256 KiB kernel-buffer hint that the previous stream also used.
    shared: Arc<Mutex<std::io::BufWriter<std::io::Stdout>>>,
    /// Path separator: `\n` by default, `\0` under `-0` / `--null`.
    sep: u8,
}

impl DirectBatcher {
    const FLUSH_AT: usize = 8 * 1024;

    fn new(shared: Arc<Mutex<std::io::BufWriter<std::io::Stdout>>>, sep: u8) -> Self {
        Self {
            scratch: Vec::with_capacity(Self::FLUSH_AT),
            shared,
            sep,
        }
    }

    fn push(&mut self, path: &std::path::Path) -> WalkState {
        let bytes = path.as_os_str().as_encoded_bytes();
        if bytes.contains(&b'\\') {
            for &b in bytes {
                self.scratch.push(if b == b'\\' { b'/' } else { b });
            }
        } else {
            self.scratch.extend_from_slice(bytes);
        }
        self.scratch.push(self.sep);
        if self.scratch.len() >= Self::FLUSH_AT {
            self.flush()
        } else {
            WalkState::Continue
        }
    }

    fn flush(&mut self) -> WalkState {
        if self.scratch.is_empty() {
            return WalkState::Continue;
        }
        // The previous channel design used `mem::swap` with a
        // pre-warmed ring to dodge the `Vec::with_capacity` cost; with
        // a direct writer that overhead is gone and a single clear
        // is enough.
        let buf = std::mem::take(&mut self.scratch);
        // Keep the same 8 KiB capacity for the next flush.
        let mut next = Vec::with_capacity(Self::FLUSH_AT);
        std::mem::swap(&mut self.scratch, &mut next);
        let mut g = self.shared.lock().unwrap();
        if g.write_all(&buf).is_err() {
            return WalkState::Quit;
        }
        WalkState::Continue
    }
}

impl Drop for DirectBatcher {
    fn drop(&mut self) {
        self.flush();
        // A small enough tree to fit entirely in the per-worker
        // scratch never trips the 8 KiB flush threshold; without this
        // final drain the trailing batch sits in the shared
        // BufWriter until the test reads /dev/null.
        if let Ok(mut g) = self.shared.lock() {
            let _ = g.flush();
        }
    }
}

/// Variant of `DirectBatcher` that buffers every path across all
/// workers in a shared `Arc<Mutex<Vec<Vec<u8>>>>` and emits them
/// sorted at end of run. Used when the user passes `--sort=path` on
/// `--files`/`-l`/`--files-with-matches`. The buffering cost is paid
/// once per run; the per-file push is identical to the streaming
/// variant.
struct SortedSink {
    paths: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    sep: u8,
    /// `false` ⇒ sort ascending (rg's `--sort path`); `true` ⇒ reverse
    /// (`--sortr path`).
    reverse: bool,
}

impl SortedSink {
    fn new(sep: u8, reverse: bool) -> Self {
        Self {
            paths: Arc::new(std::sync::Mutex::new(Vec::with_capacity(2048))),
            sep,
            reverse,
        }
    }

    fn push(&self, path: &std::path::Path) -> WalkState {
        let bytes = path.as_os_str().as_encoded_bytes();
        let mut owned = Vec::with_capacity(bytes.len() + 1);
        if bytes.contains(&b'\\') {
            for &b in bytes {
                owned.push(if b == b'\\' { b'/' } else { b });
            }
        } else {
            owned.extend_from_slice(bytes);
        }
        // Push straight into the shared vec; the lock is per-push
        // (cheap, no contention between workers on the hot path of
        // a 20k-file tree measured against the cost of the rest of
        // the worker), and the whole vec is taken out at the end
        // for the sort.
        self.paths.lock().unwrap().push(owned);
        WalkState::Continue
    }

    fn finalize(self) -> Vec<u8> {
        // Take the inner vec out of the Arc; if any worker is still
        // holding its clone (the strong_count is > 1) we fall back to
        // locking the mutex and cloning the contents out. Either way,
        // every byte that was pushed ends up in `sorted`.
        let mut sorted = match Arc::try_unwrap(self.paths) {
            Ok(mutex) => mutex.into_inner().unwrap(),
            Err(arc) => arc.lock().unwrap().clone(),
        };
        if self.reverse {
            sorted.sort_by(|a, b| b.cmp(a));
        } else {
            sorted.sort();
        }
        let mut out = Vec::with_capacity(sorted.iter().map(|s| s.len() + 1).sum());
        for p in &sorted {
            out.extend_from_slice(p);
            out.push(self.sep);
        }
        out
    }
}

/// Wrapper that selects between the direct-shared [`DirectBatcher`]
/// and the buffering [`SortedSink`] for a single worker. The first
/// produces bytes that arrive at the printer without going through
/// the mpsc channel; only the sort path needs an extra hop. The
/// single dispatch keeps the rest of the pipeline agnostic to which
/// sink is in use.
enum ListedSink {
    Direct(DirectBatcher),
    Sorted(Arc<SortedSink>),
}

impl ListedSink {
    fn push(&mut self, path: &std::path::Path) -> WalkState {
        match self {
            ListedSink::Direct(b) => b.push(path),
            ListedSink::Sorted(b) => b.push(path),
        }
    }
}

/// Batches plain-text output per worker, mirroring `DirectBatcher` for
/// the `--files` path. Each `text_msg(...)` produces a `Vec<u8>` of
/// pre-formatted lines; the batcher concatenates them into one buffer and
/// sends a single `Msg::TextBatch` per ~8 KiB. On a dense pattern over a
/// 20,000-file tree this collapses 20,000 single-message sends into ~2,500
/// batched sends -- the difference between 20,000 and 2,500 mutex
/// acquisitions on the MPSC channel.
///
/// Buffer recycling: the worker keeps a small ring of pre-sized buffers
/// so a `flush` is `mem::take` + `swap`, not a fresh allocation. The
/// printer does not need to return anything; the ring's second slot is
/// already warmed with an 8 KiB capacity by the time the next file's
/// text arrives, so the worker thread pays one `Vec::with_capacity(8192)`
/// per worker per run, not one per batch.
struct TextBatcher {
    /// The buffer we are filling right now. `flush()` moves this out to
    /// `ring` and pulls the pre-warmed next buffer into `buf`.
    buf: Vec<u8>,
    /// 2-slot ring of pre-sized buffers. Slot 0 is the in-flight buffer;
    /// slot 1 is the next-warm. `flush` swaps them.
    ring: [Vec<u8>; 2],
    txw: std::sync::mpsc::Sender<Option<Msg>>,
}

impl TextBatcher {
    fn new(txw: std::sync::mpsc::Sender<Option<Msg>>) -> Self {
        let warm = Vec::with_capacity(8192);
        Self {
            buf: Vec::with_capacity(8192),
            ring: [Vec::new(), warm],
            txw,
        }
    }

    /// The borrowing form of `Self::push_bytes`: the caller owns the scratch
    /// the text was formatted into, so no `Vec<u8>` allocation happens
    /// per file. The `>= 8192` direct-send shortcut is gone because a
    /// borrow cannot be sent; the bytes are always copied into the
    /// batch, which for the common ~100-500 byte file is a memcpy the
    /// allocator would have charged more for than the copy itself.
    fn push_bytes(&mut self, text: &[u8]) -> WalkState {
        if self.buf.len() + text.len() > 8192 && !self.buf.is_empty() {
            let ret = self.flush();
            if ret == WalkState::Quit {
                return WalkState::Quit;
            }
        }
        self.buf.extend_from_slice(text);
        if self.buf.len() >= 8192 {
            self.flush()
        } else {
            WalkState::Continue
        }
    }

    fn flush(&mut self) -> WalkState {
        if self.buf.is_empty() {
            return WalkState::Continue;
        }
        // Swap buf with ring[1], so the previously warm slot becomes the
        // in-flight buffer and the (now empty) sent buffer takes its
        // place -- capacity preserved, no allocation. ring[0] is unused
        // in this design; the symmetry with ListedBatcher's identical
        // swap is what kept the code small.
        std::mem::swap(&mut self.buf, &mut self.ring[1]);
        let bytes = std::mem::take(&mut self.ring[1]);
        if self.txw.send(Some(Msg::TextBatch(bytes))).is_err() {
            WalkState::Quit
        } else {
            WalkState::Continue
        }
    }
}

impl Drop for TextBatcher {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Format one file's plain lines -- prefix and bytes and newline -- on the
/// caller's thread. The whole text-mode record is built here so the central
/// thread has nothing to do but `write_all` the bytes. The path the printer
/// used to take is gone, which is the structural win `rg` already has and
/// rgx is now catching up on: a single printer thread was every line of
/// every file on one core while the rest of the core watched.
///
/// Context separators (`--` between non-contiguous groups) are emitted here
/// when `context` is true. The worker formats one file at a time, so
/// `last_printed` only has to track within this file's lines -- the
/// printer's cross-file path check (`p != path`) collapses to nothing
/// because no second path can ever arrive mid-file.
///
/// `--only-matching`, `-r`, binary and the `--json`/`-c`/`-l` modes stay
/// on the central thread: they are smaller and the gates that pick them
/// in the worker fall through to `Msg::Hit` for them.
/// How one line is formatted into the text output: which parts of the
/// `{path}:{line}[:{col}]:` prefix this run prints, and in which style.
/// One value per run (the flags cannot change mid-walk), so the worker
/// resolves it once instead of per line.
#[derive(Clone, Copy)]
struct LineFmt {
    multi: bool,
    lines: bool,
    context: bool,
    heading: bool,
    color: bool,
    column: bool,
}

fn text_msg(fmt: LineFmt, hit: &FileHit) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    text_msg_into(&mut buf, fmt, hit);
    buf
}

/// The body of [`text_msg`] writing into a caller-owned scratch buffer,
/// so the walker formats a hit without allocating a fresh `Vec<u8>` per
/// file. The scratch is cleared here; the caller reuses it across files.
fn text_msg_into(buf: &mut Vec<u8>, fmt: LineFmt, hit: &FileHit) {
    buf.clear();
    let mut last_printed: Option<u64> = None;
    let mut path_printed = false;
    for line in &hit.lines {
        push_fmt_line(
            buf,
            fmt,
            &hit.path,
            &mut last_printed,
            &mut path_printed,
            LineIn {
                number: line.line_number,
                is_match: line.kind == LineKind::Match,
                raw: line.as_bytes(&hit.bytes),
                sub: line.submatches(),
            },
        );
    }
}

/// What [`push_fmt_line`] needs about one line: its number, whether it is
/// a match line, its bytes and its submatch spans.
struct LineIn<'a> {
    number: u64,
    is_match: bool,
    raw: &'a [u8],
    sub: &'a [Submatch],
}

/// Format ONE line -- match or context -- exactly as the text output owes
/// it: the `--` gap under `--context`, the `{path}:{line}[:{col}]:` prefix
/// (styled under `--color`), the line text (match spans bold-red under
/// `--color`, plain otherwise so a downstream `less -R` keeps the
/// highlight), and the terminator. Both the hit formatter and the
/// streaming sink call this, so the two can never drift.
///
/// `--heading` prints the path only on the first line of a file and drops
/// it for the rest; with heading off (or single-file) the path stays on
/// every line. The `--` gap rule mirrors the printer's `needs_separator`
/// arm: a line number exactly one past the previous one keeps the groups
/// contiguous; any other gap prints `--`.
fn push_fmt_line(
    buf: &mut Vec<u8>,
    fmt: LineFmt,
    path: &str,
    last_printed: &mut Option<u64>,
    path_printed: &mut bool,
    line: LineIn<'_>,
) {
    let LineIn {
        number,
        is_match,
        raw,
        sub,
    } = line;
    if fmt.context {
        match *last_printed {
            Some(n) if n + 1 == number => {}
            Some(_) => buf.extend_from_slice(b"--\n"),
            None => {}
        }
    }
    let print_path = !fmt.heading || !*path_printed;
    // The column is the 1-based byte offset of the leftmost submatch.
    // Context lines and inverted matches have no submatches, so the column
    // is left out for them -- the same rule the printer's arms apply.
    let col = if is_match && fmt.column {
        sub.first().map(|sm| sm.start as u64 + 1)
    } else {
        None
    };
    let p = prefix(
        path, fmt.multi, print_path, number, fmt.lines, is_match, col, fmt.color,
    );
    buf.extend_from_slice(p.as_bytes());
    if fmt.color && is_match && !sub.is_empty() {
        write_colored_match(buf, raw, sub);
    } else {
        buf.extend_from_slice(raw);
    }
    buf.push(b'\n');
    *last_printed = Some(number);
    *path_printed = true;
}

/// Emit `<bold-red>match</reset>` for every submatch byte range in
/// `raw`. `out` already holds the prefix; the function only writes the
/// line text and the SGR escapes interleaved with the original bytes.
/// Outside-match bytes pass through verbatim so line context (tabs,
/// trailing whitespace) is preserved.
fn write_colored_match(out: &mut Vec<u8>, raw: &[u8], submatches: &[Submatch]) {
    let mut cursor = 0usize;
    for sm in submatches {
        let s = sm.start as usize;
        let e = sm.end as usize;
        if s > cursor {
            out.extend_from_slice(&raw[cursor..s]);
        }
        out.extend_from_slice(sgr::MATCH_BOLD_RED);
        out.extend_from_slice(&raw[s..e]);
        out.extend_from_slice(sgr::RESET);
        cursor = e;
    }
    if cursor < raw.len() {
        out.extend_from_slice(&raw[cursor..]);
    }
}

/// Format one file's whole record set -- `begin`, its lines, `end` -- into a
/// `String` ready to write, on the caller's thread.
fn json_msg(hit: FileHit) -> Msg {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    // The per-file state `print_json` tracks across files collapses here: one
    // call is one file, so its `end` is emitted the moment its lines are done.
    let mut open = String::new();
    let mut st = JsonStats::default();
    let mut bin: Option<u64> = None;
    let mut total = JsonStats::default();
    // `print_json` owns the per-file counters -- `searches`,
    // `searches_with_match` and `bytes_searched` with its stat fallback --
    // so that both call sites apply one rule in one place.
    print_json(&mut buf, &hit, &mut open, &mut st, &mut bin, &mut total);
    json_end(&mut buf, &open, bin, &st);
    // The buffer IS the message: converting it to a String was a second
    // copy of every record, and for a dense pattern that is gigabytes across
    // a run -- the whole margin the parallelisation was supposed to buy.
    Msg::Json(buf, st)
}

fn registry() -> Registry {
    // `mut` only when an adapter feature extends the vec — engine-only
    // builds would trip unused_mut without the allow
    #[allow(unused_mut)]
    let mut v: Vec<Box<dyn rgx_core::Adapter>> = Vec::new();
    #[cfg(any(
        feature = "format-zip",
        feature = "format-7z",
        feature = "format-tar",
        feature = "format-cpio",
        feature = "format-ar",
        feature = "format-git-pack",
        feature = "format-git-bundle",
        feature = "format-svn-dump",
        feature = "format-decompress",
        feature = "format-rar",
        feature = "format-pgdump",
        feature = "format-borg",
        feature = "format-iso9660",
        feature = "format-img",
        feature = "format-applefs",
        feature = "format-vhd",
        feature = "format-vhdx",
        feature = "format-qcow2",
        feature = "format-vmdk",
        feature = "format-vdi",
        feature = "format-wim",
        feature = "format-erofs",
        feature = "format-squashfs",
    ))]
    v.extend(rgx_adapters_archive::adapters());
    #[cfg(any(
        feature = "format-office",
        feature = "format-rtf",
        feature = "format-doc",
        feature = "format-ppt",
        feature = "format-xls",
        feature = "format-tex",
        feature = "format-visio",
        feature = "format-markup",
        feature = "format-abiword",
        feature = "format-hwp-raw",
        feature = "format-wordperfect",
    ))]
    v.extend(rgx_adapters_office::adapters());
    #[cfg(any(
        feature = "format-glb",
        feature = "format-stl",
        feature = "format-ply",
        feature = "format-fbx",
        feature = "format-pcd",
        feature = "format-las",
        feature = "format-vtk",
        feature = "format-blend",
        feature = "format-3ds",
        feature = "format-nifti",
        feature = "format-mrc",
    ))]
    v.extend(rgx_adapters_threed::adapters());
    #[cfg(any(
        feature = "format-gguf",
        feature = "format-safetensors",
        feature = "format-npy",
        feature = "format-protobuf",
        feature = "format-tiktoken",
        feature = "format-keras",
        feature = "format-torch",
        feature = "format-pickle",
    ))]
    v.extend(rgx_adapters_llm::adapters());
    #[cfg(any(
        feature = "format-exif",
        feature = "format-tiff",
        feature = "format-gif",
        feature = "format-bmp",
        feature = "format-psd",
        feature = "format-jpeg2000",
        feature = "format-jpegxl",
        feature = "format-openexr",
        feature = "format-avi",
        feature = "format-asf",
        feature = "format-flv",
        feature = "format-mpeg",
        feature = "format-audiotags",
        feature = "format-fits",
        feature = "format-dicom",
        feature = "format-font",
        feature = "format-woff",
        feature = "format-mobi",
        feature = "format-videotags",
    ))]
    v.extend(rgx_adapters_media::adapters());
    #[cfg(any(
        feature = "format-sqlite",
        feature = "format-duckdb",
        feature = "format-foxpro",
        feature = "format-dbf",
        feature = "format-slk",
        feature = "format-dif",
        feature = "format-lotus123",
        feature = "format-mdb",
        feature = "format-lmdb",
        feature = "format-shp",
        feature = "format-parquet",
        feature = "format-eri",
        feature = "format-mat",
        feature = "format-netcdf",
        feature = "format-arrow",
        feature = "format-hdf5",
        feature = "format-bson",
        feature = "format-redis-rdb",
        feature = "format-redis-aof",
        feature = "format-leveldb",
        feature = "format-zarr",
    ))]
    v.extend(rgx_adapters_tabular::adapters());
    // the pdf adapter is the full upstream reader: classic xref + xref streams
    // + ObjStm + CID fonts, in-process — no external fallback
    #[cfg(feature = "format-pdf")]
    v.extend(rgx_adapters_pdf::adapters());
    #[cfg(any(feature = "format-soffice", feature = "format-ocr",))]
    v.extend(rgx_adapters_docs::adapters());
    #[cfg(any(
        feature = "format-mbox",
        feature = "format-eml",
        feature = "format-msg",
        feature = "format-emlx",
        feature = "format-pst",
        feature = "format-wab",
        feature = "format-mmdf",
        feature = "format-msf",
        feature = "format-mailbox-index",
    ))]
    v.extend(rgx_adapters_mail::adapters());
    // forensic triage: registered last — it is the fallback for generic
    // binary extensions (.bin/.dat/…), after torch/zip/etc. had their say
    #[cfg(any(
        feature = "format-pe-resources",
        feature = "format-inspect",
        feature = "format-macho-strings",
        feature = "format-elf-provenance",
        feature = "format-dex-strings",
        feature = "format-wasm",
        feature = "format-wasm-meta",
        feature = "format-lnk",
        feature = "format-x509",
        feature = "format-ole2-compound",
        feature = "format-bplist",
        feature = "format-tiff-pages",
        feature = "format-djvu",
        feature = "format-isobmff",
        feature = "format-dwg",
        feature = "format-parasolid-xt",
        feature = "format-acis-sab",
        feature = "format-rvt",
        feature = "format-dgn",
        feature = "format-dxf",
        feature = "format-step",
        feature = "format-iges",
        feature = "format-acis-sat",
        feature = "format-stl-ascii",
        feature = "format-cgm",
        feature = "format-cals",
        feature = "format-edmics-c4",
        feature = "format-plt",
        feature = "format-grib",
        feature = "format-bufr",
        feature = "format-segy",
        feature = "format-root",
        feature = "format-n5",
        feature = "format-firebird",
        feature = "format-bam",
        feature = "format-bcf",
        feature = "format-cram",
        feature = "format-sam",
        feature = "format-fasta",
        feature = "format-fastq",
        feature = "format-vcf",
        feature = "format-gff",
        feature = "format-pdb",
        feature = "format-mmcif",
    ))]
    v.extend(rgx_adapters_inspect::adapters());
    Registry::with_extra_claims(v, &extra_claims())
}

/// Extra `(adapter, extension)` claims the user asked for, read once.
///
/// `RGX_CLAIM_EXT=inspect:o` puts `.o` back the way it was before the
/// default changed, and `inspect:o,inspect:objbin` adds several. It is an env
/// var rather than a flag because the set is per-invocation policy about what
/// to READ, which is what every other `RGX_*` in this table is, and because a
/// new flag would need a completion entry, a man-page line and an rg-compat
/// argument before it could be called done. `--type-add` cannot do this job:
/// it filters the walk, it does not decide which adapter claims a file.
///
/// A claim naming an adapter that is not compiled in is ignored rather than an
/// error, so the same value works across a `--no-default-features` build.
fn extra_claims() -> Vec<(&'static str, &'static str)> {
    let mut out = Vec::new();
    let Ok(spec) = std::env::var("RGX_CLAIM_EXT") else {
        return out;
    };
    for item in spec.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let Some((adapter, ext)) = item.split_once(':') else {
            continue;
        };
        let (adapter, ext) = (adapter.trim(), ext.trim().trim_start_matches('.'));
        if adapter.is_empty() || ext.is_empty() {
            continue;
        }
        // Leaked so the pair outlives this function; bounded by the number of
        // entries in one environment variable, which is a handful.
        out.push((
            Box::leak(adapter.to_string().into_boxed_str()),
            Box::leak(ext.to_string().into_boxed_str()),
        ));
    }
    out
}

/// The extraction context, hashed: what the adapter pipeline is and how it
/// will run, which is what decides the units a stored rollup signature had
/// to cover.
///
/// FNV-1a over 64 bits, not SHA-256: this value is compared for equality,
/// never preimage-resisted, and it is folded at query start next to a
/// pattern compile. What it folds, in order -- a format tag, the manifest
/// version (a signature-layout change retires every fingerprint with it),
/// the `Ctx` the pipeline recurses under, the archive producers' member
/// budget (`RGX_MAX_MEMBERS`/`RGX_MAX_MEMBER_BYTES` move the units without
/// moving the `Ctx`), the active adapter policy (`RGX_ADAPTER_VIEW` adds or
/// removes renderings from the haystack), and the adapter chain in
/// registration order: each adapter's name, its declared extraction version
/// (or `u64::MAX` for one whose output is not a function of the input bytes
/// -- an external tool, whose binary version this cannot see), whether it
/// is available here at all, and the extensions it claims, extras included.
/// Two runs that fold equal values produce the same units for the same
/// bytes; where they could still differ -- a soffice that changed on PATH
/// between build and query -- the fingerprint's boundary is that tool, and
/// the rollup is trusted only as far as the fold goes.
fn extract_fingerprint(ctx: &rgx_core::Ctx, registry: &rgx_core::Registry) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |b: &[u8]| {
        for &x in b {
            h ^= x as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    eat(b"rgx-extract-fp-1");
    eat(&rgx_core::tv_runtime::MANIFEST_VERSION.to_le_bytes());
    eat(&ctx.max_depth.to_le_bytes());
    eat(&ctx.max_members.to_le_bytes());
    eat(&ctx.max_file_size.to_le_bytes());
    // The filter is part of what the pipeline produced: the units it kept
    // are the ones the signature covers, so a signature that ignored it
    // would let one filter's units answer another filter's question.
    if let Some(f) = &ctx.filter {
        eat(f.text.as_bytes());
        eat(&[0xff]);
    }
    #[cfg(feature = "adapters-archive")]
    {
        let b = rgx_adapters_archive::budget::budget();
        eat(&b.members.to_le_bytes());
        eat(&b.bytes.to_le_bytes());
    }
    #[cfg(not(feature = "adapters-archive"))]
    {
        eat(&0u64.to_le_bytes());
        eat(&0u64.to_le_bytes());
    }
    eat(&[rgx_core::policy() as u8]);
    for a in registry.chain() {
        eat(a.name().as_bytes());
        eat(&[0xff]);
        eat(&crate::cache::version_of(a.name())
            .map(u64::from)
            .unwrap_or(u64::MAX)
            .to_le_bytes());
        eat(&[a.available() as u8]);
        for ext in a.extensions() {
            eat(ext.as_bytes());
            eat(&[0xff]);
        }
    }
    for (adapter, ext) in extra_claims() {
        eat(adapter.as_bytes());
        eat(&[0xfe]);
        eat(ext.as_bytes());
        eat(&[0xff]);
    }
    h
}

/// The extraction hook both build paths sign rollups through: every text
/// and `[rgx: ...]` note `process` hands a search for these bytes when the
/// adapter pipeline answers for the file, and `None` when it leaves the
/// file raw (the query side then searches the file's own bytes, which the
/// base signature already covers). One closure answers both the storage
/// question and the signing question so the two cannot drift apart, and
/// both build paths construct it over the same registry and `Ctx` the
/// fingerprint names.
fn pipeline_units(
    registry: Arc<rgx_core::Registry>,
    ctx: Arc<rgx_core::Ctx>,
) -> Box<rgx_core::tv_runtime::PreExtractor> {
    Box::new(move |rel: &str, data: &[u8]| {
        if !registry.may_claim_for_path(rel) {
            return None;
        }
        let mut found = Vec::new();
        let is_raw = rgx_core::process(&registry, rel, data, 0, &ctx, &mut found);
        if is_raw || found.is_empty() {
            return None;
        }
        Some(found.into_iter().map(|f| (f.path, f.bytes)).collect())
    })
}

/// One dirty owner's extracted units, keyed by the member record names the
/// build wrote for them.
type OwnerUnits = Arc<std::collections::HashMap<String, Arc<Vec<u8>>>>;

/// The units one owner container extracts to now, keyed by the member
/// record names a `--tv-pre-extract` build wrote for them. `member_rel` is
/// the naming rule and is used at both ends, so the keys agree by
/// construction. This is the dirty-file overlay's read side for member
/// records: their bytes live in the pack as of the build, and when the
/// container has moved only its current extraction answers for them.
fn extract_owner_units(
    registry: &Arc<rgx_core::Registry>,
    ctx: &Arc<rgx_core::Ctx>,
    owner: &str,
    root_dir: &std::path::Path,
) -> OwnerUnits {
    let mut map = std::collections::HashMap::new();
    if let Ok(bytes) = std::fs::read(root_dir.join(owner)) {
        let extract = pipeline_units(Arc::clone(registry), Arc::clone(ctx));
        if let Some(members) = extract(owner, &bytes) {
            for (name, b) in members {
                map.insert(rgx_core::tv_runtime::member_rel(owner, &name), Arc::new(b));
            }
        }
    }
    Arc::new(map)
}

/// Everything on a line before the text itself: the path, the line
/// number, and the separators that join them.
///
/// Six shapes, because three things are decided independently: whether
/// the path is printed, whether the number is, and whether this is a
/// match or a context line. That last one is not decoration -- rg turns
/// the path's colon into a dash on a context line (`b.txt-3-after`),
/// and a printer that keeps the colon and drops the context marker
/// produces output no rg user can read.
/// Every match in a file's lines, which is what `-o -c` counts.
///
/// The sink captured the spans at search time, so this is a sum over the
/// per-line `submatches`, not another walk of the matcher over the
/// buffered lines. `print_json` reads the same field for the same
/// reason; both used to be their own `find_iter` pass.
fn count_matches(hit: &FileHit) -> u64 {
    let mut n = 0u64;
    for line in &hit.lines {
        if line.kind != LineKind::Match {
            continue;
        }
        n += line.submatches().len() as u64;
    }
    n
}

/// True when rg's `--` belongs between the last printed line and this one.
///
/// One goes between context groups that are not contiguous, and one
/// between files whenever context is in play. None goes for a gap that no
/// context flag asked about: `-A 1` over lines 1 and 9 is two groups, but
/// the same search without context is just two matches.
fn needs_separator(last: &Option<(String, u64)>, path: &str, line: u64, context: bool) -> bool {
    if !context {
        return false;
    }
    match last {
        None => false,
        Some((p, n)) => p != path || *n + 1 != line,
    }
}

/// Build the per-line prefix (`path:line:`, `path-line-`, `path:`, `path-`,
/// `line:`, `line-`, or empty) without allocating.
///
/// In text mode this runs once per matched line — for a multi-million-line
/// corpus the count of allocations matters. `SmallString<[u8; 24]>` keeps
/// the typical `{path}:{line}:` (e.g. `Cargo.toml:42:`) inline on the stack,
/// spilling to `String` only when the path or line number is genuinely
/// longer than the inline capacity. Replaces the previous `Cow<'_, str>`
/// return, which always held an owned `String`.
///
/// `print_path` lets the caller decide per-line whether to include the
/// path component. It is independent of `multi`: `multi` is about
/// whether the search spans multiple files (it never changes per-line);
/// `print_path` is about whether this specific line carries the path
/// header. `--heading` is implemented by passing `print_path=true` on
/// the first line of a file and `false` on the rest.
// The eight parameters are the eight degrees of freedom of one line
// formatter (which parts of a `{path}:{line}:` prefix this line carries,
// and in which style). Bundling them into a spec struct would move the
// same eight switches one call site outward without removing any.
#[allow(clippy::too_many_arguments)]
fn prefix(
    path: &str,
    multi: bool,
    print_path: bool,
    line: u64,
    lines: bool,
    match_line: bool,
    col: Option<u64>,
    color: bool,
) -> Inline<24> {
    let mut s: Inline<24> = Inline::new();
    // `--column` / `--vimgrep` adds a 1-based byte column from the
    // leftmost submatch of the line. The 24-byte inline is the
    // upper bound for the common short-path case; a longer prefix
    // spills to `String` via the `Inline` field, so no path is
    // truncated, only delayed.
    //
    // The bytes are pushed, not `write!`-formatted: this runs once per
    // matched line, and the `fmt` machinery was 20-30 ns of every one of
    // 6.9 million lines on the dense single-file rows. The eight shapes
    // are exactly the old match's -- `{path}{sep}{line}{sep}[{c}:]` with
    // `sep` a colon on a match line and a dash on a context one -- and
    // every branch is a prefix of that one spelling.
    //
    // With colour on, the path and the line number are styled segments
    // and the separators stay plain -- ripgrep's layout exactly: a
    // segment is `sgr::X` (leading reset included) + text + `sgr::RESET`.
    let include_path = multi && print_path;
    let sep = if match_line { ":" } else { "-" };
    if include_path {
        if color {
            s.push_str(unsafe { core::str::from_utf8_unchecked(sgr::PATH_MAGENTA) });
            s.push_str(path);
            s.push_str(unsafe { core::str::from_utf8_unchecked(sgr::RESET) });
        } else {
            s.push_str(path);
        }
        s.push_str(sep);
    }
    if lines {
        if color {
            s.push_str(unsafe { core::str::from_utf8_unchecked(sgr::LINE_GREEN) });
            push_num(&mut s, line);
            s.push_str(unsafe { core::str::from_utf8_unchecked(sgr::RESET) });
        } else {
            push_num(&mut s, line);
        }
        if match_line {
            if let Some(c) = col {
                s.push_str(":");
                if color {
                    // ripgrep styles the column as a reset-wrapped
                    // segment: `ESC[0m` digits `ESC[0m`, a segment with no
                    // attributes of its own. Byte parity, not taste.
                    s.push_str(unsafe { core::str::from_utf8_unchecked(sgr::RESET) });
                    push_num(&mut s, c);
                    s.push_str(unsafe { core::str::from_utf8_unchecked(sgr::RESET) });
                } else {
                    push_num(&mut s, c);
                }
            }
            s.push_str(":");
        } else {
            s.push_str("-");
        }
    }
    s
}

/// Decimal digits of `n` into an [`Inline`], without the `fmt` machinery.
#[inline]
fn push_num(s: &mut Inline<24>, mut n: u64) {
    let mut tmp = [0u8; 20];
    let mut i = 20;
    loop {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    // ASCII digits are always valid UTF-8.
    s.push_str(unsafe { core::str::from_utf8_unchecked(&tmp[i..]) });
}

/// Escape a string for a JSON string literal, the way `rg --json` does.
///
/// `\\` and `"` are the obvious two. The other half is the part that was
/// missing: a JSON string may not contain a raw control character below
/// `0x20`, and a searched line routinely has one. A tab in a source file, and
/// a CR in every CRLF file on Windows, were both being written through
/// verbatim, so `rgx --json` emitted a byte stream no JSON parser accepts --
/// the line simply ends mid-token at the CR. Escapes match `serde_json`'s,
/// which is what `rg --json` is serialised by: the five short forms where
/// they exist and `\u00XX` for the rest, and nothing else. Non-ASCII passes
/// through as UTF-8, also as `rg` does it.
fn json_esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    json_esc_into(&mut out, s);
    out
}

/// The appending form of [`json_esc`], so a caller with one value per printed
/// line reuses a single buffer instead of allocating a `String` per value.
///
/// `--json` writes one record per MATCHED LINE, and each record used to
/// allocate for the path, the adapter tag, the line text, its terminator and
/// every submatch text -- about six `String`s per line. On a dense pattern
/// that allocation count, not the escaping, was the cost.
fn json_esc_into(out: &mut String, s: &str) {
    // A byte loop, not `char_indices`: only ASCII bytes are ever escaped and
    // every UTF-8 continuation byte is >= 0x80, so runs sliced at the bytes
    // this loop notices are always char boundaries and a multi-byte
    // character is copied through whole. It also skips the per-char UTF-8
    // decode, which on a dense `--json` run is one pass per matched line.
    let b = s.as_bytes();
    let mut run = 0;
    let mut i = 0;
    while i < b.len() {
        let esc: &str = match b[i] {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            0x08 => "\\b",
            0x0c => "\\f",
            b'\n' => "\\n",
            b'\r' => "\\r",
            b'\t' => "\\t",
            c if c < 0x20 => {
                out.push_str(&s[run..i]);
                // Six bytes is the upper bound for `\uXXXX`; formatting a
                // single char through `format!` allocates one String per
                // control char, which a CRLF-heavy file pays once per line.
                use std::fmt::Write as _;
                let mut buf = Inline::<6>::new();
                let _ = write!(buf, "\\u{:04x}", c);
                out.push_str(buf.as_str());
                i += 1;
                run = i;
                continue;
            }
            _ => {
                i += 1;
                continue;
            }
        };
        out.push_str(&s[run..i]);
        out.push_str(esc);
        i += 1;
        run = i;
    }
    out.push_str(&s[run..]);
}

/// Append `n` in decimal without going through `fmt`.
///
/// Four integers are formatted per match record -- the line number, the
/// absolute offset, and the submatch span pair -- and `Display`'s
/// `write_str` per integer is a measurable share of what is left of a
/// record once its allocations are gone.
fn push_u64(out: &mut String, mut n: u64) {
    if n == 0 {
        out.push('0');
        return;
    }
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    for &c in &buf[i..] {
        out.push(c as char);
    }
}

/// Classify a query into the three shapes the prefilter programme cares about.
///
/// The classification is deliberately the same one `literal::extract` uses to
/// decide whether it can build a mask at all, so the two cannot disagree: a
/// pattern with a metacharacter is `no-literal` here for exactly the reason it
/// yields `LiteralKind::None` there.
///
/// The point of reporting it is that it is the one input the whole prefilter
/// programme was missing. A single plain literal is already matched at the
/// memory-system limit by `memmem` -- 29.4 GB/s against 32.0 GB/s for the
/// best engine in existence -- so prefilling it cannot win. What prefilling can
/// win is a *caseless* pattern, because a matcher without case folding in the
/// mask has to expand `(?i)` into `2^k` literals and then cannot pack them.
/// That is the whole 2.6-2.8x in `docs/research/BEYOND-SOTA.md`, and whether it is worth
/// building is a question about query mix, not about code.
///
/// Cheap by construction: one pass over the pattern's bytes, only on the
/// `RGX_PROFILE` path.
fn describe_query_shape(args: &Args) -> String {
    let pattern = args.pattern.clone().unwrap_or_default();
    let bytes = pattern.as_bytes();
    // `fixed_strings` (`-F`) is the user saying "this is a literal", so a
    // metacharacter in the text is not one. Word-boundary wrapping (`-w`)
    // adds `\b`, which is why a wrapped pattern is not counted as a literal
    // here even though its body is.
    let metachar = !args.fixed_strings
        && bytes.iter().any(|&b| {
            matches!(
                b,
                b'\\'
                    | b'.'
                    | b'^'
                    | b'$'
                    | b'*'
                    | b'+'
                    | b'?'
                    | b'|'
                    | b'('
                    | b')'
                    | b'['
                    | b']'
                    | b'{'
                    | b'}'
            )
        });
    let word = args.word_regexp;

    let shape = if metachar {
        "regex-with-metachar"
    } else if bytes.len() < 2 {
        "too-short"
    } else {
        "literal"
    };
    let mut s = format!("{shape} ({} bytes", bytes.len());
    if args.ignore_case {
        s.push_str(", -i");
    }
    if args.fixed_strings {
        s.push_str(", -F");
    }
    if word {
        s.push_str(", -w");
    }
    // The actionable summary: a prefilter can only help the caseless shapes,
    // and a `-w` pattern is out of reach for the current extractor.
    let prefilterable = shape == "literal" && (args.ignore_case || !word);
    s.push_str(if prefilterable {
        ", prefilterable"
    } else {
        ", not prefilterable"
    });
    s
}

/// The counters `rg --json` carries in `end` and in `summary`.
///
/// `bytes_searched` is the file's size rather than the number of bytes the
/// searcher happened to look at: rgx reads the whole file unless it is
/// mapped, and the distinction is not observable from here, so the honest
/// number is the one a reader can check with `ls`. The cost is one
/// `metadata` per file, in a mode that already writes a line per match.
#[derive(Default, Clone, Copy)]
struct JsonStats {
    searches: u64,
    searches_with_match: u64,
    bytes_searched: u64,
    bytes_printed: u64,
    matched_lines: u64,
    matches: u64,
}

impl JsonStats {
    fn render(&self, indent: &str) -> String {
        format!(
            "{indent}\"stats\":{{\"bytes_printed\":{},\"bytes_searched\":{},\"matched_lines\":{},\"matches\":{},\"searches\":{},\"searches_with_match\":{}}}",
            self.bytes_printed, self.bytes_searched, self.matched_lines,
            self.matches, self.searches, self.searches_with_match,
        )
    }

    fn merge(&mut self, o: &JsonStats) {
        self.searches += o.searches;
        self.searches_with_match += o.searches_with_match;
        self.bytes_searched += o.bytes_searched;
        self.bytes_printed += o.bytes_printed;
        self.matched_lines += o.matched_lines;
        self.matches += o.matches;
    }
}

/// `{"type":"end", ...}` with rg's `binary_offset` and `stats`.
fn json_end(
    out: &mut (impl std::io::Write + ?Sized),
    path: &str,
    binary_offset: Option<u64>,
    st: &JsonStats,
) {
    let bo = match binary_offset {
        Some(o) => o.to_string(),
        None => "null".to_string(),
    };
    writeln!(
        out,
        "{{\"type\":\"end\",\"data\":{{\"path\":{{\"text\":\"{p}\"}},\"binary_offset\":{bo},{st}}}}}",
        p = json_esc(path),
        bo = bo,
        st = st.render("  "),
    )
    .ok();
}

/// `{"type":"summary", ...}`, once, after the last file.
fn json_summary(
    out: &mut (impl std::io::Write + ?Sized),
    st: &JsonStats,
    started: std::time::Instant,
) {
    let el = started.elapsed();
    let nanos = el.as_nanos();
    let secs = el.as_secs();
    // rg prints "0.000886s" -- seconds to six places, with the sub-second
    // remainder, not a `Duration` Display, which is not implemented.
    let human = format!("{:0.6}s", nanos as f64 / 1e9);
    writeln!(
        out,
        "{{\"type\":\"summary\",\"data\":{{\"elapsed_total\":{{\"human\":{h:?},\"nanos\":{n},\"secs\":{s}}},{st}}}}}",
        h = human, n = nanos, s = secs, st = st.render("  "),
    )
    .ok();
}

fn print_json(
    out: &mut (impl std::io::Write + ?Sized),
    hit: &FileHit,
    open_path: &mut String,
    last_stats: &mut JsonStats,
    last_bin_offset: &mut Option<u64>,
    total: &mut JsonStats,
) {
    // NOT gated on `multi`. A single named file is the case a human or an
    // agent runs most often, and it used to get no `begin` and no `end` at
    // all, which is not "a subset of rg's format", it is a different format.
    if *open_path != hit.path {
        if !open_path.is_empty() {
            json_end(out, open_path, last_bin_offset.take(), last_stats);
            total.merge(last_stats);
            *last_stats = JsonStats::default();
        }
        writeln!(
            out,
            "{{\"type\":\"begin\",\"data\":{{\"path\":{{\"text\":\"{}\"}}}}}}",
            json_esc(&hit.path)
        )
        .ok();
        *open_path = hit.path.clone();
        *last_bin_offset = hit.binary_offset;
    }
    // Per-file counters `end` and `summary` report. They are applied HERE,
    // after the path-change block above: applied before it, one file's
    // numbers land in the previous file's `end` record, which `json_end`
    // renders on the next path change -- and the last file's `end` renders
    // an empty `stats`. Both call sites (`json_msg` and the printer's
    // `Msg::Hit` arm) reach this point, so the rule lives in one place.
    last_stats.searches += 1;
    last_stats.searches_with_match += 1;
    // The size the producer already had, falling back to a stat only where
    // nobody knew one -- which is exactly the set of cases where the stat was
    // the only source before, including a pack member's virtual path where it
    // fails and answers 0, unchanged.
    last_stats.bytes_searched += hit
        .bytes_searched
        .unwrap_or_else(|| std::fs::metadata(&hit.path).map(|m| m.len()).unwrap_or(0));
    if hit.binary {
        return; // rg --json emits nothing for binary files
    }
    // Loop-invariant escapes: the path and the adapter tag are identical on
    // every record of this file, so they are escaped once per FILE here, not
    // once per printed line below. A dense pattern writes one record per
    // matched line, and re-escaping them per line paid two allocations and
    // two scans per line for bytes that never changed.
    let path_esc = json_esc(&hit.path);
    let via_esc = json_esc(hit.via);
    // Two scratches reused across lines: the escaped line text (with its
    // terminator appended) and the `submatches` array body. Clearing them is
    // a length reset, against a `String::new()` + `format!` pair per line.
    let mut t_scratch = String::new();
    let mut subs = String::new();
    for line in &hit.lines {
        let line_bytes = line.as_bytes(&hit.bytes);
        let text = core::str::from_utf8(line_bytes)
            .map(Cow::Borrowed)
            .unwrap_or_else(|_| Cow::Owned(String::from_utf8_lossy(line_bytes).into_owned()));
        let type_ = match line.kind {
            LineKind::Match => "match",
            LineKind::Before | LineKind::After => "context",
        };
        // The matcher walked every line at search time and the sink stashed
        // the spans here -- so this loop is the one that reads them back,
        // not the one that runs the matcher again. That is the structural
        // win: `count_matches` and `print_json` used to do their own
        // `find_iter` over the buffered lines (two passes for the
        // `-o -c --json` combination), and now they do zero.
        subs.clear();
        let mut n_matches = 0u64;
        if line.kind == LineKind::Match {
            let spans = line.submatches();
            n_matches = spans.len() as u64;
            for (i, sm) in spans.iter().enumerate() {
                if i > 0 {
                    subs.push(',');
                }
                let mtext = core::str::from_utf8(&line_bytes[sm.start as usize..sm.end as usize])
                    .map(Cow::Borrowed)
                    .unwrap_or_else(|_| {
                        Cow::Owned(
                            String::from_utf8_lossy(
                                &line_bytes[sm.start as usize..sm.end as usize],
                            )
                            .into_owned(),
                        )
                    });
                // Escaped straight into the reused `subs` scratch. The
                // `format!` this replaces built a fresh `String` per submatch
                // and then copied it in here.
                subs.push_str("{\"match\":{\"text\":\"");
                json_esc_into(&mut subs, &mtext);
                subs.push_str("\"},\"start\":");
                push_u64(&mut subs, u64::from(sm.start));
                subs.push_str(",\"end\":");
                push_u64(&mut subs, u64::from(sm.end));
                subs.push('}');
            }
        }
        // rg reports the line as it sits in the file, terminator included and
        // escaped. `line_bytes` has the `\n` stripped (every printer here adds
        // its own), so it goes back on only when the line really had one: a
        // last line with no terminator, and a file whose lines end in a bare
        // `\r`, are reported by rg without one and must not grow one here.
        t_scratch.clear();
        json_esc_into(&mut t_scratch, &text);
        if line.terminated {
            t_scratch.push_str("\\n");
        }
        let t = t_scratch.as_str();
        // `adapter` sits beside `type`, not inside `data`. A consumer that
        // reads rg's documented shape now sees exactly rg's fields, and one
        // that wants to know which adapter produced a match reads a sibling.
        // Inside `data` it was a field rg does not have, on every record.
        writeln!(out,
            "{{\"type\":\"{type_}\",\"adapter\":\"{via}\",\"data\":{{\"path\":{{\"text\":\"{p}\"}},\"lines\":{{\"text\":\"{t}\"}},\"line_number\":{ln},\"absolute_offset\":{ao},\"submatches\":[{subs}]}}}}",
            p = path_esc, t = t, ln = line.line_number,
            ao = line.offset,
            via = via_esc).ok();

        // Counters rg reports per file and in `summary`.
        last_stats.bytes_printed += t.len() as u64 + 1;
        if line.kind == LineKind::Match {
            last_stats.matched_lines += 1;
            last_stats.matches += n_matches;
        }
    }
}

/// `--files` and `--tv-build` positional fixup: in those modes every positional is a path,
/// e.g. "rgx --files src" or "rgx --tv-build src" would otherwise bind "src" to the
/// optional pattern slot.
fn fixup_args(args: &mut Args) {
    if args.list_files || args.tv_build {
        if let Some(p) = args.pattern.take() {
            args.paths.insert(0, p);
        }
    }
}

/// The type table the user's flags describe: the defaults, then
/// `--type-clear`, then every `--type-add`.
///
/// One builder for the table the filter filters by AND the table a `-t`
/// name is checked against, so the two cannot be two different tables.
///
/// `--type-add` uses ripgrep-compatible `name:ext,ext` syntax (whitespace and
/// commas both delimit extensions; the leading name is required). A specifier
/// without a `:` is reported to stderr and dropped, the same way ripgrep handles
/// it — one bad entry should not fail the whole query.
fn type_table(args: &Args) -> type_db::TypeDb {
    let mut db = type_db::TypeDb::with_defaults();
    if args.type_clear {
        db.clear();
    }
    for spec in &args.type_add {
        let (name, exts) = match spec.split_once(':') {
            Some(pair) => pair,
            None => {
                eprintln!(
                    "rgx: warning: --type-add '{spec}' missing ':name:ext,ext' separator; ignoring"
                );
                continue;
            }
        };
        let name = name.trim();
        if name.is_empty() {
            eprintln!("rgx: warning: --type-add '{spec}' has empty type name; ignoring");
            continue;
        }
        let exts: Vec<&str> = exts
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|e| !e.is_empty())
            .collect();
        if exts.is_empty() {
            eprintln!("rgx: warning: --type-add '{spec}' has no extensions; ignoring");
            continue;
        }
        db.add(name, &exts);
    }
    db
}

/// Build the `TypeFilter` from the user's `-t`/`-T`/`--type-add`/`--type-clear`
/// flags. Returns `None` when no type filter was requested, so the walker
/// skips the per-entry check entirely.
fn build_type_filter(args: &Args) -> Option<walk::TypeFilter> {
    if args.types.is_empty() && args.type_add.is_empty() && !args.type_clear && !args.type_list {
        return None;
    }
    let db = type_table(args);
    if args.types.is_empty() && !args.type_list {
        // The user asked for --type-list (or only extended the table);
        // the walker is not told to filter on anything.
        return None;
    }
    Some(walk::TypeFilter::new(db, args.types.clone()))
}

/// The first `-t`/`-T` name the type table does not have.
///
/// rg refuses an unknown type (`rg: unrecognized file type: X`, exit 2), and
/// so must rgx: a filter that matches nothing is indistinguishable from a
/// search that found nothing, and the second is the wrong answer to give. The
/// user asked for `rust` and got silence, which reads as "there is no Rust
/// here" instead of "there is no type called `rust`".
///
/// The table is the one the flags describe — the defaults, then
/// `--type-clear`, then `--type-add` — so a type the user added on the same
/// command line is a type this accepts, and a type `--type-clear` wiped is a
/// type this refuses.
fn unknown_type_name(args: &Args) -> Option<String> {
    if args.types.is_empty() {
        return None;
    }
    let db = type_table(args);
    args.types
        .iter()
        .find(|sel| !db.has_type(&sel.name))
        .map(|sel| sel.name.clone())
}

/// The message both doors report an unknown type through: the terminal and
/// the `--serve` frame.
fn unknown_type_error(name: &str) -> String {
    format!("unrecognized file type: {name}")
}

#[allow(clippy::too_many_arguments)]
fn print_messages(
    rx: mpsc::Receiver<Option<Msg>>,
    out: &mut dyn std::io::Write,
    args: &Args,
    replace_re: Option<&rgx_core::regex::ByteRegex>,
    multi: bool,
    lines: bool,
    context: bool,
    heading: bool,
    quiet: bool,
) -> bool {
    let mut any = false;
    let mut open_path = String::new();
    let mut last_printed: Option<(String, u64)> = None;
    // Whether any per-file text block has been written, so the next one can
    // be preceded by the `--` a new context group needs. Only meaningful
    // under `-A`/`-B`/`-C`.
    let mut text_seen = false;
    // JSON-only state, all four declared unconditionally because the printer
    // is chosen per message and threading a branch through it costs more than
    // the initialisation.
    let started = std::time::Instant::now();
    let mut last_stats = JsonStats::default();
    let mut last_bin_offset: Option<u64> = None;
    let mut total_stats = JsonStats::default();
    // `--sort path` is the walker's job, not this one's: the builder
    // sets `ordered` and the walk emits in path order (backwards under
    // `--sortr`), so the printer streams and holds one message at a
    // time. Buffering here until the walk ended -- what this used to do
    // -- cost one formatted block per matched file, which is unbounded
    // on a pattern that matches a whole tree. `--files` never reaches
    // this loop's ordering question (`SortedSink` sorts that route) and
    // `quiet` breaks out after the first message.
    for msg in rx.iter().flatten() {
        if !args.files_without_match
            || matches!(msg, Msg::Listed(_) | Msg::ListedBatch(_) | Msg::Json(..))
        {
            any = true;
        }
        if quiet {
            break;
        }
        let hit = match msg {
            Msg::Listed(path) => {
                // `-0` / `--null` flips the file-list separator for
                // this path too; the default keeps the newline so
                // shell pipelines keep working.
                let sep = if args.null_data { "\0" } else { "\n" };
                write!(out, "{path}{sep}").ok();
                continue;
            }
            Msg::ListedBatch(bytes) => {
                out.write_all(&bytes).ok();
                continue;
            }
            Msg::Chunks(ch) => {
                if args.files_without_match {
                    continue;
                }
                if args.files_with_matches {
                    writeln!(out, "{}", ch.path).ok();
                    continue;
                }
                if args.count {
                    writeln!(
                        out,
                        "{}{}",
                        prefix(&ch.path, multi, true, 0, false, true, None, false),
                        ch.count
                    )
                    .ok();
                    continue;
                }
                if !(ch.binary && !args.text) {
                    for chunk in &ch.chunks {
                        let via = if ch.via == "raw" {
                            String::new()
                        } else {
                            format!(" (via {})", ch.via)
                        };
                        writeln!(out, "=== {}:{}{} ===", ch.path, chunk.line_number, via).ok();
                        let _ = out.write_all(&chunk.bytes);
                        writeln!(out, "\n").ok();
                    }
                }
                continue;
            }
            Msg::Json(text, st) => {
                out.write_all(&text).ok();
                total_stats.merge(&st);
                continue;
            }
            Msg::Text(text) => {
                // `--files-without-match` prints the misses only; a hit,
                // however it reached this thread, is a file the mode must
                // not print. The `Msg::Hit` and `Msg::Chunks` arms carry
                // the same guard, and a pack query's worker renders its
                // text here rather than sending a `Msg::Hit`, so a filter
                // on only one arm left that path printing both lists.
                if args.files_without_match {
                    continue;
                }
                // A new file is always a new context group, so under
                // `-A`/`-B`/`-C` it is preceded by `--` unless it is the
                // first. `text_msg_into` cannot do this: it formats one
                // file and cannot know whether anything came before. The
                // batcher is disabled when `context` is on for the same
                // reason -- a batch concatenates files and the separator
                // would have to live inside it.
                if context && text_seen {
                    out.write_all(b"--\n").ok();
                }
                out.write_all(&text).ok();
                text_seen = true;
                continue;
            }
            Msg::TextBatch(text) => {
                // The TextBatcher concatenates formatted text from several
                // files into one buffer so the worker sends one MPSC
                // message per ~8 KiB instead of one per file. The printer
                // just writes the buffer verbatim -- the worker has already
                // produced the exact byte sequence the user sees.
                out.write_all(&text).ok();
                continue;
            }
            Msg::Hit(hit) => {
                // With text-mode formatting in the per-file worker, the
                // walker and the pack-store
                // searcher both send pre-formatted bytes through
                // `Msg::Text`; the `Msg::Hit` arm is left in place because
                // two paths still produce a `FileHit` for the printer to
                // render itself: the stdin search (see `use_stdin` in
                // `run_query` -- the stdin branch of the chunked vs.
                // non-chunked path sends `Msg::Hit` when `--chunk` is not
                // in play) and the empty-file list (the walker hands
                // every empty file to a one-shot `Searcher::search_slice`
                // because nothing else would match it). The two are the
                // only `Msg::Hit` senders left; remove this arm and one
                // of them stops printing.
                if args.files_without_match {
                    continue;
                }
                hit
            }
        };
        if args.files_with_matches {
            // `-0` / `--null` swaps the trailing newline for a NUL; the
            // default stays a newline so any existing script that
            // consumes the output keeps working.
            let sep = if args.null_data { "\0" } else { "\n" };
            write!(out, "{}{}", hit.path, sep).ok();
        } else if args.count {
            let n = if args.only_matching {
                count_matches(&hit)
            } else {
                hit.count
            };
            writeln!(
                out,
                "{}{}",
                prefix(&hit.path, multi, true, 0, false, true, None, false),
                n
            )
            .ok();
        } else if args.json {
            // The per-file counters are `print_json`'s job now. Adding them
            // here ran BEFORE its path-change reset, so this file's numbers
            // were rendered in the previous file's `end` record.
            print_json(
                &mut *out,
                &hit,
                &mut open_path,
                &mut last_stats,
                &mut last_bin_offset,
                &mut total_stats,
            );
        } else if hit.binary && !args.text {
            // Binary matches count for the exit code and for `-l`, but rg does
            // not print the lines -- it prints one line saying the file is
            // binary and where the NUL was. Printing nothing at all is not the
            // same answer: `rgx PATTERN some.dat` and `rgx PATTERN some.txt`
            // were both silent, and only one of them had nothing to say.
            //
            // `write_binary_message` in ripgrep's
            // `printer/src/standard.rs`, and the wording is its. The `quit`
            // arm is a different sentence, and rgx does not take that arm for
            // a file the user named.
            if let Some(offset) = hit.binary_offset {
                // rg writes the path, then `": "`, then the sentence -- with
                // a space, which the line prefix does not carry because a
                // line prefix is followed by the line, not by prose.
                let p = prefix(&hit.path, multi, true, 0, false, true, None, false);
                let gap = if p.is_empty() { "" } else { " " };
                writeln!(
                    out,
                    "{p}{gap}binary file matches (found \"\\0\" byte around offset {offset})"
                )
                .ok();
            }
        } else if args.only_matching {
            let mut path_printed = false;
            for line in &hit.lines {
                let is_match = line.kind == LineKind::Match;
                if needs_separator(&last_printed, &hit.path, line.line_number, context) {
                    writeln!(out, "--").ok();
                }
                last_printed = Some((hit.path.clone(), line.line_number));
                let print_path = !heading || !path_printed;
                path_printed = true;
                let p = prefix(
                    &hit.path,
                    multi,
                    print_path,
                    line.line_number,
                    lines,
                    is_match,
                    // `--column` / `--vimgrep` prints the 1-based byte
                    // column of the leftmost submatch. Context lines
                    // and inverted matches have no submatches and the
                    // column is left out, matching rg's behaviour.
                    if is_match && !args.invert_match && args.column {
                        line.submatches().first().map(|sm| sm.start as u64 + 1)
                    } else {
                        None
                    },
                    false,
                );
                let line_bytes = line.as_bytes(&hit.bytes);
                if !is_match || args.invert_match {
                    writeln!(
                        out,
                        "{}{}",
                        p,
                        core::str::from_utf8(line_bytes)
                            .map(Cow::Borrowed)
                            .unwrap_or_else(|_| {
                                Cow::Owned(String::from_utf8_lossy(line_bytes).into_owned())
                            })
                    )
                    .ok();
                    continue;
                }
                if let (Some(re), Some(repl)) = (replace_re, &args.replace) {
                    let mut w = Vec::new();
                    for m in re.captures_iter(line_bytes) {
                        re.expand(&m, repl.as_bytes(), line_bytes, &mut w);
                        writeln!(
                            out,
                            "{}{}",
                            p,
                            core::str::from_utf8(&w)
                                .map(Cow::Borrowed)
                                .unwrap_or_else(|_| {
                                    Cow::Owned(String::from_utf8_lossy(&w).into_owned())
                                })
                        )
                        .ok();
                        w.clear();
                    }
                } else {
                    for sm in line.submatches().iter() {
                        writeln!(
                            out,
                            "{}{}",
                            p,
                            core::str::from_utf8(&line_bytes[sm.start as usize..sm.end as usize],)
                                .map(Cow::Borrowed)
                                .unwrap_or_else(|_| {
                                    Cow::Owned(
                                        String::from_utf8_lossy(
                                            &line_bytes[sm.start as usize..sm.end as usize],
                                        )
                                        .into_owned(),
                                    )
                                })
                        )
                        .ok();
                    }
                }
            }
        } else if let (Some(re), Some(repl)) = (replace_re, &args.replace) {
            let mut path_printed = false;
            for line in &hit.lines {
                let is_match = line.kind == LineKind::Match;
                let print_path = !heading || !path_printed;
                path_printed = true;
                let p = prefix(
                    &hit.path,
                    multi,
                    print_path,
                    line.line_number,
                    lines,
                    is_match,
                    if is_match && args.column {
                        line.submatches().first().map(|sm| sm.start as u64 + 1)
                    } else {
                        None
                    },
                    false,
                );
                let line_bytes = line.as_bytes(&hit.bytes);
                if !is_match {
                    writeln!(
                        out,
                        "{}{}",
                        p,
                        core::str::from_utf8(line_bytes)
                            .map(Cow::Borrowed)
                            .unwrap_or_else(|_| {
                                Cow::Owned(String::from_utf8_lossy(line_bytes).into_owned())
                            })
                    )
                    .ok();
                    continue;
                }
                let replaced = re.replace(line_bytes, repl.as_bytes(), 0);
                writeln!(
                    out,
                    "{}{}",
                    p,
                    core::str::from_utf8(&replaced)
                        .map(Cow::Borrowed)
                        .unwrap_or_else(|_| {
                            Cow::Owned(String::from_utf8_lossy(&replaced).into_owned())
                        })
                )
                .ok();
            }
        } else {
            let mut path_printed = false;
            for line in &hit.lines {
                if needs_separator(&last_printed, &hit.path, line.line_number, context) {
                    writeln!(out, "--").ok();
                }
                let is_match = line.kind == LineKind::Match;
                let print_path = !heading || !path_printed;
                path_printed = true;
                let p = prefix(
                    &hit.path,
                    multi,
                    print_path,
                    line.line_number,
                    lines,
                    is_match,
                    if is_match && args.column {
                        line.submatches().first().map(|sm| sm.start as u64 + 1)
                    } else {
                        None
                    },
                    false,
                );
                writeln!(
                    out,
                    "{}{}",
                    p,
                    core::str::from_utf8(line.as_bytes(&hit.bytes))
                        .map(Cow::Borrowed)
                        .unwrap_or_else(|_| {
                            Cow::Owned(
                                String::from_utf8_lossy(line.as_bytes(&hit.bytes)).into_owned(),
                            )
                        })
                )
                .ok();
                last_printed = Some((hit.path.clone(), line.line_number));
            }
        }
    }
    if args.json && !open_path.is_empty() {
        json_end(&mut *out, &open_path, last_bin_offset, &last_stats);
        total_stats.merge(&last_stats);
    }
    if args.json {
        json_summary(&mut *out, &total_stats, started);
    }
    any
}

/// Executes a search query over a pack store.
fn run_tv_query(
    args: &Args,
    store_dir: &Path,
    out: &mut (dyn std::io::Write + Send),
) -> Result<bool> {
    let t_stage = std::time::Instant::now();
    let manifest = rgx_core::tv_runtime::format::load_manifest(store_dir).map_err(|e| {
        rgx_core::anyhow!(
            "failed to load pack store at '{}': {}",
            store_dir.display(),
            e
        )
    })?;

    // The store answers the corpus as of its build. When the filesystem has
    // moved since, the changed files are re-read off disk and answered from
    // the bytes there -- the dirty-file overlay -- so drift costs reads and
    // never correctness. Say so aloud anyway: `--tv` is the user's trade to
    // make, and a trade is honoured and warned, never silent. A file added
    // since the build is the boundary neither this nor the detector's
    // freshness gate sees without the walk the store exists to avoid.
    let (fresh_checked, fresh_stale) = if args.tv_assume_fresh {
        // The caller's word, and nothing is guessed behind it: no walk means
        // no dirty overlay, which is exactly what "assumed fresh" asserts.
        // What it buys is the walk itself -- 20,000 `stat` calls and about
        // 40 ms of every query on a store this size
        // (`benchmark/ladder-findings.md` 25).
        (manifest.files.len(), Vec::new())
    } else {
        rgx_core::tv_runtime::stale_list_in(&manifest)
    };
    if !fresh_stale.is_empty() {
        eprintln!(
            "rgx: warning: {} of {} files changed since this store was built; those are answered from the disk as it is now, the rest from the store. `--tv-build` refreshes it.",
            fresh_stale.len(),
            fresh_checked
        );
    }
    let dirty_idx: std::collections::HashSet<usize> = fresh_stale.into_iter().collect();
    // The overlay's bytes, read once on this thread and shared read-only
    // with the workers. Keyed by the record's own rel_path, which is the
    // one name both sides carry.
    let mut dirty_files: std::collections::HashMap<String, Arc<Vec<u8>>> =
        std::collections::HashMap::new();
    let root_dir = std::path::PathBuf::from(&manifest.root_path);
    // Every live record name, for the member-record rule below: a member
    // whose owner carries a record of its own defers to that record's
    // overlay pass, which re-extracts and searches the same units -- one
    // text must never be answered twice.
    let live_names: std::collections::HashSet<String> = manifest
        .files
        .iter()
        .filter(|f| !f.is_deleted)
        .map(|f| f.rel_path.clone())
        .collect();
    // One lazy extraction per dirty owner, shared by its member records.
    let mut owner_units: std::collections::HashMap<String, OwnerUnits> =
        std::collections::HashMap::new();

    // Glob filter
    let mut overrides = Override::empty();
    if !args.glob.is_empty() {
        let mut ob = OverrideBuilder::new(".");
        for g in &args.glob {
            ob.add(g).context("invalid glob")?;
        }
        overrides = ob.build()?;
    }

    // Determine path display prefix based on manifest root and current working directory
    // The prefix the user typed, because that is what the direct path
    // prints and what rg prints: name a directory and every hit carries that
    // name; name `.` and the hits are relative. The old rule derived the
    // base from the cwd instead, so a store living outside it printed bare
    // relative paths while the same query without the store printed absolute
    // ones -- two answers to one question, differing only in prefix.
    let display_base = args
        .paths
        .first()
        .map(|p| slash_path(p))
        .filter(|p| !p.is_empty() && p != ".");

    let t_manifest_ms = t_stage.elapsed().as_secs_f64() * 1000.0;
    let t_stage = std::time::Instant::now();
    let mut kept: Vec<_> = Vec::new();

    // The adapter pipeline a pack query used to be unable to run. The store
    // holds the corpus verbatim, so the slice a worker searches *is* the file
    // the direct path would have read -- which means `process` can run on it
    // and produce the same units from the same bytes, and a pack answer and
    // a direct answer agree by construction rather than by coordination.
    // The extension check is a string comparison against an in-memory index
    // and is paid per file; the pipeline itself only runs on a claim.
    let registry = Arc::new(registry());
    // The extraction context: what the adapter pipeline runs under, and
    // one input of the fingerprint the rollups were signed under. Built
    // before the kept loop because the dirty-file overlay extracts a
    // changed container's units through the same pipeline the workers use.
    let ctx = Arc::new(rgx_core::Ctx {
        max_depth: args.max_adapter_depth,
        max_members: MAX_ARCHIVE_MEMBERS,
        max_file_size: parse_size(&args.max_filesize)? as usize,
        filter: filter_of(args)?,
        facts_sink: None,
    });
    // The query's declared `-E` encoding, asked once. It decides two things
    // below: whether the binary bit the manifest carries describes the bytes
    // the query will search (it does not, under a decode), and whether the
    // n-gram filter may run at all.
    let forced = forced_bom_of(args);

    for (idx, mut f) in manifest.files.into_iter().enumerate() {
        if f.is_deleted {
            continue;
        }
        // The dirty-file overlay's read side: a record the filesystem
        // disagrees with is re-read here and searched from these bytes
        // instead of its pack slice, so the answer covers the corpus as it
        // is now. A file gone from disk contributes nothing, exactly as the
        // direct walk would never have seen it. `is_empty` and `is_binary`
        // are re-derived over the current bytes with the same rules the
        // build applies (`encoding::is_binary`), so a changed file is
        // classified exactly as a rebuild would classify it -- the record's
        // build-time verdicts describe bytes that no longer exist.
        if dirty_idx.contains(&idx) {
            match std::fs::read(root_dir.join(&f.rel_path)) {
                Ok(bytes) => {
                    f.is_empty = bytes.is_empty();
                    f.is_binary = rgx_core::encoding::is_binary(&bytes);
                    dirty_files.insert(f.rel_path.clone(), Arc::new(bytes));
                }
                Err(_) => {
                    // A member record's name is no path on disk: it hangs
                    // off its owner container, and its answer is the unit
                    // the owner's CURRENT bytes extract to. The owner is
                    // extracted once per query and every dirty member of
                    // it finds its bytes here; a unit the fresh extraction
                    // no longer produces contributes nothing, exactly as a
                    // rebuild would drop the record. The downstream search
                    // is the one the pack slice would have gone through --
                    // only the bytes' origin differs.
                    let Some(owner) = rgx_core::tv_runtime::owner_rel(&root_dir, &f.rel_path)
                    else {
                        continue;
                    };
                    if live_names.contains(&owner) {
                        continue;
                    }
                    let units = match owner_units.get(&owner) {
                        Some(u) => Arc::clone(u),
                        None => {
                            let u = extract_owner_units(&registry, &ctx, &owner, &root_dir);
                            owner_units.insert(owner, Arc::clone(&u));
                            u
                        }
                    };
                    match units.get(&f.rel_path) {
                        Some(bytes) => {
                            f.is_empty = bytes.is_empty();
                            f.is_binary = rgx_core::encoding::is_binary(bytes);
                            dirty_files.insert(f.rel_path.clone(), Arc::clone(bytes));
                        }
                        None => continue,
                    }
                }
            }
        }
        // A binary file is not searched *raw* -- but an adapter may turn it
        // into text, and the direct path searches exactly that text, so a
        // blanket skip here took every `.gz`, `.docx` and PDF out of a pack
        // answer while the direct path still had them. Binary is a property
        // of the raw bytes; the raw branch below skips on it, the adapter
        // branch does not.
        //
        // Under a declared `-E` encoding the bit is about the WRONG bytes:
        // it was decided on the raw content at build time and the query
        // searches the decoded text (NUL-dense UTF-16 is text after the
        // decode). The raw branch asks the decoded view instead, exactly as
        // the direct path's `binary_cut` does, so nothing is dropped here
        // on a stale verdict.
        if !args.text && f.is_binary && forced.is_none() {
            let claimed = registry.may_claim_for_path(&f.rel_path);
            if !claimed {
                continue;
            }
        }
        if !args.glob.is_empty() {
            let match_res = overrides.matched(Path::new(&f.rel_path), false);
            if match_res.is_ignore() {
                continue;
            }
        }
        kept.push(f);
    }

    // `--sort path` is the walker's job on the direct path and the record
    // list's job here: the manifest is in ingest order, which is neither
    // path order nor obliged to match the walk's order. The key is the
    // walker's `ordered()` key -- byte-wise rel_path -- and `--sortr`
    // reverses it. Without the flag the manifest order stands, which is
    // what the store has always answered in.
    if args.sort.is_some() {
        kept.sort_by(|a, b| {
            let ord = slash_path(&a.rel_path).cmp(&slash_path(&b.rel_path));
            if args.sort_reversed {
                ord.reverse()
            } else {
                ord
            }
        });
    }

    // The direct path's rule, the same question asked the same way: a
    // search over a directory (or over the implicit one, when no path was
    // typed) prints every hit with its path; a single named file does not.
    // The store's own file count is NOT the question -- a corpus the binary
    // rule thinned to one file is still a directory search, and printing
    // that one hit bare gave two answers to one question.
    let multi = !args.no_filename
        && (args.paths.len() > 1
            || args.paths.is_empty()
            || args.paths.iter().any(|p| std::path::Path::new(p).is_dir()));
    // `--heading` is meaningful only when multiple files are in play. If
    // the user picked `None` on the CLI, fall back to ripgrep's default:
    // group matches under a single path header when stdout is a TTY, and
    // prefix every line otherwise. The TTY check is cheap and bounded
    // to a single fcntl/ioctl call.
    let heading = args
        .heading
        .unwrap_or_else(|| std::io::stdout().is_terminal());

    // `--files` short-circuit: the manifest already carries the file paths
    // the list mode prints, so mmapping the packs to answer a question the
    // manifest already answered is ~30 ms of open/pt/vm-flags paid to no
    // purpose. Compiling the matcher is skipped for the same reason -- list
    // mode is pattern-free by definition. The `Ctx` is built above, where
    // the dirty-file overlay's extraction can reach it too.
    if args.list_files {
        let mut buffered = std::io::BufWriter::with_capacity(256 * 1024, out);
        // `-0` / `--null` makes the list machine-readable for xargs;
        // the default newline is what humans and existing scripts
        // expect.
        let sep = if args.null_data { "\0" } else { "\n" };
        for f in kept.iter() {
            let disp = match &display_base {
                Some(base) => format!("{}/{}", base, slash_path(&f.rel_path)),
                None => slash_path(&f.rel_path),
            };
            write!(buffered, "{disp}{sep}").ok();
        }
        buffered.flush()?;
        return Ok(!kept.is_empty());
    }

    // Partition after the listing short-circuit: the search stage wants
    // the two populations apart (`-L` prints the empty ones as misses) and
    // in the order the list above already printed them.
    let t_filter_ms = t_stage.elapsed().as_secs_f64() * 1000.0;
    let t_stage = std::time::Instant::now();
    let (mut active_files, mut empty_files): (Vec<_>, Vec<_>) = (Vec::new(), Vec::new());
    for f in kept {
        if f.is_empty {
            empty_files.push(f);
        } else {
            active_files.push(f);
        }
    }

    let replace_re = build_replace_regex(args);
    let quiet = args.quiet;

    let context = args.before() > 0 || args.after() > 0 || args.context.is_some();
    let lines = if args.no_line_number {
        false
    } else {
        args.line_number || args.column || std::io::stdout().is_terminal()
    };

    // Pre-map all packs
    let mut pack_storage_map = std::collections::HashMap::new();
    for pack_rec in &manifest.packs {
        let pack_path = store_dir.join(&pack_rec.filename);
        let f = std::fs::File::open(&pack_path).map_err(|e| {
            rgx_core::anyhow!("cannot open pack file '{}': {}", pack_path.display(), e)
        })?;
        let m = unsafe { rgx_core::memmap2::Mmap::map(&f)? };
        pack_storage_map.insert(pack_rec.pack_id, Arc::new(m));
    }
    let pack_storage = Arc::new(pack_storage_map);

    // The extraction context this query runs its adapter pipeline under,
    // hashed the way the build hashed the one it signed the rollups under.
    // The per-file rule below asks this question once per record.
    let query_fp = extract_fingerprint(&ctx, &registry);
    let manifest_fp = manifest.extract_fp;

    // The n-gram filter, built once per query from the literal every match
    // must contain (`ngram::query_sig512`). It may reject a file only when
    // the bytes the worker will search are the bytes the store signed, so
    // it stands down whenever they are not: `-v`/`--files-without-match`
    // (a "match" is a line the pattern does NOT cover, so nothing is
    // required in one and a pruned file is one the query owes output), a
    // forced `-E` decode (the matcher would see transcoded text), and -- per
    // file in the worker -- an extension an adapter may claim, unless the
    // record says its signature is the adapter rollup (`SIG_COVERS_ADAPTER`)
    // and the head's extraction fingerprint is this query's. Standing down
    // costs the search the filter would have saved; filtering when it must
    // not loses matches by omission, which is the one thing this filter must
    // never do.
    // `RGX_ABLATE_NGRAM` forces the stand-down state for the paper's
    // end-to-end tier ablation: cost may change, answers never do.
    let ngram_q = if !args.invert_match
        && !args.files_without_match
        && forced.is_none()
        && !rgx_core::ablate_ngram()
    {
        byte_pattern(args).as_deref().and_then(|pat| {
            let ci = args.ignore_case || (args.smart_case && !pat.chars().any(char::is_uppercase));
            rgx_core::ngram::query_sig512(pat, ci)
        })
    } else {
        None
    };
    let ngram_pruned = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ngram_total = active_files.len();

    let t_map_ms = t_stage.elapsed().as_secs_f64() * 1000.0;
    let t_stage = std::time::Instant::now();
    let (tx, rx) = mpsc::channel::<Option<Msg>>();
    let mut buffered = std::io::BufWriter::with_capacity(256 * 1024, out);
    let out_ref = &mut buffered;

    let any = std::thread::scope(|s| {
        let printer = s.spawn({
            let args = args.clone();
            move || {
                print_messages(
                    rx,
                    out_ref,
                    &args,
                    replace_re.as_ref(),
                    multi,
                    lines,
                    context,
                    heading,
                    quiet,
                )
            }
        });

        let quit_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // `--sort path` serialises here exactly as it serialises the
        // walker (`Builder::ordered`): two workers handing chunks to a
        // printer interleave the sorted order again. The walk's own words
        // apply -- an ordered run with two workers would interleave the
        // branches -- and so does its answer: threads are ignored while
        // the flag is set.
        let num_threads = if args.sort.is_some() {
            1
        } else {
            args.threads.unwrap_or_else(all_threads).max(1)
        };

        let shared_files = Arc::new(active_files);
        let dirty_map = Arc::new(dirty_files);
        let next_idx = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let chunk_size = if shared_files.is_empty() {
            64
        } else {
            (shared_files.len() / (num_threads * 4)).clamp(16, 512)
        };

        let mut workers = Vec::new();

        for _ in 0..num_threads {
            let storage = Arc::clone(&pack_storage);
            let files = Arc::clone(&shared_files);
            let next = Arc::clone(&next_idx);
            let quit = Arc::clone(&quit_flag);
            let tx_w = tx.clone();
            let args_w = args.clone();
            let base_opt = display_base.clone();
            let reg_w = Arc::clone(&registry);
            let ctx_w = Arc::clone(&ctx);
            let ngram_w = ngram_q;
            let pruned_w = Arc::clone(&ngram_pruned);
            let dirty_w = Arc::clone(&dirty_map);

            let worker = s.spawn(move || {
                let mut searcher = make_searcher(&args_w);
                let forced_w = forced_bom_of(&args_w);
                // For the units an adapter produces. Binary detection is
                // off here for the same reason the direct path's
                // `text_searcher` has it off: the NUL heuristic describes the
                // *container*, and `Quit` on a stray NUL in a rendered field
                // would take the whole file out of `-c`, `-l` and the exit
                // status. The manifest's `is_binary` bit is likewise not
                // applied to a unit -- a `.gz` is binary as a file and text
                // as its member.
                let unit_config = RgxConfig {
                    binary: engine::RgxBinaryDetection::None,
                    before: args_w.before(),
                    after: args_w.after(),
                    invert: args_w.invert_match,
                    multi_line: args_w.multiline || args_w.multiline_dotall,
                    line_numbers: needs_line_numbers(&args_w),
                    // `forced_bom` stays at its default on purpose: these
                    // bytes are adapter output, already text, and `-E`
                    // decodes INPUT. A searcher over units that also decoded
                    // would decode the rendering a second time.
                    ..RgxConfig::default()
                };
                let unit_byte = HitSink::build_byte(&args_w);
                let mut unit_searcher =
                    CompatSearcher::new(unit_config, unit_byte, engine::Mode::from_env());

                loop {
                    if quit.load(Ordering::Relaxed) {
                        break;
                    }
                    let start = next.fetch_add(chunk_size, Ordering::Relaxed);
                    if start >= files.len() {
                        break;
                    }
                    let end = (start + chunk_size).min(files.len());

                    for f in &files[start..end] {
                        if quit.load(Ordering::Relaxed) {
                            break;
                        }
                        // The overlay's read side: a dirty file is searched
                        // from the bytes the coordinator read off disk, not
                        // from its pack slice -- the slice holds the corpus
                        // as of the build.
                        let dirty_now = dirty_w.get(&f.rel_path);
                        // The n-gram filter: a signature missing a bit the
                        // pattern's holds proves the file cannot contain the
                        // needle, and the file is skipped before its bytes
                        // are read. A file an adapter may claim is searched
                        // on the pipeline's units, which only the adapter
                        // rollup covers -- and only a rollup whose
                        // `SIG_COVERS_ADAPTER` flag is set under an
                        // extraction fingerprint equal to this query's,
                        // because a rollup signed for a different Ctx,
                        // member budget, policy or adapter chain covers
                        // units this search will never see and omits units
                        // it will. Without either answer the filter stands
                        // down on the record. The all-zero signature (an
                        // un-analysed record) stands it down inside
                        // `contains_query`. A dirty file is never filtered
                        // either: its stored signature covers the bytes the
                        // build saw, and pruning on that is exactly how a
                        // filter loses a match to an edit.
                        if let Some(q) = ngram_w {
                            let claimed = reg_w.may_claim_for_path(&f.rel_path);
                            let covered = rgx_core::ngram::covered_pipeline_units(
                                claimed,
                                f.sig_covers_adapter,
                                query_fp == manifest_fp,
                            );
                            if dirty_now.is_none()
                                && rgx_core::ngram::may_reject(&f.ngram, covered, &q)
                            {
                                pruned_w.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                        }
                        let file_slice: &[u8] = match dirty_now {
                            Some(b) => b.as_slice(),
                            None => {
                                let mmap = match storage.get(&f.pack_id) {
                                    Some(m) => m,
                                    None => continue,
                                };
                                let pack_bytes = &mmap[rgx_core::tv_runtime::PackHeader::SIZE..];
                                let f_start = f.offset as usize;
                                let f_end = f_start + f.length as usize;
                                if f_end > pack_bytes.len() {
                                    continue;
                                }
                                &pack_bytes[f_start..f_end]
                            }
                        };

                        let display_path = match &base_opt {
                            Some(base) => format!("{}/{}", base, slash_path(&f.rel_path)),
                            None => slash_path(&f.rel_path),
                        };

                        // A file an adapter claims is answered by the pipeline on this
                        // slice — the same `process` the direct path
                        // runs on the same bytes. A total bail falls
                        // through to the raw search below rather than
                        // being treated as an answer (direct path's
                        // rule too). `slash_path` because the manifest
                        // stores the platform's separator and the
                        // adapters name members off this string:
                        // `strip_suffix` takes a basename by splitting
                        // on '/', so a backslashed path would name the
                        // member after the whole path. The direct path
                        // does the same conversion before `process`.
                        let rel = slash_path(&f.rel_path);
                        if reg_w.may_claim_for_path(&rel) {
                            let mut founds = Vec::new();
                            let passthrough =
                                rgx_core::process(&reg_w, &rel, file_slice, 0, &ctx_w, &mut founds);
                            if !passthrough {
                                let mut stop = false;
                                let mut any_hit = false;
                                for found in &founds {
                                    // The byte regex is what captures the
                                    // submatches; `None` here left `-o`
                                    // printing nothing and `--json` reporting
                                    // `submatches: []` on the pack engine.
                                    // `build_byte` is memoised, so this is a
                                    // lookup after the first unit.
                                    let mut sink =
                                        HitSink::new(&args_w, HitSink::build_byte(&args_w));
                                    if unit_searcher.search_slice(&found.bytes, &mut sink).is_err()
                                    {
                                        continue;
                                    }
                                    // The unit's name is the adapter's: for an archive member it is
                                    // `container!member`, which is the name the
                                    // direct path prints for the same bytes.
                                    let unit_path = match &base_opt {
                                        Some(base) => {
                                            format!("{}/{}", base, slash_path(&found.path))
                                        }
                                        None => slash_path(&found.path),
                                    };
                                    if let Some(hit) = sink.into_hit(|| unit_path, found.via) {
                                        any_hit = true;
                                        let msg = if args_w.json {
                                            json_msg(hit)
                                        } else if !args_w.only_matching
                                            && args_w.replace.is_none()
                                            && !args_w.count
                                            && !args_w.files_with_matches
                                            && !quiet
                                            && !(hit.binary && !args_w.text)
                                        {
                                            Msg::Text(text_msg(
                                                LineFmt {
                                                    multi,
                                                    lines,
                                                    context,
                                                    heading,
                                                    color: color_resolved(args_w.color.as_deref()),
                                                    column: args_w.column,
                                                },
                                                &hit,
                                            ))
                                        } else {
                                            Msg::Hit(hit)
                                        };
                                        if tx_w.send(Some(msg)).is_err() {
                                            stop = true;
                                            break;
                                        }
                                        if quiet {
                                            stop = true;
                                            break;
                                        }
                                    }
                                }
                                // `--files-without-match` lists the files that
                                // produced nothing, and a claimed file is
                                // answered here: it never falls through to the
                                // raw branch's own `Listed`. A file whose units
                                // all missed has to be listed here or it
                                // vanishes from the answer while the direct
                                // path lists it. A hit the printer suppressed
                                // (`any_hit`) is still a hit -- rg does not
                                // list a file it never looked at as text.
                                if args_w.files_without_match
                                    && !any_hit
                                    && !stop
                                    && tx_w.send(Some(Msg::Listed(display_path))).is_err()
                                {
                                    stop = true;
                                }
                                if stop {
                                    quit.store(true, Ordering::Relaxed);
                                    break;
                                }
                                continue;
                            }
                            // `passthrough`: the adapters declined and the units `process`
                            // copied are the input bytes, so the raw
                            // search below is both the honest and the
                            // cheaper answer — unless the file is binary,
                            // in which case it reached this branch only
                            // because an adapter might have claimed it,
                            // none did, and there is nothing left to
                            // search.
                            // Under `-E` the decoded view decides
                            // binary-ness, and the raw branch below asks it
                            // of the decoded head; dropping here on the
                            // manifest's raw-bytes verdict would repeat the
                            // skip this branch exists to avoid.
                            if passthrough && !args_w.text && f.is_binary && forced_w.is_none() {
                                continue;
                            }
                        }

                        // The binary rule for the raw slice. Without a
                        // declared encoding the manifest's `is_binary` is
                        // the answer -- the same rule, marks and all, over
                        // the whole file at build time. Under `-E` the
                        // searcher decodes first, so the question is asked
                        // here of the decoded head: the same question
                        // `binary_cut` asks on the direct path, and a walked
                        // file that is binary is dropped whole, as there.
                        let is_bin = match forced_w {
                            Some(bom) => {
                                binary_cut(&file_slice[..SNIFF.min(file_slice.len())], Some(bom))
                                    .is_some()
                            }
                            None => f.is_binary,
                        };
                        if is_bin && !args_w.text {
                            continue;
                        }
                        // As above: the submatch regex, not `None`, or the
                        // pack engine's raw records answer without columns.
                        let mut sink = HitSink::new(&args_w, HitSink::build_byte(&args_w));
                        sink.binary = is_bin;

                        let _ = searcher.search_slice(file_slice, &mut sink);

                        // `"raw"`: no adapter produced the bytes. The
                        // storage engine is `--explain-engine`'s to say;
                        // a JSON reader comparing a pack answer with a
                        // direct one should see the same object.
                        let hit_opt = sink.into_hit(|| display_path.clone(), "raw");
                        if let Some(hit) = hit_opt {
                            let msg = if args_w.json {
                                json_msg(hit)
                            } else if !args_w.only_matching
                                && args_w.replace.is_none()
                                && !args_w.count
                                && !args_w.files_with_matches
                                && !quiet
                                && !(hit.binary && !args_w.text)
                            {
                                Msg::Text(text_msg(
                                    LineFmt {
                                        multi,
                                        lines,
                                        context,
                                        heading,
                                        color: color_resolved(args_w.color.as_deref()),
                                        column: args_w.column,
                                    },
                                    &hit,
                                ))
                            } else {
                                Msg::Hit(hit)
                            };
                            if tx_w.send(Some(msg)).is_err() {
                                quit.store(true, Ordering::Relaxed);
                                break;
                            }
                            if quiet {
                                quit.store(true, Ordering::Relaxed);
                                break;
                            }
                        } else if args_w.files_without_match
                            && tx_w.send(Some(Msg::Listed(display_path))).is_err()
                        {
                            quit.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            });
            workers.push(worker);
        }

        for f in &empty_files {
            let display_path = match &display_base {
                Some(base) => format!("{}/{}", base, slash_path(&f.rel_path)),
                None => slash_path(&f.rel_path),
            };
            let mut sink = HitSink::new(args, HitSink::build_byte(args));
            let mut searcher = make_searcher(args);
            let _ = searcher.search_slice(&[], &mut sink);
            if let Some(hit) = sink.into_hit(|| display_path.clone(), "raw") {
                let _ = tx.send(Some(Msg::Hit(hit)));
            } else if args.files_without_match {
                let _ = tx.send(Some(Msg::Listed(display_path)));
            }
        }

        for w in workers {
            let _ = w.join();
        }
        drop(tx);
        printer.join().unwrap()
    });

    buffered.flush()?;
    if std::env::var_os("RGX_NGRAM_STATS").is_some() {
        eprintln!(
            "rgx-ngram: pruned {} of {} files before search",
            ngram_pruned.load(Ordering::Relaxed),
            ngram_total
        );
    }
    let t_work_ms = t_stage.elapsed().as_secs_f64() * 1000.0;
    if args.stats {
        let t_in = t_manifest_ms + t_filter_ms + t_map_ms + t_work_ms;
        // Same shape as the legacy `rgx-tv --stats` (crates/rgx-core/src/bin/
        // rgx-tv.rs print_stages): one line, five fields plus teardown, on
        // stderr so it never joins the answer. `scripts/tv-matrix.sh` parses
        // this exact line -- change both together. These are `Instant`
        // readings inside the process, so they cannot decide a single-shot
        // question, which is what the harness says about them too.
        eprintln!(
            "rgx-tv: in-process {:.1} ms = manifest {:.1} + filter {:.1} + map {:.1} + work {:.1} + teardown {:.1}",
            t_in, t_manifest_ms, t_filter_ms, t_map_ms, t_work_ms, 0.0,
        );
    }
    Ok(any)
}

/// The body of a search: build matcher/ctx from the args, walk, print to
/// `out`. Shared by one-shot mode and --serve (one call per query).
/// Returns whether anything matched (the exit-code bit).
/// `out` must be Send: the printer thread writes through it (a `Stdout`
/// handle qualifies; a `StdoutLock` does not).
fn run_query(
    args: &Args,
    registry: &Arc<Registry>,
    out: &mut (dyn std::io::Write + Send),
    allow_stdin: bool,
) -> Result<bool> {
    let detection = detector::AutoDetector::detect(args);
    // `--explain-engine` prints the *effective* engine, so it is
    // emitted after the pack-store admission check below rather than
    // before. Printing the detector's raw verdict first and any
    // correction afterwards reads as two answers, and the correction
    // is the one that is true.
    if args.explain_engine && detection.engine != detector::EngineChoice::PackStore {
        eprintln!(
            "[rgx detector] selected engine: {} ({})",
            detection.engine.as_str(),
            detection.reason
        );
    }
    if detection.engine == detector::EngineChoice::PackStore {
        // A pack store indexes the corpus bytes verbatim and the pack
        // searcher runs the adapter pipeline on the slice it holds —
        // the same `process`, the same bytes, so a `.gz` member, a
        // `.docx` paragraph and a PDF page are all present in a pack
        // answer. A pack answer is no longer a subset of a direct
        // one, so neither branch below has a wrong answer to decline.
        let store_dir = match detection.store_path.clone() {
            Some(p) => p,
            None => {
                // Unreachable unless the engine was named explicitly: the
                // automatic branch only selects the pack engine after
                // `find_store` has already located one.
                let target = args.paths.first().map(|s| s.as_str()).unwrap_or(".");
                let s_path = match &args.tv_store {
                    Some(s) => std::path::PathBuf::from(s),
                    None => std::path::Path::new(target).join(".rgx-tv"),
                };
                eprintln!(
                    "rgx: auto-building pack store for '{}' -> '{}'...",
                    target,
                    s_path.display()
                );
                let cfg = rgx_core::tv_runtime::BuildConfig {
                    follow_symlinks: args.follow,
                    hidden: !args.no_hidden,
                    gitignore: !args.no_ignore,
                    // These three were dropped on the floor, so
                    // `--tv-build . -g '*.rs'` ingested the whole tree and
                    // `--max-depth` did nothing, under flags that say
                    // otherwise. `BuildConfig` documents each one; this is
                    // the same list the direct walker gets, so both axes
                    // answer the same question about one corpus.
                    parents: !args.no_ignore,
                    max_depth: args.max_depth,
                    globs: args.glob.clone(),
                    ..Default::default()
                };
                let reg_for_ext = Arc::clone(registry);
                let ctx_for_ext = Arc::new(Ctx::default());
                let units = pipeline_units(Arc::clone(&reg_for_ext), Arc::clone(&ctx_for_ext));
                let units_for_sign =
                    pipeline_units(Arc::clone(&reg_for_ext), Arc::clone(&ctx_for_ext));
                let signer = move |rel: &str, data: &[u8]| -> Vec<Vec<u8>> {
                    units_for_sign(rel, data)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|(_, b)| b)
                        .collect()
                };
                let ext_ref: Option<&rgx_core::tv_runtime::PreExtractor> = if args.tv_pre_extract {
                    Some(&units)
                } else {
                    None
                };
                let sign_ref: Option<&rgx_core::tv_runtime::UnitSigner> = Some(&signer);
                let extract_fp = extract_fingerprint(&ctx_for_ext, &reg_for_ext);
                let (act, b, u) = rgx_core::tv_runtime::build_or_update_store_with_extractor(
                    Path::new(target),
                    &s_path,
                    &cfg,
                    ext_ref,
                    sign_ref,
                    extract_fp,
                )?;
                report_store(act, &b, u.as_ref());
                s_path
            }
        };
        if args.explain_engine {
            eprintln!(
                "[rgx detector] selected engine: {} ({})",
                detection.engine.as_str(),
                detection.reason
            );
        }
        return run_tv_query(args, &store_dir, out);
    }
    let args = Arc::new(args.clone());
    let max_filesize = parse_size(&args.max_filesize)?;
    let ctx = Arc::new(Ctx {
        max_depth: args.max_adapter_depth,
        max_members: MAX_ARCHIVE_MEMBERS,
        max_file_size: max_filesize as usize,
        filter: filter_of(&args)?,
        facts_sink: None,
    });
    // The archive producers enforce this same budget before they enumerate,
    // and the pipeline enforces it again when it recurses. The two caps have
    // to come from one value or the truncation note would misreport what was
    // dropped.
    //
    // `-M` wins over the environment, so this is only called when the flag
    // resolved to something other than its default; otherwise RGX_MAX_MEMBERS
    // and RGX_MAX_MEMBER_BYTES would be unreachable from the command line.
    // Presence is not the test: applying a default calls `insert_value`, which
    // bumps `occurrences`, so `is_present` is true either way.
    //
    // `-M 0` is a legal limit -- rg answers it by skipping every non-empty
    // file -- and it does all of that work in the walk, where
    // `Ctx::max_file_size` is compared against the file length. Nothing
    // reaches an adapter, so this budget is not what enforces it, and
    // `set_budget` asserts `bytes >= 1` because a zero-byte budget cannot
    // hold the truncation note. Leaving the budget alone keeps both
    // contracts: the limit is 0, and the note keeps its room.
    #[cfg(feature = "adapters-archive")]
    if ctx.max_file_size != rgx_core::Ctx::default().max_file_size && ctx.max_file_size >= 1 {
        rgx_adapters_archive::budget::set_budget(rgx_adapters_archive::budget::Budget {
            members: ctx.max_members,
            bytes: ctx.max_file_size as u64,
        });
    }

    // stdin: explicit `-`, or no paths with input that is genuinely piped
    // (rg semantics: with no pipe and no paths, search the current
    // directory). `readable_stdin` is the test -- `!is_terminal()` also
    // answers "yes" for NUL and for an inherited console handle, and
    // searching those is how `rgx PATTERN` came back empty under CI.
    let use_stdin =
        args.paths.iter().any(|p| p == "-") || (args.paths.is_empty() && readable_stdin());
    if use_stdin && !allow_stdin {
        rgx_core::bail!(
            "stdin search is unavailable in --serve mode (the query stream owns stdin); pass explicit paths"
        );
    }
    let real_paths: Vec<String> = if args.paths.is_empty() && !use_stdin {
        vec![".".into()]
    } else {
        args.paths.iter().filter(|p| *p != "-").cloned().collect()
    };
    // Paths the user named as files, as opposed to the roots the walker
    // will descend from. rg turns binary detection off for these and
    // leaves it on everywhere else; the whole of the binary policy
    // hangs off that one distinction — see `drops_binary_walk_hits`.
    let explicit_paths: Arc<std::collections::HashSet<String>> = Arc::new(
        real_paths
            .iter()
            .filter(|p| !Path::new(p).is_dir())
            .map(|p| slash_path(p))
            .collect(),
    );
    let multi = !args.no_filename
        && (real_paths.len() + usize::from(use_stdin) > 1
            || real_paths.iter().any(|p| Path::new(p).is_dir()));
    // See the other `let heading` site for the rationale. The
    // path-stdin walker also formats hits with this resolved value.
    let heading = args
        .heading
        .unwrap_or_else(|| std::io::stdout().is_terminal());

    // rg's rule for `-n`: the number appears when stdout is a
    // terminal, and for nothing else on its own (several files do
    // not turn it on — the path prefix disambiguates). An explicit
    // flag always wins; `--no-line-number` wins over `--line-number`.
    let context = args.before() > 0 || args.after() > 0 || args.context.is_some();
    let lines = if args.no_line_number {
        false
    } else {
        args.line_number || args.column || std::io::stdout().is_terminal()
    };

    if std::env::var_os("RGX_PROFILE").is_some() {
        rgx_core::profile_init();
    }
    // The packed-mask counters are off unless a run asks for them;
    // asking for them is what makes the candidate-rate question
    // answerable on a real corpus instead of a guess.
    rgx_core::maskstats::enable(std::env::var_os("RGX_MASK_STATS").is_some());

    // rg-compatible globs: gitignore-style, leading `!` excludes.
    // Validated here and handed to the walker below (`!~$*` skips
    // transient MS Office owner-lock scratch files). Building the
    // `Override` once here avoids compiling every glob regex twice.
    let mut walk_overrides = OverrideBuilder::new(".");
    let _ = walk_overrides.add("!~$*");
    for g in &args.glob {
        walk_overrides.add(g).context("invalid glob")?;
    }
    let walk_overrides = walk_overrides.build()?;

    let (tx, rx) = mpsc::channel::<Option<Msg>>();
    // Absent unless --cache was given: the flag is the only thing that can
    // turn a memo into stale bytes for a user who never asked for one.
    let cache = match &args.cache {
        Some(dir) => Some(Arc::new(cache::Cache::open(cache::locate(Some(dir))?))),
        None => None,
    };
    let build_stamp = cache.as_ref().and_then(|_| cache::build_stamp());
    let quiet = args.quiet;
    // Stdout is line-buffered: without this wrapper every printed
    // line is its own write syscall. The flush after the scope keeps
    // ordering intact for `--serve` sentinels and the one-shot exit
    // code path.
    let mut buffered = std::io::BufWriter::with_capacity(256 * 1024, out);
    let out_ref = &mut buffered;
    let any = std::thread::scope(|s| {
        let printer = s.spawn({
            let args = args.clone();
            let replace_re = build_replace_regex(&args);
            move || {
                print_messages(
                    rx,
                    out_ref,
                    &args,
                    replace_re.as_ref(),
                    multi,
                    lines,
                    context,
                    heading,
                    quiet,
                )
            }
        });

        // stdin is searched as a single unlabeled unit, before the walk.
        // Harness use is `rgx pattern < file`, where ordering is trivial.
        if use_stdin {
            use std::io::Read;
            let mut buf = Vec::new();
            if std::io::stdin().lock().read_to_end(&mut buf).is_err() {
                // printer is gone or stdin broke; stop the query
                drop(tx);
                let _ = printer.join();
                return false;
            }
            let mut raw = RawState::new(&args);
            // `-` is a path the user named, so it gets the explicit half
            // of rg's binary rule: searched as text, counted, listed,
            // exit status set, only line output suppressed. That is
            // exactly what `raw.text_searcher` is — the same searcher
            // with binary detection off that the walker's binary branch
            // uses. rg agrees (`rg -c 'fn ' < blob.rs` prints the count).
            let stdin_searcher = &mut raw.text_searcher;
            let send_err = if let Some(budget) = args.chunk {
                let mut sink = RangeSink::new(args.quiet, args.max_count, compiled_byte_arc(&args));
                let _ = stdin_searcher.search_slice(&buf, &mut sink);
                let chunks = (sink.count > 0).then(|| build_chunks(&buf, &sink.ranges, budget));
                match chunks.filter(|c| !c.is_empty()) {
                    Some(chunks) => tx
                        .send(Some(Msg::Chunks(ChunkHit {
                            path: "<stdin>".into(),
                            via: "raw",
                            count: sink.count,
                            binary: sink.binary,
                            chunks,
                        })))
                        .is_err(),
                    None => false,
                }
            } else {
                // The submatch regex, so `-o`/`--column`/`--json` answer
                // from stdin exactly as they answer from a named file.
                let mut sink = HitSink::new(&args, HitSink::build_byte(&args));
                let _ = stdin_searcher.search_slice(&buf, &mut sink);
                match sink.into_hit(|| "<stdin>".to_string(), "raw") {
                    Some(hit) => tx.send(Some(Msg::Hit(hit))).is_err(),
                    None => false,
                }
            };
            if send_err {
                // printer is gone (panic or early break); stop the query
                drop(tx);
                let _ = printer.join();
                return false;
            }
        }

        // walker: same traversal semantics as rg
        if !real_paths.is_empty() {
            // owned clones so the walker's 'static boxed closures can move them
            let registry = Arc::clone(registry);
            let ctx = Arc::clone(&ctx);
            let args = Arc::clone(&args);
            let explicit_paths = Arc::clone(&explicit_paths);
            let mut builder = WalkBuilder::new(&real_paths[0]);
            for p in &real_paths[1..] {
                builder.add(p);
            }
            builder
                .hidden(args.no_hidden)
                .parents(!args.no_ignore)
                .git_ignore(!args.no_ignore)
                .git_global(!args.no_ignore)
                .git_exclude(!args.no_ignore)
                .follow_links(args.follow)
                .max_depth(args.max_depth);
            // `--sort path` on a search: walk single-threaded in
            // sorted order so the printer needs no buffer at all. The
            // listing path keeps its parallel walk and `SortedSink`;
            // `quiet` breaks out after the first message and has
            // nothing to order. Same three conditions `print_messages`
            // reads, so the two cannot disagree about whether a run is
            // sorted.
            let sort_search = args.sort.is_some() && !args.list_files && !args.quiet;
            if sort_search {
                builder.ordered(args.sort_reversed);
            }
            // The `-t`/`-T` filter installs into the walker so the
            // per-entry check runs at the traversal site, not after
            // the file has already been stat'ed and pushed onto the
            // work queue. The helper is called here even when no
            // type flags were passed: it returns `None` cheaply and
            // the walker short-circuits.
            if let Some(tf) = build_type_filter(&args) {
                builder.type_filter(tf);
            }
            // MS Office owner-lock files (~$budget.xlsx) and the user's
            // `-g` globs were validated and compiled into `walk_overrides`
            // before spawning the printer thread; install them into the
            // walker here without recompiling the regexes.
            builder.overrides(walk_overrides);
            // thread count is asked of the OS on every walker build —
            // cache it process-wide (matters in --serve, where a
            // walker is built per query). `-j` overrides; `0` means
            // "ask the OS" (ripgrep's behaviour).
            static WALK_THREADS: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
            let requested = args.threads.unwrap_or(0);
            // Listing default width is not the search default width:
            // asking for the machine's width on a listing measured 39%
            // slower than asking for eight over a 20,000-file tree.
            // An explicit `-j` is left alone: a person who typed a
            // number meant it.
            const LISTING_DEFAULT_WIDTH: usize = 8;
            let default_width = if args.list_files {
                LISTING_DEFAULT_WIDTH
            } else {
                let hw = *WALK_THREADS.get_or_init(|| {
                    std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(4)
                });
                if !real_paths.is_empty()
                    && real_paths.iter().all(|p| std::path::Path::new(p).is_file())
                {
                    hw.min(real_paths.len().max(1))
                } else {
                    hw
                }
            };
            let walk: WalkParallel = builder
                .threads(if requested > 0 {
                    requested
                } else {
                    default_width
                })
                .build_parallel();

            // WalkParallel workers run on their own threads; one HitSink
            // per worker, reset between files, removes 20k per-file
            // `Vec<u8>` + `Vec<Line>` allocations from the hot path. The
            // `Arc<Args>` is captured by `move ||` and below.
            let _args_for_sink = Arc::clone(&args);

            let txw = tx.clone();
            // `--sort path` / `--sortr path`: every worker pushes into
            // a shared vec that the main thread sorts and ships at end
            // of walk. Held outside the closure so the post-walk
            // `finalize` step can reach it after `walk.run` returns.
            let sorted_sink: Option<Arc<SortedSink>> = if args.sort.is_some() {
                Some(Arc::new(SortedSink::new(
                    if args.null_data { b'\0' } else { b'\n' },
                    args.sort_reversed,
                )))
            } else {
                None
            };
            // `move ||` would consume `sorted_sink`; clone the Arc so the
            // outer post-walk finalize step still has a handle.
            let sorted_sink_for_workers = sorted_sink.as_ref().map(Arc::clone);
            // Direct-shared stdout used by every worker when the
            // listing mode does not need sorting. Channels are
            // bypassed entirely; the only contention is the per-flush
            // mutex on the shared `BufWriter`. Held outside the
            // `walk.run` closure so the post-walk flush step can reach
            // the same `Arc` after every worker drops its clone.
            let direct_shared: Arc<Mutex<std::io::BufWriter<std::io::Stdout>>> =
                Arc::new(Mutex::new(std::io::BufWriter::with_capacity(
                    256 * 1024,
                    std::io::stdout(),
                )));
            let direct_for_workers = Arc::clone(&direct_shared);
            walk.run(move || {
                let txw = txw.clone();
                let registry = registry.clone();
                let ctx = ctx.clone();
                let args = args.clone();
                let cache = cache.clone();
                let explicit_paths = Arc::clone(&explicit_paths);
                let profile = std::env::var_os("RGX_PROFILE").is_some();
                // Built per worker because a `Searcher` is not `Sync`;
                // the alternative — one shared behind a mutex — is a mutex
                // per match. Built lazily: a listing never reaches the
                // code that uses it, so `--files` would otherwise pay
                // three pattern compiles per thread for nothing.
                let mut raw: Option<RawState> = None;
                // One HitSink per worker. `take_hit` swaps the
                // populated `bytes`/`lines` `Vec`s out and the sink
                // keeps the 8 KiB pre-allocation across files.
                let mut sink = HitSink::new(&_args_for_sink, HitSink::build_byte(&_args_for_sink));
                // Adapter-output buffers, reused across files.
                let mut founds: Vec<rgx_core::Found> = Vec::new();
                let mut hits: Vec<FileHit> = Vec::new();
                let mut chunk_hits: Vec<ChunkHit> = Vec::new();
                // Without the sort flag, the per-worker direct-shared
                // stdout sink bypasses the mpsc channel entirely.
                let mut listed_batcher = if let Some(sink) = sorted_sink_for_workers.as_ref() {
                    ListedSink::Sorted(Arc::clone(sink))
                } else {
                    ListedSink::Direct(DirectBatcher::new(
                        Arc::clone(&direct_for_workers),
                        if args.null_data { b'\0' } else { b'\n' },
                    ))
                };
                let mut text_batcher = TextBatcher::new(txw.clone());
                // Per-worker formatting scratch, cleared by
                // `text_msg_into` on every use. One Vec reused across
                // every file the worker formats, instead of a fresh
                // `Vec::with_capacity(1024)` per hit.
                let mut text_scratch: Vec<u8> = Vec::with_capacity(1024);
                Box::new(move |entry| {
                    if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                        return WalkState::Continue;
                    }
                    let path = entry.path();
                    // --files: list what would be searched, never open the file
                    if args.list_files {
                        return listed_batcher.push(path);
                    }
                    // The size is not asked of the walk any more:
                    // `entry.metadata()` is a path-based stat per searched
                    // file, and on the 20k-file tree that is one whole
                    // syscall of the four each file pays. The raw path
                    // derives the length from its own first read (a short
                    // read into the sniff window is EOF and its length is
                    // the file's -- see `raw_search_inner`) and enforces
                    // `--max-filesize` there; the adapter path still asks,
                    // because its cache key is size + mtime before the
                    // read. rg does not apply `--max-filesize` to a path
                    // named on the command line, and neither does this --
                    // and the explicit-path test stays behind the size
                    // comparison's short circuit, where it only runs for
                    // the rare file over the cap.
                    // Whether a binary file keeps its hits, and so
                    // whether it has to be searched past the NUL.
                    let keep_binary = keeps_binary_walk_hits(&args, &explicit_paths, path);
                    // An extension with claiming adapters goes through
                    // the adapter pipeline; extensions nobody claims are
                    // searched raw (mmap). When every claimed adapter
                    // bails, the pipeline emits the original bytes as a
                    // single raw passthrough — the file is raw after
                    // all and must get the raw treatment.
                    // `hits`/`chunk_hits`/`read_data` are owned by the
                    // closure factory; clearing them between files reuses
                    // the heap allocations instead of freeing +
                    // reallocating per walk entry.
                    hits.clear();
                    chunk_hits.clear();
                    let mut read_data: Option<Vec<u8>> = None;
                    // Whether the raw bytes are binary, recorded
                    // whether or not anything matched: `-L` has to tell
                    // "did not match" from "rg would never have looked",
                    // and a file with no match leaves no `FileHit` to
                    // carry the flag.
                    let mut raw_is_binary = false;
                    let path_lossy = path.to_string_lossy();
                    let mut do_raw = !registry.may_claim_for_path(&path_lossy);
                    if do_raw && registry.has_magic_claimants() {
                        // The name says nothing; the bytes may still. A borg
                        // segment is `data/0/2` -- no extension, no dot -- and
                        // the only evidence of what it is lives in its first
                        // eight bytes. The probe is one short read, paid only
                        // by the files no adapter claims by name.
                        do_raw = !claims_magic(path, registry.as_ref());
                    }
                    // A file no adapter claims is searched raw, and the raw
                    // path never goes through `rgx_core::process` -- so the
                    // filter has to be asked HERE, before the file is read.
                    // The facts are complete at this point: the path, the
                    // extension and the format, which is "raw" because
                    // nothing claimed the file. There is no fact left to
                    // learn from the bytes, because no adapter will read
                    // them.
                    if do_raw && ctx.wants_filter() {
                        let path_str = slash_path(&path_lossy);
                        let facts = rgx_core::filter::file_facts(&path_str, "raw");
                        if !ctx.passes(&facts) {
                            return WalkState::Continue;
                        }
                    }

                    if !do_raw {
                        // The adapter path keeps the walk's stat: its cache
                        // key wants size + mtime before anything is read,
                        // and adapters are the rare extensions -- this is
                        // not the many-small-files hot path.
                        let meta = match entry.metadata() {
                            Ok(m) => m,
                            Err(_) => return WalkState::Continue,
                        };
                        if meta.len() > ctx.max_file_size as u64
                            && !is_explicit_path(&explicit_paths, path)
                        {
                            return WalkState::Continue;
                        }
                        let path_str = slash_path(&path_lossy);
                        let t1 = profile.then(std::time::Instant::now);
                        // `founds` is owned by the closure factory and
                        // cleared between files; reused instead of
                        // freed + reallocated per walk entry.
                        founds.clear();
                        // The memo has two layers. The alias — the path
                        // with the size and the mtime the walk already
                        // has, plus what decides the answer — is derived
                        // without reading the file, so a repeated run
                        // costs a stat and a directory read. The content
                        // key — the bytes plus the same — is derived only
                        // when the alias misses, and it is what lets two
                        // copies of a file, or a file that moved, share one
                        // extraction.
                        let chain = cache
                            .as_ref()
                            .and_then(|_| cache::chain_for(&registry, &path_str));
                        let memo = match (&cache, &chain) {
                            (Some(_), Some(chain)) => Some(cache::Key {
                                path: &path_str,
                                size: meta.len(),
                                mtime: meta.modified().ok(),
                                chain: chain.as_slice(),
                                ctx: &ctx,
                                build: build_stamp,
                                policy: cache::policy_code(),
                            }),
                            _ => None,
                        };
                        let key = memo.as_ref().and_then(|k| k.derive());
                        // The fast path: the alias says "this is the file I
                        // saw last time", and the content entry it points
                        // at holds the units. The file is not read.
                        let aliased = match (&cache, &key) {
                            (Some(c), Some(k)) => c.alias(k).and_then(|ck| c.content(&ck)),
                            _ => None,
                        };
                        let passthrough = if let Some(hit) = aliased {
                            // Reuse the per-worker `founds` Vec: copy each
                            // entry into it. `Found` is not `Clone`, so the
                            // cache hit branch cannot just hand the memo
                            // entry over -- we iterate and rebuild. The
                            // paths come back relative to the file, and the
                            // file's own path goes back in front of them.
                            for f in &hit {
                                founds.push(rgx_core::Found {
                                    path: cache::restamp(&f.path, &path_str),
                                    bytes: f.bytes.clone(),
                                    via: f.via,
                                });
                            }
                            if let Some(c) = &cache {
                                c.note_alias_hit();
                            }
                            false
                        } else {
                            let t0 = profile.then(std::time::Instant::now);
                            let Ok(d) = std::fs::read(path) else {
                                return WalkState::Continue;
                            };
                            if let Some(t0) = t0 {
                                READ_NS
                                    .fetch_add(t0.elapsed().as_nanos() as u64, Ordering::Relaxed);
                            }
                            // The content key: this file's bytes, plus what
                            // decides the answer. The same bytes under the
                            // same name are the same extraction, wherever
                            // they live.
                            let content_key = memo
                                .as_ref()
                                .and_then(|k| k.derive_content(&cache::content_hash(&d)));
                            // The extraction is coordinated by the content
                            // key: the walk is parallel, and two copies of
                            // the same content can reach this at the same
                            // time. The second one waits for the first and
                            // finds what it stored, so the content is
                            // extracted once.
                            let units = match (&cache, &content_key) {
                                (Some(c), Some(ck)) => c.extract_once(ck, &path_str, || {
                                    let mut fresh = Vec::new();
                                    let fell = rgx_core::process(
                                        &registry, &path_str, &d, 0, &ctx, &mut fresh,
                                    );
                                    // A file that fell through to the raw
                                    // path is not stored: its units are a
                                    // copy of the input and would cost the
                                    // cache more than the walk does.
                                    if fell {
                                        None
                                    } else {
                                        Some(fresh)
                                    }
                                }),
                                _ => {
                                    let mut fresh = Vec::new();
                                    let fell = rgx_core::process(
                                        &registry, &path_str, &d, 0, &ctx, &mut fresh,
                                    );
                                    if fell {
                                        None
                                    } else {
                                        Some(fresh)
                                    }
                                }
                            };
                            match units {
                                Some(units) => {
                                    for f in &units {
                                        founds.push(rgx_core::Found {
                                            path: cache::restamp(&f.path, &path_str),
                                            bytes: f.bytes.clone(),
                                            via: f.via,
                                        });
                                    }
                                    // The alias is written now, so the next
                                    // run does not even read the file.
                                    if let (Some(c), Some(k), Some(ck)) =
                                        (&cache, &key, &content_key)
                                    {
                                        c.put_alias(k, ck);
                                    }
                                    false
                                }
                                None => {
                                    read_data = Some(d);
                                    true
                                }
                            }
                        };
                        if let Some(t1) = t1 {
                            PROC_NS.fetch_add(t1.elapsed().as_nanos() as u64, Ordering::Relaxed);
                        }
                        // total bail: every adapter declined — this file is raw.
                        // `process` says so explicitly; the bytes it copied into
                        // `founds` are dead weight now, the raw search below reuses
                        // the already-read `data` instead of a second disk read
                        if passthrough {
                            do_raw = true;
                        } else if let Some(budget) = args.chunk {
                            // chunk mode: paragraph windows per produced unit
                            for found in &founds {
                                let t3 = profile.then(std::time::Instant::now);
                                // A unit that is the file's own bytes carries
                                // the file's binary rule: a walked binary
                                // file is dropped whole, exactly as the raw
                                // path drops it, and it is not a miss.
                                if found.path == path_str
                                    && found.via == "raw"
                                    && !keep_binary
                                    && unit_is_binary(&args, &found.bytes)
                                {
                                    raw_is_binary = true;
                                    continue;
                                }
                                let mut sink = RangeSink::new(
                                    args.quiet,
                                    args.max_count,
                                    compiled_byte_arc(&args),
                                );
                                if unit_searcher(
                                    raw.get_or_insert_with(|| RawState::new(&args)),
                                    found,
                                    &path_str,
                                    keep_binary && !args.text,
                                )
                                .search_slice(&found.bytes, &mut sink)
                                .is_ok()
                                    && sink.count > 0
                                {
                                    let chunks = build_chunks(&found.bytes, &sink.ranges, budget);
                                    if !chunks.is_empty() {
                                        chunk_hits.push(ChunkHit {
                                            path: found.path.clone(),
                                            via: found.via,
                                            count: sink.count,
                                            binary: sink.binary,
                                            chunks,
                                        });
                                    }
                                }
                                if let Some(t3) = t3 {
                                    SEARCH_NS.fetch_add(
                                        t3.elapsed().as_nanos() as u64,
                                        Ordering::Relaxed,
                                    );
                                }
                            }
                        } else {
                            for found in &founds {
                                let t3 = profile.then(std::time::Instant::now);
                                // The same file's binary rule as the chunk
                                // arm above: a unit that is the file's own
                                // bytes is dropped whole when the file is
                                // binary, and a file `rg` never looked at is
                                // not a file without a match.
                                if found.path == path_str
                                    && found.via == "raw"
                                    && !keep_binary
                                    && unit_is_binary(&args, &found.bytes)
                                {
                                    raw_is_binary = true;
                                    continue;
                                }
                                // Per-worker HitSink, reset between files
                                // by `take_hit` below. The sink carries
                                // the compiled byte regex so `-o`/`--json`
                                // can capture submatches.
                                if unit_searcher(
                                    raw.get_or_insert_with(|| RawState::new(&args)),
                                    found,
                                    &path_str,
                                    keep_binary && !args.text,
                                )
                                .search_slice(&found.bytes, &mut sink)
                                .is_ok()
                                {
                                    if let Some(hit) = sink.take_hit(
                                        || path_for_hit(args.no_filename, &found.path),
                                        found.via,
                                    ) {
                                        hits.push(hit);
                                    }
                                }
                                if let Some(t3) = t3 {
                                    SEARCH_NS.fetch_add(
                                        t3.elapsed().as_nanos() as u64,
                                        Ordering::Relaxed,
                                    );
                                }
                            }
                        }
                    }
                    if do_raw {
                        // raw path: small files are read once into a
                        // reusable buffer; large files keep the mmap
                        // path (never slurped). Chunk mode always
                        // mmaps unless the bytes are already in hand.
                        let t3 = profile.then(std::time::Instant::now);
                        // `path_str` is needed by `chunk_search`/
                        // `raw_search_buf` to populate the `FileHit.path`;
                        // under `--no-filename` the path is never read,
                        // so skip the allocation entirely. The main
                        // `raw_search` arm takes `path: &Path` and builds
                        // its own path string lazily inside `take_hit`,
                        // so for the walked-file majority (no `--chunk`,
                        // no adapter bail) the `slash_path` `String` here
                        // was allocated and never read — one wasted heap
                        // alloc per file. It is now computed only in the
                        // two arms that consume it.
                        let path_str;
                        if let Some(budget) = args.chunk {
                            path_str = if args.no_filename {
                                String::new()
                            } else {
                                slash_path(&path_lossy)
                            };
                            let ch = match &read_data {
                                Some(data) => chunk_search_buf(data, &path_str, &args, budget),
                                None => {
                                    chunk_search(path, &path_str, &args, budget, &explicit_paths)
                                }
                            };
                            if let Ok(Some(ch)) = ch {
                                chunk_hits.push(ch);
                            }
                        } else if let Some(data) = &read_data {
                            path_str = if args.no_filename {
                                String::new()
                            } else {
                                slash_path(&path_lossy)
                            };
                            let raw = raw.get_or_insert_with(|| RawState::new(&args));
                            // This route has its own `begin_file`: the
                            // display path is `path_str`, exactly what
                            // `raw_search_buf`'s `take_hit` closure hands
                            // the collected fallback, so the streamed and
                            // collected bytes name the same file. Arming
                            // here also means no call site depends on a
                            // previous file having disarmed.
                            raw.sink.begin_file(
                                args.no_filename,
                                &path_str,
                                LineFmt {
                                    multi,
                                    lines,
                                    context,
                                    heading,
                                    color: color_resolved(args.color.as_deref()),
                                    column: args.column,
                                },
                            );
                            if let Ok(Some(hit)) = raw_search_buf(
                                raw,
                                data,
                                &path_str,
                                &args,
                                keep_binary,
                                &mut raw_is_binary,
                            ) {
                                hits.push(hit);
                            }
                        } else {
                            let raw = raw.get_or_insert_with(|| RawState::new(&args));
                            raw.sink.begin_file(
                                args.no_filename,
                                &path_lossy,
                                LineFmt {
                                    multi,
                                    lines,
                                    context,
                                    heading,
                                    color: color_resolved(args.color.as_deref()),
                                    column: args.column,
                                },
                            );
                            if let Ok(Some(hit)) = raw_search(
                                raw,
                                path,
                                &args,
                                keep_binary,
                                &mut raw_is_binary,
                                ctx.max_file_size as u64,
                                &explicit_paths,
                            ) {
                                hits.push(hit);
                            }
                        }
                        if let Some(t3) = t3 {
                            SEARCH_NS.fetch_add(t3.elapsed().as_nanos() as u64, Ordering::Relaxed);
                        }
                    }
                    // rg's binary rule is about where the path came from, not
                    // about the file: a path the user named is searched
                    // as text (`-c` counts it, `-l` lists it, exit
                    // status is set, only line output is suppressed);
                    // a file the walk turned up is dropped whole. rgx
                    // used to apply the second half to both, which
                    // made `rgx -c PATTERN dir` and `rg -c PATTERN dir`
                    // disagree on every binary file in the tree.
                    let before = hits.len() + chunk_hits.len();
                    if !keep_binary {
                        hits.retain(|h| !h.binary);
                        chunk_hits.retain(|c| !c.binary);
                    }
                    // A file rg suppressed is skipped, not a miss:
                    // `--files-without-match` lists the files that do
                    // not match, and rg does not list the binary ones
                    // it never looked at. Counting them as misses is
                    // what turned `rgx --files-without-match` into
                    // "every binary file in the tree" on a pattern
                    // that matches nothing anywhere.
                    let suppressed = raw_is_binary || before > hits.len() + chunk_hits.len();
                    let had_no_hit = !suppressed && hits.is_empty() && chunk_hits.is_empty();
                    // `--files-without-match`: only the misses are
                    // reported; sending hits would make `any` true
                    // even when every file matched.
                    if !args.files_without_match {
                        for mut hit in hits.drain(..) {
                            // The walk's own visit callback: this is
                            // where the common path's hits are born.
                            // `context` is part of text mode now:
                            // `text_msg` emits the `--` separators
                            // itself, and the central thread no longer
                            // has the per-line `writeln!` for a
                            // default-text hit. The remaining `Msg::Hit`
                            // arms are the smaller modes (`-o`, `-r`,
                            // `-c`, `-l`, binary note) the central
                            // thread handles unchanged.
                            if args.json {
                                if txw.send(Some(json_msg(hit))).is_err() {
                                    return WalkState::Quit;
                                }
                            } else if !args.only_matching
                                && args.replace.is_none()
                                && !args.count
                                && !args.files_with_matches
                                && !quiet
                                && !(hit.binary && !args.text)
                            {
                                // `--sort path` cannot batch: a batch
                                // concatenates several files into one
                                // buffer, and the per-file order has to
                                // survive to the printer. One message per
                                // file carries the path; batching stays the
                                // unsorted hot path. `context` is the same
                                // reason one level up: a batch concatenates
                                // files and the `--` a new context group
                                // needs would have to live inside it.
                                if args.sort.is_some() || context {
                                    let bytes = text_msg(
                                        LineFmt {
                                            multi,
                                            lines,
                                            context,
                                            heading,
                                            color: color_resolved(args.color.as_deref()),
                                            column: args.column,
                                        },
                                        &hit,
                                    );
                                    if txw.send(Some(Msg::Text(bytes))).is_err() {
                                        return WalkState::Quit;
                                    }
                                } else {
                                    // The streaming sink formatted these
                                    // bytes as the lines matched -- the
                                    // line text goes into the batch once,
                                    // where the collect-then-format path
                                    // copied it three times. A sink that
                                    // was not armed carries `None` and
                                    // falls back to the hit formatter.
                                    match hit.formatted.take() {
                                        Some(bytes) => {
                                            if text_batcher.push_bytes(&bytes) == WalkState::Quit {
                                                return WalkState::Quit;
                                            }
                                        }
                                        None => {
                                            text_msg_into(
                                                &mut text_scratch,
                                                LineFmt {
                                                    multi,
                                                    lines,
                                                    context,
                                                    heading,
                                                    color: color_resolved(args.color.as_deref()),
                                                    column: args.column,
                                                },
                                                &hit,
                                            );
                                            if text_batcher.push_bytes(&text_scratch)
                                                == WalkState::Quit
                                            {
                                                return WalkState::Quit;
                                            }
                                        }
                                    }
                                }
                            } else if txw.send(Some(Msg::Hit(hit))).is_err() {
                                return WalkState::Quit;
                            }
                        }
                        for ch in chunk_hits.drain(..) {
                            if txw.send(Some(Msg::Chunks(ch))).is_err() {
                                return WalkState::Quit;
                            }
                        }
                    }
                    if had_no_hit
                        && args.files_without_match
                        && txw
                            .send(Some(Msg::Listed(slash_path(&path_lossy))))
                            .is_err()
                    {
                        return WalkState::Quit;
                    }
                    WalkState::Continue
                })
            });
            // The walk is over. With `--sort path` we pull every path out,
            // sort, and ship one ListedBatch to the printer; without
            // it the per-worker streaming batcher already shipped its
            // bytes during the walk.
            // `Arc::try_unwrap` succeeds because every worker dropped
            // its `ListedSink` when `walk.run()` returned; the `else`
            // branch is a paranoia fallback.
            if let Some(sink) = sorted_sink {
                let sorted = match Arc::try_unwrap(sink) {
                    Ok(s) => s.finalize(),
                    Err(arc) => {
                        let mut paths = arc.paths.lock().unwrap();
                        let mut sorted = std::mem::take(&mut *paths);
                        if arc.reverse {
                            sorted.sort_by(|a, b| b.cmp(a));
                        } else {
                            sorted.sort();
                        }
                        let mut out = Vec::with_capacity(sorted.iter().map(|s| s.len() + 1).sum());
                        for p in &sorted {
                            out.extend_from_slice(p);
                            out.push(arc.sep);
                        }
                        out
                    }
                };
                let _ = tx.send(Some(Msg::ListedBatch(sorted)));
            }
            // Drain whatever the direct-shared BufWriter is still
            // holding. Each worker took the lock on its 8 KiB flush,
            // but a tree whose last batch sat below that threshold
            // would otherwise leave the trailing bytes in the kernel
            // buffer when the test harness captured stdout.
            if let Ok(mut g) = direct_shared.lock() {
                let _ = g.flush();
            };
        } // if !real_paths.is_empty()
        drop(tx);
        printer.join().unwrap_or(false)
    }); // std::thread::scope
    buffered.flush().ok();

    if std::env::var_os("RGX_PROFILE").is_some() {
        let mut rows = rgx_core::profile_dump();
        rows.sort_by_key(|&(_, _, t)| std::cmp::Reverse(t));
        for (name, calls, ns) in rows {
            eprintln!(
                "adapter {name}: {calls} calls, {:?}",
                std::time::Duration::from_nanos(ns)
            );
        }
        eprintln!(
            "profile: read={:?} process={:?} search={:?}",
            std::time::Duration::from_nanos(READ_NS.load(Ordering::Relaxed)),
            std::time::Duration::from_nanos(PROC_NS.load(Ordering::Relaxed)),
            std::time::Duration::from_nanos(SEARCH_NS.load(Ordering::Relaxed)),
        );
        // Query shape, not timing. A plain literal is already at the
        // memory-system limit (29.4 GB/s against 32.0 for the best
        // engine in existence), so only a caseless pattern or one
        // with no usable literal is worth prefilling. This reports
        // the three shapes so a session's worth of `RGX_PROFILE=1
        // rgx ...` runs answers it with data.
        let shape = describe_query_shape(&args);
        eprintln!("query: {shape}");
    }
    Ok(any)
}

/// Serve the Model Context Protocol on stdio.
///
/// The framing is the one `--serve` already uses: one JSON object per
/// line, newline-delimited, in both directions. The difference is what
/// the objects say. `--serve` takes rgx's own argv arrays; this takes
/// the protocol's methods, and the tools it offers are named by
/// `tools/list`.
///
/// The server owns stdin and never exits on its own: the client closes
/// the stream, and the server answers what came before that.
fn mcp_serve(registry: &Arc<Registry>, args: &Args) -> Result<()> {
    // The context the tools run under. The limits are the CLI's own:
    // a client that asks about a corpus is asking the same question the
    // command line would ask, and the answer should not depend on which
    // door the question came through.
    let ctx = Ctx {
        max_depth: args.max_adapter_depth,
        max_members: MAX_ARCHIVE_MEMBERS,
        max_file_size: parse_size(&args.max_filesize)? as usize,
        filter: None,
        facts_sink: None,
    };
    let server = rgx_core::mcp::McpServer::with_shared_context(Arc::clone(registry), ctx);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    server
        .serve(&mut input, &mut output)
        .map_err(|e| rgx_core::anyhow!("mcp: {e}"))
}

/// Write one serve-mode response sentinel.
fn serve_end(
    stdout: &std::io::Stdout,
    seq: u64,
    tag: &str,
    status: i32,
    matched: bool,
    error: Option<&str>,
) {
    let err = error
        .map(|e| format!(",\"error\":\"{}\"", rgx_core::djson::escape_json_string(e)))
        .unwrap_or_default();
    let mut out = stdout.lock();
    writeln!(
        out,
        "{{\"rgx\":\"end\",\"seq\":{seq},\"tag\":\"{tag}\",\"status\":{status},\"matched\":{matched}{err}}}"
    )
    .ok();
    out.flush().ok();
}

fn serve(registry: &Arc<Registry>) -> Result<()> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let tag = format!(
        "{:016x}",
        (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0))
            ^ (u64::from(std::process::id()) << 32)
    );
    let mut seq: u64 = 0;
    {
        use std::io::Write as _;
        let mut out = stdout.lock();
        writeln!(
            out,
            "{{\"rgx\":\"ready\",\"tag\":\"{tag}\",\"pid\":{}}}",
            std::process::id()
        )
        .ok();
        out.flush().ok();
    }
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        seq += 1;
        let tokens: Vec<String> = match rgx_core::djson::parse(&line) {
            Ok(arena) => {
                let root = arena.root();
                match root {
                    rgx_core::djson::Value::Array(arr_idx) => arena
                        .get_array(arr_idx)
                        .iter()
                        .filter_map(|v| v.as_str(&arena).map(str::to_string))
                        .collect(),
                    _ => {
                        serve_end(
                            &stdout,
                            seq,
                            &tag,
                            2,
                            false,
                            Some("query must be a JSON array"),
                        );
                        continue;
                    }
                }
            }
            Err(e) => {
                serve_end(
                    &stdout,
                    seq,
                    &tag,
                    2,
                    false,
                    Some(&format!("invalid JSON query: {e}")),
                );
                continue;
            }
        };
        let mut qargs = match Args::try_parse_from(std::iter::once("rgx".to_string()).chain(tokens))
        {
            Ok(a) if a.completions.is_some() => {
                serve_end(
                    &stdout,
                    seq,
                    &tag,
                    2,
                    false,
                    Some("--completions writes to the terminal, not to a query answer"),
                );
                continue;
            }
            Ok(a) => a,
            Err(e) => {
                serve_end(&stdout, seq, &tag, 2, false, Some(&e.to_string()));
                continue;
            }
        };
        fixup_args(&mut qargs);
        if qargs.pattern.is_none() && !qargs.list_files {
            serve_end(&stdout, seq, &tag, 2, false, Some("no pattern given"));
            continue;
        }
        // The same refusal the terminal makes, in the frame's own words: a
        // type the table does not have is a flag the user got wrong, and the
        // server answers the query with the error instead of searching for
        // nothing.
        if let Some(name) = unknown_type_name(&qargs) {
            serve_end(
                &stdout,
                seq,
                &tag,
                2,
                false,
                Some(&unknown_type_error(&name)),
            );
            continue;
        }
        {
            use std::io::Write as _;
            let mut out = stdout.lock();
            writeln!(out, "{{\"rgx\":\"begin\",\"seq\":{seq},\"tag\":\"{tag}\"}}").ok();
            out.flush().ok();
        }
        let mut qout = std::io::stdout();
        match run_query(&qargs, registry, &mut qout, false) {
            Ok(true) => serve_end(&stdout, seq, &tag, 0, true, None),
            Ok(false) => serve_end(&stdout, seq, &tag, 1, false, None),
            Err(e) => serve_end(&stdout, seq, &tag, 2, false, Some(&e.to_string())),
        }
    }
    Ok(())
}

/// Members an archive may enumerate. Matches `Ctx::max_members`,
/// which caps recursion into them; the producers apply this one
/// first, so a member bomb costs bounded work rather than bounded
/// memory.
const MAX_ARCHIVE_MEMBERS: usize = 4096;

// K10 + Windows scaling: mimalloc replaces MSVCRT's HeapAlloc, whose
// global lock serialises 32-worker walks. Per-thread arenas cut the
// contention (measured 5-12% on the corpus benches). Opt-in via the
// `mimalloc` feature (off by default — the variance it adds on this
// machine outweighs the median gain, so the user has to ask for it
// explicitly). The `#[cfg]` block keeps a minimal build from
// pulling the symbol.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    // The engine tally is a property of the whole walk, so it is
    // printed on the way out of `main` rather than by whichever
    // worker happened to be last. Silent by default.
    let out = run();
    engine::stats::report();
    // rg's contract is 0 for a match, 1 for no match, 2 for an error, and
    // AGENTS.md promises the same three. Returning the error from `main`
    // printed it and exited 1 -- the status a script reads as "searched and
    // found nothing" -- so `rgx` with no arguments looked like a search
    // that matched nothing. `{:?}` is the same rendering `Result`'s
    // `Termination` used, error chain included.
    if let Err(e) = out {
        eprintln!("Error: {e:?}");
        std::process::exit(2);
    }
}

/// Print what a store write did, in the shape each one reports it.
fn report_store(
    action: rgx_core::tv_runtime::StoreAction,
    b: &rgx_core::tv_runtime::BuildStats,
    u: Option<&rgx_core::tv_runtime::UpdateStats>,
) {
    match (action, u) {
        (rgx_core::tv_runtime::StoreAction::Updated, Some(u)) => eprintln!(
            "rgx-tv: updated: {} added, {} modified, {} deleted, {} packs written ({} bytes) in {:.2}ms (generation {})",
            u.files_added, u.files_modified, u.files_deleted,
            u.new_packs_written, u.new_bytes_written, u.elapsed_ms, u.new_generation
        ),
        _ => eprintln!(
            "rgx-tv: built {} packs with {} files ({} bytes) in {:.2}ms",
            b.total_packs, b.total_files, b.total_bytes_ingested, b.elapsed_ms
        ),
    }
}

/// `--tv-verify` was a pack-store side-by-side measurement of the
/// in-house and `grep-regex` engines. The grep crates are gone and
/// the in-house engine is the only path, so the comparison has
/// nothing on the other side. The flag is kept as an error rather
/// than deleted so an old script that names it learns from the
/// diagnostic, the same way `--engine grep` and `--engine both`
/// route to the in-house engine with a warning.
fn verify_and_report(_store_dir: &Path, _pattern: &str, _args: &Args) -> Result<()> {
    rgx_core::bail!(
        "--tv-verify is gone: the in-house engine is the only path, and there is no \
         second engine to compare against. Run a normal query on the store instead."
    )
}

/// Build a token index for `args.paths[0]` and write it to the `.ugi`
/// file picked by `--index-store` (or `<root>/.rgx-idx.ugi`).
///
/// The walk is rgx's own: hidden files on by default (`--no-hidden` turns
/// them off), gitignore on by default, follow links off, max depth from
/// `--max-depth`. The
/// index is a flat per-file read: the in-house engine and the
/// adapter registry are not in this path. The index sees the
/// on-disk bytes (the way ripgrep would scan them), and the byte
/// engine confirms the candidate with the adapter-extracted text
/// at query time.
fn build_token_index(args: &Args) -> Result<()> {
    let target = args.index_build.as_deref().unwrap_or(".");
    let store_path = match &args.index_store {
        Some(s) => std::path::PathBuf::from(s),
        None => match &args.index_dir {
            Some(d) => std::path::PathBuf::from(d).join(".rgx-idx.ugi"),
            None => std::path::Path::new(target).join(".rgx-idx.ugi"),
        },
    };
    let case_insensitive = args.ignore_case
        || (args.smart_case
            && !args
                .pattern
                .as_deref()
                .unwrap_or("")
                .chars()
                .any(char::is_uppercase));
    let index = rgx_core::index::TokenIndex::new();
    let mut builder = WalkBuilder::new(target);
    for p in args.paths.iter().skip(1) {
        builder.add(p);
    }
    builder
        .hidden(args.no_hidden)
        .parents(!args.no_ignore)
        .git_ignore(!args.no_ignore)
        .git_global(!args.no_ignore)
        .git_exclude(!args.no_ignore)
        .follow_links(args.follow)
        .max_depth(args.max_depth);
    for g in &args.glob {
        builder.add_glob(g);
    }
    if let Some(tf) = build_type_filter(args) {
        builder.type_filter(tf);
    }
    let target_owned = target.to_string();
    // The walker's `build_parallel` takes an `FnMut` factory that
    // returns a `FnMut` worker, both `'static`. A single mutable
    // `TokenIndex` cannot move into a `'static` factory, so this
    // build path is sequential. The pack-store build is the one
    // that has to be parallel (build cost is on the critical path
    // of every query); the index build is paid once and amortised
    // forever.
    // The same `parse_size` the search path uses. A plain `parse::<u64>`
    // silently fell back to 1 GiB for every spelling with a suffix, so
    // `--index-build` with `-M 100M` indexed gigabytes the limit excluded.
    let max = parse_size(&args.max_filesize)?;
    let walker = builder.build_parallel();
    let index = std::sync::Arc::new(std::sync::Mutex::new(index));
    let index_w = std::sync::Arc::clone(&index);
    let walked_w = std::sync::Arc::new(std::sync::Mutex::new(0u64));
    let walked_w_c = std::sync::Arc::clone(&walked_w);
    let bytes_w = std::sync::Arc::new(std::sync::Mutex::new(0u64));
    let bytes_w_c = std::sync::Arc::clone(&bytes_w);
    walker.run(move || {
        let index = std::sync::Arc::clone(&index_w);
        let walked = std::sync::Arc::clone(&walked_w_c);
        let bytes = std::sync::Arc::clone(&bytes_w_c);
        Box::new(move |entry| {
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                return WalkState::Continue;
            }
            let path = entry.path().to_string_lossy().into_owned();
            if let Ok(meta) = entry.metadata() {
                if meta.len() > max {
                    return WalkState::Continue;
                }
            } else {
                return WalkState::Continue;
            }
            let data = match std::fs::read(entry.path()) {
                Ok(d) if d.len() as u64 <= max => d,
                _ => return WalkState::Continue,
            };
            let mut idx = index.lock().expect("index");
            let file_id = idx.intern_path(&path);
            idx.add_text(file_id, &data, case_insensitive);
            drop(idx);
            *walked.lock().expect("walked") += 1;
            *bytes.lock().expect("bytes") += data.len() as u64;
            WalkState::Continue
        })
    });
    let index = std::sync::Arc::try_unwrap(index)
        .map_err(|_| rgx_core::Error::msg("rgx: index Arc not uniquely owned after walk"))?
        .into_inner()
        .map_err(|_| rgx_core::Error::msg("rgx: index Mutex poisoned after walk"))?;
    let walked = *walked_w.lock().expect("walked");
    let _bytes_indexed = *bytes_w.lock().expect("bytes");
    let mut buf = Vec::new();
    rgx_core::index_io::save(&index, case_insensitive, &mut buf);
    if let Some(parent) = store_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                rgx_core::Error::msg(format!(
                    "rgx: cannot create {} for the index file: {e}",
                    parent.display()
                ))
            })?;
        }
    }
    std::fs::write(&store_path, &buf).map_err(|e| {
        rgx_core::Error::msg(format!("rgx: cannot write {}: {e}", store_path.display()))
    })?;
    eprintln!(
        "rgx: wrote {} bytes of index ({} files, {} tokens, {} postings, case_insensitive={}) to {}",
        buf.len(),
        walked,
        index.token_count(),
        index.posting_count(),
        case_insensitive,
        store_path.display()
    );
    // Reference target_owned so the borrow checker is happy if the
    // closure ever wants to take it again; the println below is
    // otherwise the only read.
    let _ = target_owned;
    Ok(())
}

/// The sink the pipeline hands the facts of every file to.
///
/// The pipeline runs on several threads, so the sink owns a mutex and the
/// records come out in the order the threads finished rather than in the
/// order the walk found them. The index is sorted before it is written,
/// so the file is the same whatever the thread count was.
struct FactsCollector {
    records: Mutex<Vec<rgx_core::facts_index::Record>>,
}

impl FactsCollector {
    fn new() -> Self {
        FactsCollector {
            records: Mutex::new(Vec::new()),
        }
    }

    /// The records, sorted by path.
    fn take(&self) -> Vec<rgx_core::facts_index::Record> {
        let mut records = self.records.lock().expect("facts");
        records.sort_by(|a, b| a.path.cmp(&b.path));
        std::mem::take(&mut *records)
    }
}

impl rgx_core::FactsSink for FactsCollector {
    fn record(&self, path: &str, facts: Vec<rgx_core::Field>) {
        self.records
            .lock()
            .expect("facts")
            .push(rgx_core::facts_index::Record::new(path, facts));
    }
}

/// Where the facts index lives for a given root.
///
/// The default is `<root>/.rgx-facts.jsonl`: a dotfile in the corpus, so
/// it does not show up in the corpus's own file list, and a name that says
/// what it is.
fn facts_store_path(root: &str, store: Option<&str>) -> std::path::PathBuf {
    match store {
        Some(s) => std::path::PathBuf::from(s),
        None => std::path::Path::new(root).join(".rgx-facts.jsonl"),
    }
}

/// Build the persistent index of the facts of every file under a
/// directory, and exit.
///
/// The walk is rgx's own, exactly as `--index-build`'s is: hidden files on
/// by default (`--no-hidden` turns them off), gitignore on by default,
/// follow links off, max depth from `--max-depth`.
///
/// **What the index holds.** One record per path, with the facts the
/// pipeline computed for it: the path, the extension, the format, the
/// MIME type, the language, and whatever the adapter that answered
/// reported. A member of an archive gets its own record, with the
/// container's facts inherited — the same facts the filter saw.
///
/// **What the index does not hold.** The file's bytes, and the file's
/// modification time. The stamp is what says whether a record is still
/// worth answering from; the bytes are what a search reads, and they are
/// read from the file, not from the index. An index that held the bytes
/// would be a second copy of the corpus, and a stale one.
fn build_facts_index(args: &Args) -> Result<()> {
    let target = args.facts_build.as_deref().unwrap_or(".");
    let store_path = facts_store_path(target, args.facts_store.as_deref());
    let max = parse_size(&args.max_filesize)?;
    let registry = Arc::new(registry());
    let collector = Arc::new(FactsCollector::new());

    // The context the pipeline runs under. The filter is `None` on
    // purpose: the index is the corpus's facts, and a file the filter
    // would have rejected is still a file the index has to know about.
    // The sink is what makes the pipeline assemble the facts at all.
    let ctx = Arc::new(Ctx {
        max_depth: args.max_adapter_depth,
        max_members: MAX_ARCHIVE_MEMBERS,
        max_file_size: max as usize,
        filter: None,
        facts_sink: Some(Arc::clone(&collector) as Arc<dyn rgx_core::FactsSink>),
    });

    let mut builder = WalkBuilder::new(target);
    for p in args.paths.iter().skip(1) {
        builder.add(p);
    }
    builder
        .hidden(args.no_hidden)
        .parents(!args.no_ignore)
        .git_ignore(!args.no_ignore)
        .git_global(!args.no_ignore)
        .git_exclude(!args.no_ignore)
        .follow_links(args.follow)
        .max_depth(args.max_depth);
    for g in &args.glob {
        builder.add_glob(g);
    }
    if let Some(tf) = build_type_filter(args) {
        builder.type_filter(tf);
    }

    // The facts are stamped with the file's size and modification time
    // as the walk sees them, so that a later query can tell a record
    // that is still true from one that is not. The stamp is taken from
    // the walk's own metadata, not from a second `stat`: the walk
    // already paid for it.
    let stamps: Arc<Mutex<std::collections::HashMap<String, (u64, i64)>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let stamps_w = Arc::clone(&stamps);
    let registry_w = Arc::clone(&registry);
    let ctx_w = Arc::clone(&ctx);
    let walker = builder.build_parallel();
    let walked = Arc::new(Mutex::new(0u64));
    let walked_w = Arc::clone(&walked);
    walker.run(move || {
        let registry = Arc::clone(&registry_w);
        let ctx = Arc::clone(&ctx_w);
        let stamps = Arc::clone(&stamps_w);
        let walked = Arc::clone(&walked_w);
        Box::new(move |entry| {
            if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                return WalkState::Continue;
            }
            let path = entry.path().to_string_lossy().into_owned();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => return WalkState::Continue,
            };
            if meta.len() > max {
                return WalkState::Continue;
            }
            let data = match std::fs::read(entry.path()) {
                Ok(d) if d.len() as u64 <= max => d,
                _ => return WalkState::Continue,
            };
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            stamps
                .lock()
                .expect("stamps")
                .insert(path.clone(), (meta.len(), mtime));
            // The pipeline is run for the facts alone. The units it
            // produces are dropped: the index is about what the files
            // ARE, not about what they contain, and the bytes are read
            // again by the search that follows.
            let mut out = Vec::new();
            rgx_core::process(&registry, &path, &data, 0, &ctx, &mut out);
            *walked.lock().expect("walked") += 1;
            WalkState::Continue
        })
    });

    let mut index = rgx_core::facts_index::FactsIndex::new();
    let mut records = collector.take();
    let stamps = stamps.lock().expect("stamps");
    for record in records.iter_mut() {
        // The stamp belongs to the file on disk, which for a member of
        // an archive is the container: the member has no file of its
        // own, and the container is what changed when its bytes did.
        let file = match record.path.find('!') {
            Some(i) => &record.path[..i],
            None => record.path.as_str(),
        };
        if let Some((size, mtime)) = stamps.get(file) {
            record.size = *size;
            record.mtime = *mtime;
        }
    }
    drop(stamps);
    index.records = records;

    let text = index.to_jsonl().map_err(|e| {
        rgx_core::Error::msg(format!("rgx: the facts index cannot be written: {e}"))
    })?;
    if let Some(parent) = store_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                rgx_core::Error::msg(format!(
                    "rgx: cannot create {} for the facts index: {e}",
                    parent.display()
                ))
            })?;
        }
    }
    std::fs::write(&store_path, text.as_bytes()).map_err(|e| {
        rgx_core::Error::msg(format!("rgx: cannot write {}: {e}", store_path.display()))
    })?;
    eprintln!(
        "rgx: wrote {} records ({} files walked) to {}",
        index.records.len(),
        *walked.lock().expect("walked"),
        store_path.display()
    );
    Ok(())
}

/// Answer a `--filter` from the persistent facts index, without walking
/// the corpus.
///
/// **What this answers.** The same question `--filter` asks during a
/// walk, asked of the facts that were kept: which paths have facts that
/// satisfy the expression. The filter's grammar is the filter's grammar
/// — there is one query language over the facts, not two.
///
/// **What this does not do.** It does not search. The index holds facts,
/// not text: the answer is which files carry the facts, and the search
/// that follows is the search that reads the bytes.
///
/// **The staleness rule.** A record whose file no longer has the size and
/// the modification time the record was taken at is stale, and a stale
/// record does not answer. Saying so is the honest answer: the index
/// knows what the file was, and the file is not that any more.
fn query_facts_index(args: &Args, index_dir: &str) -> Result<()> {
    let store_path = facts_store_path(index_dir, args.facts_store.as_deref());
    let text = std::fs::read_to_string(&store_path).map_err(|e| {
        rgx_core::Error::msg(format!(
            "rgx: cannot read the facts index {}: {e}",
            store_path.display()
        ))
    })?;
    let index = rgx_core::facts_index::FactsIndex::from_jsonl(&text).map_err(|e| {
        rgx_core::Error::msg(format!(
            "rgx: {} is not a readable facts index: {e}",
            store_path.display()
        ))
    })?;

    let filter = filter_of(args)?;
    let out = std::io::stdout();
    let mut out = out.lock();
    let mut matched = 0usize;
    let mut stale = 0usize;
    for record in &index.records {
        // The staleness check costs a `stat` per record, and the point
        // of the index is to answer without the walk. A record whose
        // file moved is reported as stale rather than answered: a
        // filter that matched a file that has since changed is a
        // filter that answered about a file that is not there.
        let file = match record.path.find('!') {
            Some(i) => &record.path[..i],
            None => record.path.as_str(),
        };
        if let Ok(meta) = std::fs::metadata(file) {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            if !record.is_fresh(meta.len(), mtime) {
                stale += 1;
                continue;
            }
        }
        let keep = match &filter {
            None => true,
            Some(f) => rgx_core::filter::matches(&f.expr, &record.facts),
        };
        if keep {
            let _ = writeln!(out, "{}", record.path);
            matched += 1;
        }
    }
    let _ = out.flush();
    if stale > 0 {
        eprintln!(
            "rgx: {} of {} records are stale and were not answered",
            stale,
            index.records.len()
        );
    }
    std::process::exit(if matched > 0 { 0 } else { 1 });
}

/// Write the facts index to a file as JSON Lines, and exit.
///
/// The export is the index's own format: a copy of the index under
/// another name. That is deliberate — an export in a format only rgx
/// reads would be a way to move facts that only rgx can then use, and
/// JSON Lines is read by everything.
fn export_facts_index(args: &Args) -> Result<()> {
    let source = match (&args.facts_index, &args.facts_build) {
        (Some(dir), _) => facts_store_path(dir, args.facts_store.as_deref()),
        (None, Some(dir)) => facts_store_path(dir, args.facts_store.as_deref()),
        (None, None) => {
            rgx_core::bail!("--facts-export needs --facts-index (the directory holding the index)")
        }
    };
    let destination = args.facts_export.as_deref().unwrap_or("");
    let text = std::fs::read_to_string(&source).map_err(|e| {
        rgx_core::Error::msg(format!(
            "rgx: cannot read the facts index {}: {e}",
            source.display()
        ))
    })?;
    // The index is validated before it is copied: an export that carries
    // a broken index forward is an export that breaks the next reader
    // too.
    rgx_core::facts_index::FactsIndex::from_jsonl(&text).map_err(|e| {
        rgx_core::Error::msg(format!(
            "rgx: {} is not a readable facts index: {e}",
            source.display()
        ))
    })?;
    std::fs::write(destination, text.as_bytes())
        .map_err(|e| rgx_core::Error::msg(format!("rgx: cannot write {destination}: {e}")))?;
    Ok(())
}

/// Answer a query through the token index at `<index_dir>/.rgx-idx.ugi`
/// (or the file the operator named with `--index-store`).
///
/// The flow is: tokenize the query, intersect the posting lists, group
/// the candidates by file, read each file once, walk its lines, and
/// for every candidate `(file_id, line)` re-run the in-house byte
/// regex on that line. The index narrows "which lines are worth
/// looking at" from every line in the corpus to the small set that
/// carries every token in the query; the regex confirms "this line
/// actually matches the full pattern, with whatever metacharacters
/// were in it" -- the index is an inverted view, not a duplicate of
/// the corpus.
fn query_with_index(args: &Args, index_dir: &str) -> Result<()> {
    let pattern = args.pattern.as_deref().unwrap_or("");
    let ugi_path = match &args.index_store {
        Some(s) => std::path::PathBuf::from(s),
        None => std::path::Path::new(index_dir).join(".rgx-idx.ugi"),
    };
    let bytes = std::fs::read(&ugi_path).map_err(|e| {
        rgx_core::Error::msg(format!("rgx: cannot read {}: {e}", ugi_path.display()))
    })?;
    let case_insensitive =
        args.ignore_case || (args.smart_case && !pattern.chars().any(char::is_uppercase));
    let index = rgx_core::index_io::load(&bytes, case_insensitive).map_err(|e| {
        rgx_core::Error::msg(format!(
            "rgx: cannot load index {}: {e}",
            ugi_path.display()
        ))
    })?;
    let candidates = index.candidates(pattern.as_bytes(), case_insensitive);
    eprintln!(
        "rgx: index query: pattern={pattern:?} ci={case_insensitive} candidates={}",
        candidates.len()
    );
    if candidates.is_empty() {
        return Ok(());
    }
    // Group candidate lines by file id so the per-file read happens
    // once even when the same file has many candidate lines. The
    // bucket is a `BTreeMap` so the output is sorted by file id
    // (and therefore by the order the index inserted the paths),
    // which is the same ordering rgx's main path uses.
    let mut by_file: std::collections::BTreeMap<u32, Vec<u32>> = std::collections::BTreeMap::new();
    for p in &candidates {
        by_file.entry(p.file_id).or_default().push(p.line);
    }
    // Parallel read + confirm: each file is read whole and walked once.
    // The thread count matches the corpus size: too few threads leaves
    // cores idle, too many wastes context switches on a single read per
    // file. `available_parallelism` is right for both ends; clamping to
    // `by_file.len()` keeps us from spinning up idle workers when the
    // index has fewer candidate files than threads.
    let job_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(by_file.len())
        .max(1);
    let (tx, rx) = std::sync::mpsc::channel::<(u32, Vec<(u32, Vec<u8>)>)>();
    let by_file_for_workers: Vec<(u32, Vec<u32>)> =
        by_file.iter().map(|(k, v)| (*k, v.clone())).collect();
    // Materialise the per-file paths so the workers don't borrow `index`.
    // `index.file_path` allocates a `String` per call, and a single
    // upfront resolve is cheaper than N resolves inside `claim()`.
    let file_paths: Vec<(u32, String)> = by_file_for_workers
        .iter()
        .filter_map(|(id, _)| index.file_path(*id).map(|p| (*id, p.to_string())))
        .collect();
    std::thread::scope(|s| {
        let chunk = (by_file_for_workers.len() + job_count - 1) / job_count.max(1);
        for slice in by_file_for_workers.chunks(chunk.max(1)) {
            let tx = tx.clone();
            let paths_for_slice: Vec<(u32, &str)> = slice
                .iter()
                .filter_map(|(id, _)| {
                    file_paths
                        .iter()
                        .find(|(fid, _)| fid == id)
                        .map(|(_, p)| (*id, p.as_str()))
                })
                .collect();
            let lines_for_slice: Vec<(u32, Vec<u32>)> = slice.to_vec();
            let pattern_bytes = pattern.as_bytes().to_vec();
            s.spawn(move || {
                // Each worker rebuilds the byte regex. The build is one
                // NFA+VM compile per thread (job_count, not per file),
                // which keeps the work proportional to the thread count
                // and not to the candidate file count.
                let byte =
                    match rgx_core::regex::ByteRegex::new_flags(&pattern_bytes, case_insensitive) {
                        Ok(b) => b,
                        Err(_) => return,
                    };
                for (file_id, path) in paths_for_slice {
                    let lines = match lines_for_slice.iter().find(|(fid, _)| *fid == file_id) {
                        Some((_, l)) => l,
                        None => continue,
                    };
                    let data = match std::fs::read(path) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };
                    // `lines` came from the index, which is built with a
                    // single 1-based line convention; build a set so a
                    // file with several candidate lines on the same line
                    // number (different tokens of the query matching
                    // different instances of the same line) does not
                    // produce a duplicate re-scan.
                    let wanted: std::collections::BTreeSet<u32> = lines.iter().copied().collect();
                    let mut current_line: u32 = 1;
                    let mut line_start: usize = 0;
                    let mut hits: Vec<(u32, Vec<u8>)> = Vec::new();
                    for (i, &b) in data.iter().enumerate() {
                        if b == b'\n' {
                            if wanted.contains(&current_line)
                                && byte.is_match_at(&data[line_start..i], 0)
                            {
                                hits.push((current_line, data[line_start..i].to_vec()));
                            }
                            current_line += 1;
                            line_start = i + 1;
                        }
                    }
                    if line_start < data.len()
                        && wanted.contains(&current_line)
                        && byte.is_match_at(&data[line_start..], 0)
                    {
                        hits.push((current_line, data[line_start..].to_vec()));
                    }
                    if !hits.is_empty() {
                        let _ = tx.send((file_id, hits));
                    }
                }
            });
        }
    });
    // `thread::scope` has returned: every worker is gone. Their sender
    // clones are gone too. The original `tx` is now the only sender; drop
    // it so the channel closes and `while let Ok(...)` below terminates.
    drop(tx);
    // Collect results in file_id order. The mpsc receiver drains in
    // worker-finish order, so an explicit BTreeMap preserves the
    // index-insertion order that the original single-threaded loop
    // produced.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut collected: std::collections::BTreeMap<u32, Vec<(u32, Vec<u8>)>> =
        std::collections::BTreeMap::new();
    while let Ok((file_id, hits)) = rx.recv() {
        collected.insert(file_id, hits);
    }
    for (file_id, hits) in &collected {
        let path = match index.file_path(*file_id) {
            Some(p) => p,
            None => continue,
        };
        for (line, _line_bytes) in hits {
            let _ = writeln!(out, "{path}:{line}:");
        }
    }
    Ok(())
}

/// Run the in-house byte regex on `line` and, on a hit, write a
/// `path:line:` line to `out`. The slice passed in is the line's
/// content with the trailing `\n` already stripped; the regex sees
/// it the same way the engine's slice path would on the same bytes.
#[allow(dead_code)]
fn confirm_and_print(
    byte: &rgx_core::regex::ByteRegex,
    path: &str,
    line: u32,
    line_bytes: &[u8],
    out: &mut std::io::StdoutLock,
) {
    if byte.is_match_at(line_bytes, 0) {
        let _ = writeln!(out, "{path}:{line}:");
    }
}

fn run() -> Result<()> {
    let mut args = Args::parse();
    // Ahead of everything else: both print and exit, and neither takes a
    // pattern, so they cannot be confused for a search.
    if let Some(shell) = &args.completions {
        let Some(shell) = Shell::from_name(shell) else {
            rgx_core::bail!("--completions: no generator for {shell}");
        };
        print!("{}", generate_completion(&app(), shell));
        return Ok(());
    }
    if args.serve {
        if args.pattern.is_some() || !args.paths.is_empty() {
            rgx_core::bail!(
                "--serve takes no query of its own; queries arrive on stdin, one JSON argv-array per line"
            );
        }
        if args.pick {
            rgx_core::bail!(
                "--serve and --pick cannot be combined: --serve owns stdin and never exits"
            );
        }
        let registry = Arc::new(registry());
        return serve(&registry);
    }
    if args.mcp {
        if args.serve {
            rgx_core::bail!(
                "--mcp and --serve cannot be combined: both speak a protocol on stdin, and only one of them can own it"
            );
        }
        if args.pattern.is_some() || !args.paths.is_empty() {
            rgx_core::bail!(
                "--mcp takes no query of its own; requests arrive on stdin, one JSON-RPC object per line"
            );
        }
        if args.pick {
            rgx_core::bail!(
                "--mcp and --pick cannot be combined: --mcp owns stdin and never exits"
            );
        }
        let registry = Arc::new(registry());
        return mcp_serve(&registry, &args);
    }
    fixup_args(&mut args);
    reject_uncompilable_pattern(&args);
    // A type the table does not have is a flag the user got wrong, and rg
    // refuses it rather than searching for nothing.
    if let Some(name) = unknown_type_name(&args) {
        eprintln!("rgx: {}", unknown_type_error(&name));
        std::process::exit(2);
    }
    if args.cache_clear || args.cache_prune {
        let dir = cache::locate(args.cache.as_deref())?;
        let (removed, freed) = if args.cache_clear {
            cache::clear(&dir)?
        } else {
            cache::prune(
                &dir,
                std::time::Duration::from_secs(args.cache_max_age as u64 * 86_400),
                cache::MAX_BYTES,
            )?
        };
        eprintln!(
            "rgx: {removed} cache entries removed from {} ({freed} bytes)",
            dir.display()
        );
        return Ok(());
    }
    if args.type_list {
        // Print the registered type table after applying any --type-add /
        // --type-clear, then exit. The walker is not involved.
        let filter = build_type_filter(&args)
            .unwrap_or_else(|| walk::TypeFilter::new(type_db::TypeDb::with_defaults(), Vec::new()));
        for name in filter.db().type_names() {
            println!("{name}");
        }
        return Ok(());
    }
    if args.tv_build {
        let target = args.paths.first().map(|s| s.as_str()).unwrap_or(".");
        let store_dir = match &args.tv_store {
            Some(s) => std::path::PathBuf::from(s),
            None => std::path::Path::new(target).join(".rgx-tv"),
        };
        let cfg = rgx_core::tv_runtime::BuildConfig {
            follow_symlinks: args.follow,
            hidden: !args.no_hidden,
            gitignore: !args.no_ignore,
            // Same three as the auto-build path above; see the note there.
            parents: !args.no_ignore,
            max_depth: args.max_depth,
            globs: args.glob.clone(),
            ..Default::default()
        };
        eprintln!(
            "rgx: building pack store for '{}' -> '{}'...",
            target,
            store_dir.display()
        );
        let reg_for_ext = Arc::new(registry());
        let ctx_for_ext = Arc::new(Ctx::default());
        let units = pipeline_units(Arc::clone(&reg_for_ext), Arc::clone(&ctx_for_ext));
        let units_for_sign = pipeline_units(Arc::clone(&reg_for_ext), Arc::clone(&ctx_for_ext));
        let signer = move |rel: &str, data: &[u8]| -> Vec<Vec<u8>> {
            units_for_sign(rel, data)
                .unwrap_or_default()
                .into_iter()
                .map(|(_, b)| b)
                .collect()
        };
        let ext_ref: Option<&rgx_core::tv_runtime::PreExtractor> = if args.tv_pre_extract {
            Some(&units)
        } else {
            None
        };
        let sign_ref: Option<&rgx_core::tv_runtime::UnitSigner> = Some(&signer);
        let extract_fp = extract_fingerprint(&ctx_for_ext, &reg_for_ext);
        let (act, b, u) = rgx_core::tv_runtime::build_or_update_store_with_extractor(
            Path::new(target),
            &store_dir,
            &cfg,
            ext_ref,
            sign_ref,
            extract_fp,
        )?;
        report_store(act, &b, u.as_ref());
        return Ok(());
    }
    if let Some(pattern) = args.tv_verify.clone() {
        let target = args.paths.first().map(|s| s.as_str()).unwrap_or(".");
        let store_dir = match &args.tv_store {
            Some(s) => std::path::PathBuf::from(s),
            None => std::path::Path::new(target).join(".rgx-tv"),
        };
        return verify_and_report(&store_dir, &pattern, &args);
    }
    if args.index_build.is_some() {
        return build_token_index(&args);
    }
    if let Some(index_dir) = args.index_dir.clone() {
        return query_with_index(&args, &index_dir);
    }
    if args.facts_build.is_some() {
        return build_facts_index(&args);
    }
    if let Some(index_dir) = args.facts_index.clone() {
        if args.facts_export.is_some() {
            return export_facts_index(&args);
        }
        return query_facts_index(&args, &index_dir);
    }
    if args.facts_export.is_some() {
        return export_facts_index(&args);
    }
    if args.pattern.is_none() && !args.list_files {
        rgx_core::bail!(
            "no pattern given (usage: rgx [OPTIONS] PATTERN [PATHS...], or rgx --files)"
        );
    }
    let registry = Arc::new(registry());
    if args.pick {
        let query = args.clone();
        let reg = Arc::clone(&registry);
        let req = pick::Request {
            args: &args.fzf_args,
            binary: args.fzf_binary.as_deref(),
        };
        let code = match pick::pick(Box::new(move |w| run_query(&query, &reg, w, true)), &req) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("error: {e:#}");
                2
            }
        };
        engine::stats::report();
        std::process::exit(code);
    }
    let mut out = std::io::stdout();
    let any = run_query(&args, &registry, &mut out, true)?;
    // Reported here as well as in `main`: the exit status of a grep-shaped tool
    // is the matched/not-matched bit, and it leaves through `process::exit`,
    // which does not run the tail of `main`.
    engine::stats::report();
    // Here rather than at the end of `main`: the exit status leaves through
    // `process::exit`, which does not run the tail of `main`, so a report
    // placed there never prints.
    let mask = rgx_core::maskstats::snapshot();
    if !mask.is_empty() {
        eprintln!("{}", mask.summary());
    }
    if args.cache.is_some() {
        eprintln!("{}", cache::Cache::summary());
    }
    // Off unless `RGX_WALK_STATS` is set, and never part of a published
    // timing: it exists to tell a per-pattern COMPILE from a per-entry
    // MATCH, which the end-to-end numbers draw identically.
    walk::print_walk_stats();
    // `--files` short-circuits to the listing path that bypasses
    // the central printer (the DirectBatcher writes to stdout
    // directly); the printer's `any` flag never gets set even when
    // paths were printed, so exit 0 explicitly on that branch.
    std::process::exit(if any || args.list_files { 0 } else { 1 });
}

static READ_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static PROC_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SEARCH_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
mod tests {
    use super::*;

    fn found(path: &str, via: &'static str) -> rgx_core::Found {
        rgx_core::Found {
            path: path.into(),
            bytes: b"line
"
            .to_vec(),
            via,
        }
    }

    fn args_of(argv: &[&str]) -> Args {
        Args::parse_from(argv).expect("args")
    }

    const FILE: &str = "dir/report.pdf";

    /// The rule `unit_searcher` encodes, as the invariant it is: a unit the
    /// adapter chain produced is searched without binary detection, and the
    /// file's own bytes are searched with it.
    ///
    /// It is the loss of a whole file that this exists to prevent. `Quit`
    /// reports *nothing* once a NUL sits in the first 64 KiB -- not the lines
    /// before it -- so a single NUL in a rendered field removed a `.crt` from
    /// `-c`, from `-l` and from the exit status on a file `rg` had counted.
    /// The container being binary says nothing about the text describing it.
    ///
    /// The discriminator is the path, not `via`, and the last row is why.
    /// `brotli_big_q0.br` decompresses to 120,552 bytes with its first NUL at
    /// offset 305, and `process` hands those bytes back labelled `"raw"`
    /// because no adapter claims an extensionless member name. Judged by `via`
    /// they were the file's own bytes; judged by path they are what came out
    /// of the container, which is the whole distinction.
    #[test]
    fn adapter_text_is_searched_without_binary_detection() {
        let mut raw = RawState::new(&args_of(&["rgx", "needle"]));
        for (unit, want) in [
            (
                found("dir/report.crt", "x509"),
                engine::RgxBinaryDetection::None,
            ),
            (
                found("dir/page.html", "html"),
                engine::RgxBinaryDetection::None,
            ),
            (
                found("dir/deck.pptx", "office"),
                engine::RgxBinaryDetection::None,
            ),
            // what a single-file decompressor produces: `via` says "raw",
            // the path says otherwise, and the path is right
            (
                found("dir/big.br/big", "raw"),
                engine::RgxBinaryDetection::None,
            ),
            // the file's own bytes, either as the passthrough or as the
            // original beside an adapter-failure note
            (found(FILE, "raw"), engine::RgxBinaryDetection::Quit(0)),
        ] {
            assert_eq!(
                unit_searcher(&mut raw, &unit, FILE, false).binary_detection(),
                want,
                "path={}: the wrong searcher, so the wrong binary rule",
                unit.path
            );
        }
    }

    /// A NUL anywhere in adapter text is exactly the case the rule is for,
    /// and the count has to survive it. `rg -c` on a certificate carrying a
    /// zero-address SAN printed a number; rgx printed nothing.
    #[test]
    fn a_nul_in_adapter_text_still_counts() {
        let args = args_of(&["rgx", "-c", "needle"]);
        let bytes = b"head needle\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\ntail needle\n";
        let byte = Arc::new(ByteRegex::new(b"needle").unwrap());
        let mut raw = RawState::new(&args);

        let mut sink = HitSink::new(&args, Some(byte.clone()));
        unit_searcher(&mut raw, &found("dir/report.crt", "x509"), FILE, false)
            .search_slice(bytes, &mut sink)
            .unwrap();
        assert_eq!(sink.count, 2, "the NUL ate the file");
        assert!(!sink.binary, "adapter text is not the container");

        // the same bytes as the file's own are still binary, and still cut
        let mut sink = HitSink::new(&args, Some(byte));
        unit_searcher(&mut raw, &found(FILE, "raw"), FILE, false)
            .search_slice(bytes, &mut sink)
            .unwrap();
        assert_eq!(sink.count, 0, "the file's own bytes keep the NUL rule");
    }

    /// A path the user NAMED is searched as text, and rg's rule for it is
    /// `convert`: the whole buffer, the NUL reported instead of ending the
    /// search. The unit path has to draw the same line as the raw path,
    /// because a file that carries a note beside its bytes is searched
    /// there -- and `rg -c` on a named binary file counts it, so rgx that
    /// dropped it would answer differently from rg on the same file.
    #[test]
    fn a_named_binary_file_is_searched_as_text() {
        let args = args_of(&["rgx", "needle"]);
        let bytes = b"head needle\n\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\ntail needle\n";
        let byte = Arc::new(ByteRegex::new(b"needle").unwrap());
        let mut raw = RawState::new(&args);

        let mut sink = HitSink::new(&args, Some(byte));
        unit_searcher(&mut raw, &found(FILE, "raw"), FILE, true)
            .search_slice(bytes, &mut sink)
            .unwrap();
        assert_eq!(sink.count, 2, "a named binary file is searched as text");
        assert!(sink.binary, "and the NUL is reported, not obeyed");
    }

    /// `--json` per-file `end` stats belong to the file they close, and
    /// `bytes_searched` is the size the producer stamped -- not a stat the
    /// printer re-derives per matched file.
    ///
    /// The printer's `Msg::Hit` arm used to add a hit's counters BEFORE
    /// `print_json`, which resets them whenever the path changes: file A's
    /// `end` carried A's numbers plus B's, and the last file's `end` carried
    /// an empty `stats`. `tests/cli.rs` asserted only that the `stats` KEY
    /// was present, so the shift was invisible to the suite.
    #[test]
    fn json_end_stats_belong_to_the_file_they_close() {
        let args = args_of(&["rgx", "needle", "--json"]);
        let mut out: Vec<u8> = Vec::new();
        let mut open = String::new();
        let mut st = JsonStats::default();
        let mut bin: Option<u64> = None;
        let mut total = JsonStats::default();

        // Two files of DIFFERENT sizes so a shift shows up in the numbers,
        // each stamped the way `raw_search` stamps the walk's `meta.len()`.
        for (path, len) in [("a.txt", 11u64), ("b.txt", 22u64)] {
            let mut sink = HitSink::new(&args, HitSink::build_byte(&args));
            let mut searcher = make_searcher(&args);
            searcher.search_slice(b"needle one\n", &mut sink).unwrap();
            let mut hit = sink.take_hit(|| path.to_string(), "raw").expect("a hit");
            hit.bytes_searched = Some(len);
            print_json(&mut out, &hit, &mut open, &mut st, &mut bin, &mut total);
        }
        json_end(&mut out, &open, bin, &st);
        total.merge(&st);

        let text = String::from_utf8_lossy(&out);
        let ends: Vec<_> = text
            .lines()
            .filter_map(|l| rgx_core::djson::parse(l).ok())
            .filter(|a| {
                let v = a.root();
                v.get(a, "type").and_then(|t| t.as_str(a)) == Some("end")
            })
            .collect();
        assert_eq!(ends.len(), 2, "one end per file: {text}");
        for (arena, (want_path, want_len)) in ends.iter().zip([("a.txt", 11u64), ("b.txt", 22u64)])
        {
            let v = arena.root();
            let d = v.get(arena, "data").expect("end has data");
            let p = d.get(arena, "path").expect("data.path");
            assert_eq!(
                p.get(arena, "text").and_then(|t| t.as_str(arena)),
                Some(want_path),
                "end record order: {text}"
            );
            let s = d.get(arena, "stats").expect("end has stats");
            assert_eq!(
                s.get(arena, "searches").and_then(|n| n.as_u64()),
                Some(1),
                "{want_path} searches: {text}"
            );
            assert_eq!(
                s.get(arena, "searches_with_match").and_then(|n| n.as_u64()),
                Some(1),
                "{want_path} searches_with_match: {text}"
            );
            assert_eq!(
                s.get(arena, "bytes_searched").and_then(|n| n.as_u64()),
                Some(want_len),
                "{want_path} bytes_searched: {text}"
            );
        }
        // The summary is the sum of both files, never one file counted twice.
        assert_eq!(total.searches, 2, "{text}");
        assert_eq!(total.bytes_searched, 33, "{text}");
    }
}
