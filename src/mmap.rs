// SPDX-License-Identifier: Apache-2.0

//! Memory-mapped file access (K10).
//!
//! **What it buys is platform-split, and both sides are measured.** On
//! Windows a mapping loses: ~12% slower end to end, and the zero-copy
//! shape - the mapping handed to the searcher as a slice - is the worst row
//! of the fill harness (13.2 ms against 9.0 for `ReadFile` plus scan),
//! because a user mapping faults every page through soft fault handling
//! while `ReadFile` faults the same pages in kernel context and hands over
//! a buffer that is warm for every later pass. On Linux the ordering
//! reverses exactly as the table in `enabled_by_env` predicted it might: a
//! warm `read()` still pays `copy_to_user` per byte (40 ms of a 64 ms
//! zero-match floor over the 246 MB single-file probe) and soft faults are
//! an order of magnitude cheaper, so `Searcher::search_windows` -- the
//! mapping searched in place, no copy -- beats the rolling-buffer read on
//! every row of that probe. `should_map` therefore defaults to mapped on
//! Linux and to read everywhere else, with `RGX_MMAP` overriding both ways.
//!
//! **The automatic promotion exists on that one platform.**
//! `AUTO_MMAP_THRESHOLD` is still declared and still carries the
//! measurement table that removed the old promotion -- that table is about
//! mapping-AND-copying, which paid nothing on either arm, and it remains
//! the reason no size between `MAP_THRESHOLD` and that number is worth the
//! question. What promotes today is `should_map`, and what it promotes on
//! is Linux.
//!
//! **Why a mapping is not just a faster `read`.** It is a promise about the
//! file: every byte in it was inside the file when the mapping was made. Break
//! that promise — truncate the file — and touching a page past the new end of
//! file is not an error return, it is a fault: `SIGBUS` on Linux, an access
//! violation on Windows. `memmap2` says so on both `as_ptr` and `len` and
//! does not check for you. So the buffer boundary that made short reads safe
//! is gone, and that is the whole risk of this module.
//!
//! Every slice this module hands out is therefore clipped to a *verified*
//! length, `MappedFile::live_len`: the mapping's length, an optional
//! caller-imposed limit, and the file's length as the OS reports it now,
//! re-queried from the same open handle before each fill. A truncation before
//! the fill becomes a short read and then EOF, exactly what an ordinary reader
//! sees. What is left is the window between the query and the `memcpy` — a
//! sub-microsecond race that cannot be closed without giving the mapping up —
//! and it is stated here rather than claimed away.
//!
//! **Windows is different, and the difference runs both ways.** Truncating a
//! file with an open section is refused outright: `SetEndOfFile` fails with
//! `ERROR_USER_MAPPED_FILE` (1224). So the concurrent-truncation crash this
//! module is built around cannot happen against *this* mapping — and cannot be
//! tested there, which is why the truncation tests drive the same code through
//! an injected limit as well. The other difference is per-file cost: a mapping
//! is two kernel objects (`CreateFileMappingW` plus `MapViewOfFile`) against
//! Linux's single `mmap(2)`, which is why `worth_mapping` sets a floor — below
//! one search buffer there is nothing to win back and the setup is pure cost.

// The module's whole surface is exercised by its own tests. The parts rgx
// calls today are the whole-file mapping, its length, and the reader; the rest
// -- a partial mapping, and a caller-imposed ceiling -- is the rest of the K10
// contract ("handle partial mappings and files whose size changes while
// mapped"), kept and tested rather than dropped because nothing calls it yet.
#![allow(dead_code)]

use std::fs::File;
use std::io;
use std::path::Path;

use rgx_core::memmap2::{Mmap, MmapOptions};

/// Below this, map nothing.
///
/// The fixed cost of a mapping -- `CreateFileMappingW` + `MapViewOfFile` +
/// `CloseHandle` on Windows -- cannot be amortised over a file that needs one
/// read. 64 KiB is `Config::buffer_capacity`, so this reads as "map only what
/// takes more than one read". It is not the deciding threshold anyway;
/// `should_map` is, and it splits by platform: on Windows the measurement
/// in `enabled_by_env` says the mapping loses at every size, on Linux the
/// ordering reverses (see `should_map`).
pub const MAP_THRESHOLD: u64 = 64 * 1024;

/// Threshold that *was* supposed to promote large files to memory-mapped
/// slices without anyone asking.
///
/// **DEAD: nothing reads this constant.** `should_map` is
/// `enabled_by_env() && worth_mapping(len)` and never consults it, so no file
/// is ever promoted here. It is kept only because its doc comment carries the
/// measurement table below, and that table is the record of the decision that
/// removed the promotion.
///
/// The table was real when the promotion was real — both arms, same tree,
/// count-gated, 7 rounds x 2 interleaved passes, `-j1`, `Stdout` to the null
/// device:
///
/// ```text
///   235.1 MiB (big235.rs, `pub fn`)   auto   194.2 ms   plain read   191.3 ms   1.015x
///    64.0 MiB (bslice_64m.plain, `fn`) auto    43.3 ms   plain read    43.4 ms   0.998x
/// ```
///
/// Both rows are inside the +/-3% floor — "overlap, not a result" in both
/// directions. That neutrality at exactly the sizes the promotion governed is
/// what removed it: an automatic behaviour that does not pay, cannot be
/// measured from inside a query, and can only surprise. Note that the same
/// table is **not** evidence that `RGX_MMAP=1` is a win; the ~12% loss at
/// 26.6 MiB in `enabled_by_env` is about the switch itself.
pub const AUTO_MMAP_THRESHOLD: u64 = 64 * 1024 * 1024;

/// Whether a file of `len` bytes is worth mapping.
pub fn worth_mapping(len: u64) -> bool {
    len >= MAP_THRESHOLD
}

/// Whether a file of `len` bytes should be mapped.
///
/// Two arms, split by platform, which is where this question was always
/// going to land. On Windows a mapping SLOWED the search -- the table in
/// [`enabled_by_env`]: 94 ms read against 106 ms mapped, and the
/// zero-copy shape is the worst row of the fill harness at 13.2 ms against
/// 9.0 -- because a user mapping faults each page through soft fault
/// handling while `ReadFile` faults the same pages in kernel context and
/// hands over a buffer that is warm for every later pass. On Linux the
/// ordering reverses: a warm `read()` still pays `copy_to_user` per byte
/// (40 ms of a 64 ms zero-match floor over the 246 MB single-file probe)
/// while soft faults are an order of magnitude cheaper, and
/// [`crate::searcher::Searcher::search_windows`] searches the mapping in
/// place with no copy at all. The bench host measured the mapped arm ahead
/// on every sparse row of that probe; Windows keeps the read.
///
/// `RGX_MMAP` overrides both ways: any non-empty value other than `0`
/// forces the mapping on, `0` forces it off. Unset means the platform
/// default -- mapped on Linux, read everywhere else, where the ordering is
/// either against the mapping (Windows, measured) or unmeasured (macOS).
// `enabled_by_env` already took the forcing-on values; what remains here
// is an explicit off or the unset case. The match arms are NOT redundant:
// the `None` arm is the platform DEFAULT, not `true`, so clippy's
// `is_none()` suggestion is only equivalent on Linux and would silently
// flip Windows and macOS to mapped. The equivalent `is_some()` rewrite
// trades this lint for "this if-then-else always returns false" on
// Windows, where `cfg!(target_os = "linux")` folds to `false` -- the
// lint, not the code, is what is platform-sensitive here.
#[allow(clippy::redundant_pattern_matching)]
pub fn should_map(len: u64) -> bool {
    if !worth_mapping(len) {
        return false;
    }
    if enabled_by_env() {
        return true;
    }
    match std::env::var_os("RGX_MMAP") {
        Some(_) => false,
        None => cfg!(target_os = "linux"),
    }
}

/// Whether `RGX_MMAP` asked for files to be read through a mapping.
///
/// **Off by default, and that is the measurement, not caution.** On this
/// machine (Windows, page cache warm, `rgx -c searcher` over six 26.6 MB
/// files with `RGX_ENGINE=rgx`, best of 15, run in both orders): **94 ms read
/// against 106 ms mapped** -- a ~12% loss, reproducibly. The fills in
/// isolation, over one 26.6 MB file, best of 15, from a standalone harness
/// rather than from rgx:
///
/// ```text
///   ReadFile into 64 KiB                     2.22 ms   12.0 GB/s
///   mapping, copy out, + GetFileSizeEx        7.93 ms    3.4 GB/s
///   mapping, copy out, no length query        7.53 ms    3.5 GB/s
///   fs::read into a Vec, then scan            9.97 ms    2.7 GB/s
///   mapping as a slice, then scan            13.22 ms    2.0 GB/s
///   ReadFile into 64 KiB, then scan           8.98 ms    3.0 GB/s
/// ```
///
/// The reason is in the last three rows, and it is not the copy: a *file*
/// mapping faults, and 26.6 MB is 6,500 faults that each go through the page
/// cache to find the page. `ReadFile` faults the same pages, in kernel
/// context, and delivers them into a buffer that is then warm for every
/// subsequent pass. The zero-copy shape -- a mapping handed to the searcher as
/// a slice -- is the *worst* of the three, so the win mmap normally buys (no
/// copy) does not even pay for the faults here.
///
/// The length query is the other half of that table: it is 0.4 ms of the
/// 7.93, not the 5.5 ms the faults are. Asking through `File::metadata`
/// instead -- which is what this did first -- made it 3.4 us a call and put
/// end-to-end at 111 ms, i.e. half the regression was the safety check, and
/// [`file_len`] is the other half of fixing it.
///
/// Linux is the other half of this question and it is untested on this
/// machine: soft faults are an order of magnitude cheaper there and `read()`
/// carries an extra `copy_to_user`, so the ordering there can be the opposite.
/// The switch is what lets somebody answer that on a Linux box, which is the
/// only reason it is a switch and not a deleted module.
///
/// The fallback is the ordinary read either way, so nothing the user sees
/// depends on which side of this switch a run is on.
pub fn enabled_by_env() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("RGX_MMAP").is_some_and(|v| v != "0" && !v.is_empty()))
}

/// A file mapped read-only, read as if it were a `Read`.
///
/// The mapping is read-only: nothing here can write through it, and nothing
/// outside it should. `mapped` is the length the mapping was made with, which
/// is the length the file had at open time -- a file that grows afterwards is
/// not seen, because extending the view is not possible without remapping, and
/// the reader path never promised to see a grow either (a reader stops at the
/// EOF it read).
pub struct MappedFile {
    /// `None` for an empty file: `memmap2` maps a zero-length file fine, but
    /// there is nothing to map and asking the OS for it is not free.
    map: Option<Mmap>,
    /// Kept open for `MappedFile::live_len`. `memmap2` duplicates the
    /// handle for the mapping itself (`DuplicateHandle` on Windows), so this
    /// is a second handle, not a keep-alive.
    file: File,
    /// Length of the mapping.
    mapped: usize,
    /// A caller-imposed ceiling that only ever lowers `mapped`. This is the
    /// hook the truncation tests drive, and the hook a caller that has an
    /// independent notion of "how much of this file is there" would use.
    limit: usize,
    /// The last length the OS confirmed. Kept so that a failed length query
    /// falls back to something already verified rather than to the mapping's
    /// full length, which is the one value that may no longer exist.
    verified: usize,
    /// How far a read has got.
    pos: usize,
}

/// Map a whole file, read-only.
///
/// Returns the error the mapping produced, for the caller to fall back from.
/// A zero-length file maps successfully to zero bytes without the OS being
/// asked (which memmap2 would answer anyway -- its own `map_empty_file` test
/// pins that); a path that is not a readable regular file (a directory, a
/// pipe, a file held for exclusive writing) is an error, and neither failure
/// is reported to the user.
pub fn map_file(path: &Path) -> io::Result<MappedFile> {
    map_open_file(&File::open(path)?)
}

/// Map a file the caller has **already opened**, read-only.
///
/// The counterpart to [`map_file`] for a caller that opened the file for
/// another reason and does not want to pay a second `CreateFileW` for the
/// `engine::FileSource` is that caller: it receives the
/// handle `raw_search` opened with `FILE_FLAG_SEQUENTIAL_SCAN`, and mapping it
/// was costing a second open without the sequential hint.
///
/// Takes the handle by **reference**, deliberately. `MappedFile` needs to own
/// a `File` for `MappedFile::live_len`, and a mapping that fails has to leave
/// the caller holding the handle so it can fall back to the ordinary read --
/// which is the whole of `FileSource::new`'s fallback arm. `try_clone` is
/// `DuplicateHandle` on Windows, and it is paid only on the mapping arm: the
/// mapping is already two kernel objects there (`CreateFileMappingW` plus
/// `MapViewOfFile`, per this module's header), the default path never reaches
/// it, and `memmap2` duplicates the handle for the mapping itself anyway.
pub fn map_open_file(file: &File) -> io::Result<MappedFile> {
    let meta = file.metadata()?;
    // A mapping is a promise about a regular file, and the promise is
    // checked before the empty shortcut answers for something that is not
    // one: on overlayfs a directory reports a length of zero, and this arm
    // used to hand it back as a successful empty mapping before `mmap`
    // ever refused (ext4 gives it 4096 bytes and the `ENODEV`; overlayfs
    // gives it nothing). Windows refuses at the `open`; this is the Unix
    // side of the same contract.
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a mapping is about a regular file, and this is not one",
        ));
    }
    let len = meta.len();
    if len == 0 {
        return Ok(MappedFile::empty(file.try_clone()?, 0));
    }
    // SAFETY: the mapping is read-only and nothing writes through it. The
    // safety obligation memmap2 states -- do not touch the mapping after the
    // file is truncated -- is discharged by `read` and `as_live_slice`, which
    // clip to `live_len` first.
    let map = unsafe { MmapOptions::new().map(file)? };
    let mapped = map.len();
    Ok(MappedFile::mapped(map, file.try_clone()?, mapped))
}

/// Map the first `len` bytes of a file: a partial mapping.
///
/// `len` is clamped to the file's length, so asking for more than there is
/// gives the whole file rather than an error -- the same answer a `take(len)`
/// reader gives. Offsets other than zero are deliberately not exposed: on
/// Windows `CreateFileMappingW`/`MapViewOfFile` require a non-zero offset to
/// be a multiple of the allocation granularity (64 KiB), so a byte-granular
/// range would have to fail on most offsets.
pub fn map_prefix(path: &Path, len: usize) -> io::Result<MappedFile> {
    let file = File::open(path)?;
    let meta = file.metadata()?;
    // The same contract as `map_open_file`: a directory that reports a
    // zero length (overlayfs) must not slip through the empty shortcut.
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a mapping is about a regular file, and this is not one",
        ));
    }
    let file_len = meta.len();
    let want = (len as u64).min(file_len);
    if want == 0 {
        return Ok(MappedFile::empty(file, 0));
    }
    // SAFETY: as in `map_file`; the mapping is read-only and only read
    // through `live_len`-clipped bounds.
    let map = unsafe {
        if want == file_len {
            MmapOptions::new().map(&file)?
        } else {
            MmapOptions::new().len(want as usize).map(&file)?
        }
    };
    let mapped = map.len();
    Ok(MappedFile::mapped(map, file, mapped))
}

impl MappedFile {
    fn empty(file: File, limit: usize) -> Self {
        MappedFile {
            map: None,
            file,
            mapped: 0,
            limit,
            verified: 0,
            pos: 0,
        }
    }

    fn mapped(map: Mmap, file: File, mapped: usize) -> Self {
        MappedFile {
            map: Some(map),
            file,
            mapped,
            limit: mapped,
            verified: mapped,
            pos: 0,
        }
    }

    /// The length of the mapping, i.e. what the file held when it was mapped.
    /// This is *not* the length that may be read: see `MappedFile::live_len`.
    pub fn len(&self) -> usize {
        self.mapped
    }

    /// Whether there is nothing mapped at all.
    pub fn is_empty(&self) -> bool {
        self.mapped == 0
    }

    /// How much of the file can be read right now, without risking a fault.
    ///
    /// `min(mapping, caller limit, the file's current length)`. The last term
    /// is [`file_len`], queried once per fill: that is what turns a concurrent
    /// truncation into EOF instead of a crash.
    ///
    /// If the query itself fails, the last verified length stands. That is
    /// monotonic and cannot exceed what the OS already confirmed; the
    /// alternative -- treating a failed query as "the file is gone" -- would
    /// silently return nothing for a file that is still perfectly readable
    /// through the mapping.
    pub fn live_len(&mut self) -> usize {
        let ceiling = self.limit.min(self.mapped);
        #[cfg(windows)]
        {
            // On Windows, truncating a file with an open section is refused outright
            // by the kernel with ERROR_USER_MAPPED_FILE, so concurrent truncation
            // cannot happen while mapped. Avoid querying GetFileSizeEx on every fill.
            self.verified = ceiling;
        }
        #[cfg(not(windows))]
        {
            self.verified = match file_len(&self.file) {
                Ok(len) => ceiling.min(usize::try_from(len).unwrap_or(usize::MAX)),
                Err(_) => self.verified.min(ceiling),
            };
        }
        self.verified
    }

    /// Lower the ceiling `MappedFile::live_len` applies. Never raises it,
    /// and never moves the read position: if the limit falls behind the
    /// position the next read reports EOF, which is what a file truncated
    /// there looks like.
    pub fn set_limit(&mut self, len: usize) {
        self.limit = len.min(self.mapped);
        self.verified = self.verified.min(self.limit);
    }

    /// The bytes that are currently safe to touch, as a slice.
    ///
    /// Shorter than the mapping whenever the file has been truncated since it
    /// was mapped. The read-only slice borrows the mapping, so it is valid for
    /// exactly as long as the mapping is -- and only while nobody truncates the
    /// file in the window between the length query above and the use.
    pub fn as_live_slice(&mut self) -> &[u8] {
        let live = self.live_len();
        match self.map.as_ref() {
            Some(map) => &map[..live],
            None => &[],
        }
    }

    /// Fill `buf` from the mapping, like [`std::io::Read::read`].
    ///
    /// A partial fill is a short read and 0 is EOF; the searcher's reader loop
    /// handles both, so the shape of this is `File::read`'s and the truncation
    /// case rides the same path.
    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let live = self.live_len();
        let Some(map) = self.map.as_ref() else {
            return Ok(0);
        };
        if self.pos >= live {
            return Ok(0);
        }
        let n = buf.len().min(live - self.pos);
        buf[..n].copy_from_slice(&map[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    /// How many bytes have been handed out by [`MappedFile::read`].
    pub fn consumed(&self) -> usize {
        self.pos
    }
}

/// The file's length, cheaply enough to ask once per 64 KiB fill.
///
/// `File::metadata` is the obvious call and it is the wrong one on Windows:
/// it fills a `BY_HANDLE_FILE_INFORMATION` -- creation time, attributes, the
/// index -- through `GetFileInformationByHandle`, measured here at **3.4 us**
/// against **1.0 us** for `GetFileSizeEx`, which is the one field wanted.
/// Over a 26.6 MB file that is 1.4 ms against 0.4 ms. Since this runs on
/// every fill, it is worth the declaration rather than the convenience.
///
/// Everywhere else `File::metadata` is `fstat` plus a struct copy, and there
/// is no cheaper portable spelling of it.
#[cfg(windows)]
pub(crate) fn file_len(file: &File) -> io::Result<u64> {
    use std::os::windows::io::AsRawHandle;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileSizeEx(file: *mut core::ffi::c_void, file_size: *mut i64) -> i32;
    }

    // SAFETY: the handle is open and owned by the `File` for the whole call,
    // and `size` is a live `i64` for the call to write through. A failure
    // returns 0, which is how this tells an error from a zero-length file --
    // `GetLastError` then says why.
    let mut size: i64 = 0;
    if unsafe { GetFileSizeEx(file.as_raw_handle().cast(), &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(u64::try_from(size).unwrap_or(0))
}

#[cfg(not(windows))]
pub(crate) fn file_len(file: &File) -> io::Result<u64> {
    Ok(file.metadata()?.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fmt;
    use std::fs::OpenOptions;
    use std::io::Read as _;

    use rgx_core::regex::ByteRegex;
    use rgx_core::searcher::{
        Config, LineBuffer, Searcher as RgxSearcher, Sink as RgxSink, SinkContext, SinkFinish,
        SinkMatch,
    };

    /// A temp directory of its own: a test that put its files in the working
    /// directory would leave them there for the parity tests to find.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rgx-mmap-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = scratch(name).join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// Line-corpus generator. Every line is `body <i> needle`, so a line count
    /// is a number that can be checked against the file itself.
    fn lines(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n * 32);
        for i in 0..n {
            v.extend_from_slice(format!("body {i:06} needle tail\n").as_bytes());
        }
        v
    }

    /// Read every byte through the mapping, in `chunk`-sized fills.
    fn read_all(m: &mut MappedFile, chunk: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; chunk];
        loop {
            let n = m.read(&mut buf).unwrap();
            if n == 0 {
                return out;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }

    // ---- the mapping itself ------------------------------------------------

    #[test]
    fn maps_and_reads_a_file() {
        let data = lines(100);
        let path = write("whole", &data);
        let mut m = map_file(&path).unwrap();
        assert_eq!(m.len(), data.len());
        assert!(!m.is_empty());
        assert_eq!(read_all(&mut m, 64 * 1024), data);
        assert_eq!(m.consumed(), data.len());
    }

    #[test]
    fn empty_file_maps_to_nothing() {
        let path = write("empty", b"");
        let mut m = map_file(&path).unwrap();
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
        assert_eq!(m.live_len(), 0);
        assert_eq!(m.as_live_slice(), b"");
        assert_eq!(m.read(&mut [0u8; 64]).unwrap(), 0);
    }

    #[test]
    fn one_byte_file() {
        let path = write("one", b"x");
        let mut m = map_file(&path).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m.as_live_slice(), b"x");
        let mut buf = [0u8; 8];
        assert_eq!(m.read(&mut buf).unwrap(), 1);
        assert_eq!(&buf[..1], b"x");
        assert_eq!(m.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn file_of_exactly_one_buffer() {
        // `Config::buffer_capacity`: a file that fills the read buffer exactly,
        // so the scan ends on a boundary rather than on a short read.
        let data = vec![b'a'; 64 * 1024];
        let path = write("onebuffer", &data);
        let mut m = map_file(&path).unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        assert_eq!(m.read(&mut buf).unwrap(), 64 * 1024);
        assert_eq!(m.read(&mut buf).unwrap(), 0);
        assert!(worth_mapping(64 * 1024));
        assert!(!worth_mapping(64 * 1024 - 1));
    }

    #[test]
    fn short_reads_at_the_tail() {
        // A read buffer that does not divide the file: the last fill is short
        // and the one after it is EOF. This is the shape an ordinary reader
        // has, and the searcher depends on it.
        let data = lines(500);
        let path = write("tail", &data);
        let mut m = map_file(&path).unwrap();
        assert_eq!(read_all(&mut m, 1000), data);
    }

    #[test]
    fn partial_mapping_is_a_prefix() {
        let data = lines(200);
        let path = write("prefix", &data);
        let mut m = map_prefix(&path, 100).unwrap();
        assert_eq!(m.len(), 100);
        assert_eq!(m.as_live_slice(), &data[..100]);
        assert_eq!(read_all(&mut m, 32), data[..100]);

        // Asking for more than there is gives the whole file, like `take`.
        let mut all = map_prefix(&path, data.len() * 4).unwrap();
        assert_eq!(all.len(), data.len());
        assert_eq!(all.as_live_slice(), &data);

        // Asking for nothing maps nothing, but is not an error.
        let mut none = map_prefix(&path, 0).unwrap();
        assert!(none.is_empty());
        assert_eq!(none.read(&mut [0u8; 8]).unwrap(), 0);
    }

    #[test]
    fn a_directory_does_not_map() {
        // The refusal is explicit and comes before the empty shortcut: a
        // directory on overlayfs reports a length of zero, and the shortcut
        // used to answer `Ok` for it before the `mmap` ever refused -- ext4
        // gives a directory 4096 bytes and the kernel's `ENODEV`, overlayfs
        // gives it nothing, so the same file was an error on one machine
        // and a successful empty mapping on another. The type check is the
        // contract; where the `open` fails (Windows) this never reaches it.
        let dir = scratch("dir");
        assert!(map_file(&dir).is_err(), "a directory must not map");
        assert!(map_prefix(&dir, 8).is_err(), "nor does a prefix of one");
    }

    #[test]
    fn a_missing_path_does_not_map() {
        let err = map_file(Path::new("no/such/file/at/all"))
            .err()
            .expect("a missing path must not map");
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
    }

    // ---- truncation --------------------------------------------------------

    #[test]
    fn truncation_is_a_short_read_not_a_fault() {
        // The hazard this module exists for, driven deterministically: the
        // file is the full size, and the length the reader is allowed to use
        // is cut to half part-way through the scan.
        let data = lines(20_000); // ~460 KiB: several 64 KiB fills
        let cut = lines(15_000).len(); // well past the second fill
        let path = write("shrink", &data);

        let mut m = map_file(&path).unwrap();
        assert_eq!(m.len(), data.len());
        let mut buf = vec![0u8; 64 * 1024];
        let mut got = Vec::new();
        let mut fills = 0;
        loop {
            let n = m.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            fills += 1;
            if fills == 2 {
                // The file shrank here, as far as this reader is concerned.
                m.set_limit(cut);
            }
        }
        assert!(
            fills > 2,
            "the scan must still have been going: {fills} fills"
        );
        // Everything after the limit is never touched, and the read ends at
        // exactly the limit rather than at the mapping's length.
        assert_eq!(got, data[..cut]);
        assert_eq!(m.live_len(), cut);
        assert_eq!(m.as_live_slice(), &data[..cut]);
        // Past the limit a read reports EOF, not bytes from the mapping.
        assert_eq!(m.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn a_limit_behind_the_position_reads_nothing() {
        let data = lines(100);
        let path = write("behind", &data);
        let mut m = map_file(&path).unwrap();
        let mut buf = vec![0u8; 16];
        m.read(&mut buf).unwrap();
        assert_eq!(m.consumed(), 16);
        m.set_limit(4);
        assert_eq!(m.live_len(), 4);
        assert_eq!(m.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn a_limit_never_raises_the_mapping() {
        let data = lines(10);
        let path = write("noraise", &data);
        let mut m = map_file(&path).unwrap();
        m.set_limit(usize::MAX);
        assert_eq!(m.live_len(), data.len());
    }

    /// What the platform does when the file is really truncated under a live
    /// mapping. The two answers are both correct and both worth asserting:
    ///
    /// - Windows refuses: `SetEndOfFile` on a file with a mapped section open
    ///   fails with `ERROR_USER_MAPPED_FILE` (1224), so the hazard cannot be
    ///   reached and the mapping stays whole.
    /// - Unix allows it, and then `live_len` is what keeps the read off the
    ///   pages that went away.
    #[test]
    fn truncating_under_a_live_mapping() {
        let data = lines(4000);
        let cut = lines(1000).len();
        let path = write("realshrink", &data);
        let mut m = map_file(&path).unwrap();

        let handle = OpenOptions::new().write(true).open(&path).unwrap();
        match handle.set_len(cut as u64) {
            Ok(()) => {
                // Only reachable where the OS lets it happen.
                assert_eq!(m.live_len(), cut, "a real truncation must be seen");
                let got = read_all(&mut m, 4096);
                assert_eq!(got, data[..cut], "and must stop at the new end");
            }
            Err(e) => {
                assert_eq!(
                    e.raw_os_error(),
                    Some(1224),
                    "unexpected refusal: {e} (raw {:?})",
                    e.raw_os_error()
                );
                // Nothing changed, so the mapping is still whole.
                assert_eq!(m.live_len(), data.len());
                assert_eq!(read_all(&mut m, 4096), data);
            }
        }
    }

    // ---- the searcher over the mapping ------------------------------------

    /// Counts matching lines and remembers their numbers, so two engines can
    /// be compared without a printer in the way.
    #[derive(Default)]
    struct Counter {
        lines: Vec<u64>,
        bytes: u64,
    }

    impl RgxSink for Counter {
        type Error = io::Error;
        fn matched(&mut self, m: &SinkMatch<'_>) -> Result<bool, io::Error> {
            self.lines.push(m.line_number.unwrap_or(0));
            Ok(true)
        }
        fn context(&mut self, _: &SinkContext<'_>) -> Result<bool, io::Error> {
            Ok(true)
        }
        fn finish(&mut self, fin: &SinkFinish<'_>) -> Result<(), io::Error> {
            self.bytes = fin.byte_count;
            Ok(())
        }
    }

    fn counter_over<F: FnMut(&mut [u8]) -> Result<usize, fmt::Error>>(mut f: F) -> Counter {
        let re = ByteRegex::new(b"needle").unwrap();
        let searcher = RgxSearcher::new(&re, Config::default());
        let mut sink = Counter::default();
        let mut buf = LineBuffer::new(searcher.config());
        searcher.search_reader(&mut f, &mut sink, &mut buf).unwrap();
        sink
    }

    /// The whole point of the wiring: the same lines, in the same order, from
    /// the mapping and from an ordinary read.
    ///
    /// The corpora are the ones that break: a last line with no terminator, a
    /// file of exactly one buffer, and a file that is not a whole number of
    /// buffers, so every one of them ends on a short read or on nothing at
    /// all.
    #[test]
    fn mapping_and_reading_agree_line_for_line() {
        let exactly_one_buffer = {
            let mut v = b"needle\n".to_vec();
            v.resize(64 * 1024 - 22, b'x');
            v.extend_from_slice(b"tail needle no newline");
            assert_eq!(v.len(), 64 * 1024, "fixture must be exactly 64 KiB");
            v
        };
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("no trailing newline", {
                let mut v = lines(300);
                v.extend_from_slice(b"body 999999999 needle tail");
                v
            }),
            ("exactly one buffer", exactly_one_buffer),
            ("buffer and a bit", {
                let mut v = lines(4000);
                v.extend_from_slice(b"body 4000 needle\n");
                assert!(v.len() > 64 * 1024 && v.len() < 128 * 1024);
                v
            }),
            ("one byte", b"x".to_vec()),
            ("empty", Vec::new()),
        ];

        for (name, data) in cases {
            let path = write("agree", &data);

            // Ordinary read.
            let mut file = std::fs::File::open(&path).unwrap();
            let from_reader = counter_over(|b: &mut [u8]| file.read(b).map_err(|_| fmt::Error));

            // The mapping, filled in 64 KiB reads like the searcher would.
            let mut m = map_file(&path).unwrap();
            let from_map = counter_over(|b: &mut [u8]| m.read(b).map_err(|_| fmt::Error));

            assert_eq!(
                from_map.lines, from_reader.lines,
                "{name}: mapped and read disagree on which lines match"
            );
            assert_eq!(from_map.bytes, from_reader.bytes, "{name}: byte count");
            assert_eq!(from_map.bytes as usize, data.len(), "{name}: whole file");

            // And the mapping agrees with a slice search, which is the path
            // every small file takes today.
            let re = ByteRegex::new(b"needle").unwrap();
            let searcher = RgxSearcher::new(&re, Config::default());
            let mut slice_sink = Counter::default();
            searcher.search_slice(&data, &mut slice_sink).unwrap();
            assert_eq!(slice_sink.lines, from_map.lines, "{name}: slice vs map");
        }
    }

    /// The truncation case again, this time through the searcher: the file is
    /// mapped whole, the length is cut mid-scan, and the searcher has to stop
    /// there without panicking and without reporting a line the truncated file
    /// does not have.
    #[test]
    fn search_over_a_file_truncated_mid_scan() {
        let data = lines(20_000);
        let cut = lines(15_000).len();
        let path = write("midscan", &data);

        let re = ByteRegex::new(b"needle").unwrap();
        let searcher = RgxSearcher::new(&re, Config::default());

        let mut m = map_file(&path).unwrap();
        let mut fills = 0usize;
        let mut read = |b: &mut [u8]| -> Result<usize, fmt::Error> {
            let n = m.read(b).map_err(|_| fmt::Error)?;
            if n > 0 {
                fills += 1;
                if fills == 2 {
                    m.set_limit(cut);
                }
            }
            Ok(n)
        };
        let mut sink = Counter::default();
        let mut buf = LineBuffer::new(searcher.config());
        searcher
            .search_reader(&mut read, &mut sink, &mut buf)
            .unwrap();

        assert!(fills > 2, "the scan has to still have been going: {fills}");

        // What the same searcher reports over the truncated file itself. A
        // cursor over a fixed slice, which is the reader `cross_check_path`
        // builds for the same bytes.
        let mut cursor: &[u8] = &data[..cut];
        let expected = counter_over(|b: &mut [u8]| {
            let n = core::cmp::min(b.len(), cursor.len());
            b[..n].copy_from_slice(&cursor[..n]);
            cursor = &cursor[n..];
            Ok(n)
        });
        assert_eq!(
            sink.lines, expected.lines,
            "the truncated scan reported other lines"
        );
        assert_eq!(sink.lines.len(), 15_000);
        assert!(
            sink.bytes <= cut as u64,
            "read past the truncation: {}",
            sink.bytes
        );
    }
}
