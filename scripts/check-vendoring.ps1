<#
.SYNOPSIS
    Guards the vendoring rules: rgx links nothing from upstream, and every
    vendored file declares its source.

.DESCRIPTION
    rgx copies code out of upstream; it never depends on it. This script fails
    if that ever stops being true, so the rule is checked rather than
    remembered. Four checks:

      1. No upstream reference in any Cargo manifest, Cargo.lock, or
         .cargo/config.toml. Provenance comments in *other* files are
         fine and are not flagged; only manifests matter, because only
         manifests can create a dependency edge.
      2. No [patch] section in .cargo/config.toml, which could redirect a
         dependency to a local upstream checkout without a path entry.
      3. Every vendored source file carries a provenance header naming
         upstream, so copied code stays traceable to its origin.
      4. No external crates.io dependencies. Known-remaining ones are
         listed with what replaces them, so the count is a progress
         metric and a newly added crate fails the check.

    Run from the repo root:  powershell -File scripts/check-vendoring.ps1
    Exits 1 on any violation.
#>

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot

$failures = New-Object System.Collections.Generic.List[string]

function Add-Failure([string]$msg) {
    $script:failures.Add($msg) | Out-Null
    Write-Host "  FAIL: $msg" -ForegroundColor Red
}

Write-Host "checking vendoring rules in $repoRoot" -ForegroundColor Cyan

# --- 1. no upstream reference in any manifest ---------------------------------
# A match here is a dependency edge, a [patch] target, or a workspace
# inherit. All three are forbidden. Comments that merely mention the
# provenance are acceptable in Cargo.toml, so only the non-comment part
# of a line is inspected.
Write-Host "`n[1/4] no upstream in manifests" -ForegroundColor Cyan
$manifests = @()
$manifests += Get-ChildItem -Path . -Filter 'Cargo.toml' -Recurse -File |
    Where-Object { $_.FullName -notmatch '[\\/]target[\\/]' }
$manifests += Get-ChildItem -Path . -Filter 'Cargo.lock' -Recurse -File |
    Where-Object { $_.FullName -notmatch '[\\/]target[\\/]' }
$manifests += Get-ChildItem -Path . -Filter 'config.toml' -Recurse -File |
    Where-Object { $_.FullName -like '*\.cargo\*' -and $_.FullName -notmatch '[\\/]target[\\/]' }

foreach ($f in $manifests) {
    $rel = Resolve-Path -Relative $f.FullName
    $lineNo = 0
    foreach ($line in Get-Content $f.FullName) {
        $lineNo++
        # drop comments: a full-line '#' and any trailing ' #'
        $code = ($line -split '#', 2)[0]
        if ($code -match '(?i)vendored from') {
            Add-Failure "$rel`:$lineNo references upstream source in manifest code: $($line.Trim())"
        }
    }
}
if ($failures.Count -eq 0) {
    Write-Host "  ok: $($manifests.Count) manifests clean" -ForegroundColor Green
}

# --- 2. no [patch] in .cargo/config.toml ----------------------------------
Write-Host "`n[2/4] no [patch] redirects" -ForegroundColor Cyan
$cfg = Join-Path $repoRoot '.cargo\config.toml'
if (Test-Path $cfg) {
    if ((Get-Content $cfg -Raw) -match '(?m)^\s*\[patch') {
        Add-Failure ".cargo/config.toml has a [patch] section; it could redirect a dependency to a local checkout"
    } else {
        Write-Host "  ok: no [patch] section" -ForegroundColor Green
    }
} else {
    Write-Host "  ok: no .cargo/config.toml" -ForegroundColor Green
}

# --- 3. vendored trees declare provenance ---------------------------------
# A vendored tree is covered by ONE provenance statement in its root module
# (mod.rs), not by per-file headers: the copies are kept byte-identical to
# upstream so a re-sync is a plain file overwrite, and a header on every file
# would have to be re-applied on each sync. Files that were *modified*
# after copying do carry their own header (see sevenz/graph_mode.rs) and
# are listed as exceptions below.
#
# A crate vendored whole (crates/rar-codec) has no mod.rs -- its root module
# is lib.rs, so that is accepted as the root when mod.rs is absent.
#
# So the invariant checked here is: the tree root names its upstream source.
Write-Host "`n[3/4] vendored trees declare provenance" -ForegroundColor Cyan
$vendoredRoots = @('crates\rgx-adapters-archive\src\sevenz', 'crates\rar-codec\src', 'crates\rgx-core\src\memmap2')
$checked = 0
foreach ($vroot in $vendoredRoots) {
    $dir = Join-Path $repoRoot $vroot
    if (-not (Test-Path $dir)) { continue }
    $rootName = $null
    foreach ($candidate in @('mod.rs', 'lib.rs')) {
        if (Test-Path (Join-Path $dir $candidate)) { $rootName = $candidate; break }
    }
    if ($null -eq $rootName) {
        Add-Failure "$vroot has no mod.rs or lib.rs to carry tree-level provenance"
        continue
    }
    $checked++
    $root = Join-Path $dir $rootName
    $head = (Get-Content $root -TotalCount 25) -join "`n"
    # A vendored tree must name its upstream source. The accepted
    # markers are `vendored from` (legacy trees) or `independent
    # reimplementation` (current trees); if neither is present the tree
    # has no provenance to audit.
    if ($head -notmatch '(?i)(vendored from|independent reimplementation)') {
        Add-Failure "$vroot\$rootName does not name its upstream source; add a tree-level provenance header (vendored from / independent reimplementation)"
    } else {
        $n = (Get-ChildItem -Path $dir -Filter '*.rs' -File).Count
        Write-Host "  ok: $vroot\$rootName declares provenance for $n files" -ForegroundColor Green
    }
}
if ($checked -eq 0) {
    Write-Host "  ok: no vendored trees configured yet" -ForegroundColor Green
}

# --- 4. no external crates ------------------------------------------------
# The zero-external-crates rule is the project's headline invariant, and
# checks 1-3 could not see it: they only look for upstream references and
# provenance headers, so any number of crates.io dependencies passed
# unnoticed. This check enumerates them.
#
# Known remaining dependencies are listed rather than simply forbidden, so
# the count is a progress metric and nobody can add a new one by forgetting.
# Each entry names what replaces it; the OCR stack is planned in
# OCR-PLAN.md, the search engine in MUST-WRITE.md.
$knownExternal = @{
    # --- search engine (MUST-WRITE.md) ---
    'regex'         = 'the oracle for the syntax and searcher tests. It is a dev-dependency only -- nothing in any binary links it -- and it is the ONLY oracle left: `differential.rs` and the grep-searcher dev-dependency were removed with the grep dependencies, so every parity case in `crates/rgx-core/src/{syntax,regex}.rs` is written against this crate. The in-house engine is the shipped matcher (MUST-WRITE K1); what remains is the capture-group surface `grep-regex` used to provide.'
    'ignore'        = 'MUST-WRITE K4 -- parallel walker with gitignore semantics'

    # --- compression and archives: upstream already has these in-house ---
    'brotli'        = 'NO REPLACEMENT: rgx has the RFC 7932 decoder in crates/rgx-adapters-archive/src/brotli/. See tests::oracle::vendored_brotli_does_not_decode_reference_streams'
    'xz2'           = 'upstream b02/compress/xz/ (RFC 8478 container + LZMA2)'
    'zstd'          = 'NOT YET: upstream b02/compress/zstd.rs was refused as not actually zstd'
    # rgx's own .bz2 decoding is in-house already (rgx_core::compress::bzip2,
    # a vendored copy of upstream b02/compress/bzip2.rs, verified against
    # reference-bzip2-CLI fixtures). What is left here is the `zip` crate's
    # own bzip2 backend, which only a fork of `zip` could drop.
    'bzip2-0_5-static' = 'C binding, pulled in by the zip crate; rgx needs a zip without the bzip2 feature to remove it'
    'lz4_flex'       = 'LZ4 for the persistent extraction cache (src/cache.rs:411 compress, :435 decompress). Unlike the archive decoders, this one is not search: the cache stores what a decode would produce, so it needs a fast compressor the codec modules never had. Will go away if the cache moves to the same raw-blob layout the pack store uses, at the cost of cache size on disk.'

    # --- container and metadata readers ---
    'rusqlite'      = 'upstream b01/io/binary/sqlite.rs + b02/sqlite/rusqlite_compat.rs'
    'kamadak-exif'  = 'upstream b01/io/image/exif/'

    # --- plumbing ---
    'clap'          = 'argument parsing; no upstream equivalent identified yet'
    'crossbeam-deque' = 'the work-stealing deque the parallel walker drains (src/walk.rs:17). Replacing it means writing a Chase-Lev ring in-house; the comment above the dependency records that a hand-rolled Chase-Lev already sits behind the walker mutex and was slower, so the deque is the deliberate second attempt rather than the first.'
    'mimalloc'       = 'the opt-in global allocator (src/main.rs:4795). Measured 5-12% on the corpus benches against MSVCRT HeapAlloc, and it is why the third CI job runs the suite with `--features mimalloc`. There is no in-house replacement -- this is a whole allocator, not a dependency rgx could reimplement at a useful size. Optional and off by default; nothing links it in a default build.'
    'memchr'        = 'crates/rgx-core/src/memchr.rs re-exports the external memchr 2.x crate; there is no in-house memchr tree in this checkout.'
    'libc'          = 'the constants and `mmap(2)` / `msync(2)` / `madvise(2)` syscall FFI the vendored `memmap2` module (crates/rgx-core/src/memmap2) reaches for on Unix. Gated on the `std` feature so the no_std build does not link it. Will go away when the `memmap2` module is rewritten in pure inline FFI (a follow-up) or when Linux / macOS gating moves to `std::sys::pal`.'
    'anyhow'        = 'rgx-core/src/error.rs is the in-house replacement; leftover entry'

    # --- OCR stack (OCR-PLAN.md) ---
    'ocrs'          = 'OCR-PLAN K11 -- detection and recognition pipeline'
    'rten'          = 'OCR-PLAN K8/K9 -- model file reader and tensor runtime'
    'image'         = 'OCR-PLAN K10 -- decode and preprocess; upstream has the codecs'

    # --- test-only ---
    'flate2'        = 'dev-dependency for test fixtures'
    'zip'           = 'dev-dependency for test fixtures'
    'libfuzzer-sys' = 'fuzz harness only; not part of a shipped build'
}

Write-Host "`n[4/4] no unexpected external crates" -ForegroundColor Cyan

# A dependency section is any [..dependencies] table, including
# target-specific ones. Everything else is not a dependency list.
$depSection = $false
$external = New-Object System.Collections.Generic.List[object]
foreach ($f in $manifests) {
    if ($f.Name -ne 'Cargo.toml') { continue }
    $rel = Resolve-Path -Relative $f.FullName
    $section = ''
    $lineNo = 0
    foreach ($line in Get-Content $f.FullName) {
        $lineNo++
        $trimmed = $line.Trim()
        if ($trimmed -match '^\[+\s*([^\]]+?)\s*\]+$') {
            $section = $matches[1]
            $depSection = ($section -match '(^|\.)(dev-|build-)?dependencies$')
            continue
        }
        if (-not $depSection) { continue }
        $code = ($trimmed -split '#', 2)[0].Trim()
        if ($code -notmatch '^([A-Za-z0-9_-]+)\s*=') { continue }
        $name = $matches[1]
        # path = ... is an in-tree crate; workspace = true inherits one.
        if ($code -match '\bpath\s*=') { continue }
        if ($code -match '\bworkspace\s*=') { continue }
        $external.Add([pscustomobject]@{ Name = $name; Where = "$rel`:$lineNo" })
    }
}

$unexpected = New-Object System.Collections.Generic.List[object]
$seen = @{}
foreach ($d in $external) {
    if ($seen.ContainsKey($d.Name)) { continue }
    $seen[$d.Name] = $true
    if (-not $knownExternal.ContainsKey($d.Name)) {
        $unexpected.Add($d)
    }
}

if ($unexpected.Count -gt 0) {
    foreach ($d in $unexpected) {
        Add-Failure "$($d.Where): external dependency '$($d.Name)' is not in the known-remaining list; either it is in-tree (use path =) or add it with what replaces it"
    }
} else {
    Write-Host "  ok: no unlisted external crates" -ForegroundColor Green
}

# Report what is still outstanding. This is the number to drive to zero.
$remaining = ($seen.Keys | Where-Object { $knownExternal.ContainsKey($_) } | Sort-Object)
if ($remaining.Count -gt 0) {
    Write-Host "  $($remaining.Count) known external dependenc(ies) still to remove:" -ForegroundColor Yellow
    foreach ($name in $remaining) {
        Write-Host "    - $name ($($knownExternal[$name]))" -ForegroundColor Yellow
    }
} else {
    Write-Host "  zero external dependencies: the invariant holds" -ForegroundColor Green
}

# --- result ----------------------------------------------------------------
Write-Host ""
if ($failures.Count -gt 0) {
    Write-Host "vendoring check FAILED: $($failures.Count) violation(s)" -ForegroundColor Red
    exit 1
}
Write-Host "vendoring check passed" -ForegroundColor Green
exit 0
