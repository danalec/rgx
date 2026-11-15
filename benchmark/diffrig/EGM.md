# diffrig

## Overview

`diffrig/` is the byte-for-byte differential harness that compares rgx against
ripgrep. It answers one question in four ways: does the same query produce the
same bytes? The four programs differ only in how much they ask for.

`cmp.sh` asks once — one label, one input, one argument list — and prints the
two `od -c` dumps side by side when they differ. `fuzz.py` asks a matrix: 40
flag combinations × 5 patterns × 10 file sets — 2000 combinations, every one
run against both binaries. `ptytest.py` and `conpty.py` ask the console
question: when stdout is a terminal, ripgrep prints line numbers and rgx has to
match it, so both harnesses attach a real pseudo-terminal to the process — a
POSIX `pty` on Unix, a Windows `ConPTY` through `kernel32` — and compare the
bytes the process actually wrote to the terminal.

The `fx/` directory holds the fixture corpus: seventeen files — an empty file,
a file of blank lines, a file of one word, files with and without a trailing
newline, a file whose matches sit between other lines, a file of short lines
with a gap in them, a binary file carrying NUL bytes, a file whose needle is
surrounded by spaces, and a deep file of many short lines. Every ending in the
corpus is LF, `crlf.txt` and `crlf2.txt` notwithstanding. The matrix's file
sets select eight of them (`hello.txt`, `two.txt`, `multi.txt`, `nonl.txt`,
`ctx.txt`, `empty.txt`, `blank.txt`, `oneword.txt`) and the two console checks
add `crlf.txt`; the other eight are in no file set at all. The corpus is
deterministic, and `fuzz.py` rewrites the three files it needs on every run.

The four programs resolve their own binaries: `RGX` is derived from the
script's own location (debug build first, release as the fallback), and `rg`
takes an `RG` environment override, then `PATH`, then the ripgrep that the Git
for Windows ships. Three of the four try `rgx.exe` first and then fall back to
a bare `rgx`, because the Unix host they exist for has no `.exe`; only
`conpty.py`, which is Windows-only, keeps the suffix hardcoded. `cmp.sh` has
no `RG` override for `rg` at all: it invokes bare `rg`.

## Interface

- `bash cmp.sh <label> <stdin-file-or-"-"> args…` — runs `rg "$@"` and `rgx "$@"` over the given input, compares the `od -c` dumps, and prints `SAME <label>` or `DIFF <label>   [args: …]` followed by the first 30 lines of each side's dump. With `-` the input is `/dev/null` and the two stderr streams are captured separately.
- `python3 fuzz.py` — the matrix. Public surface: the constants `FLAGS` (40 verified-emulatable flag combinations), `PATTERNS` (`needle`, `needle|foo`, `n.edle`, `^needle`, `needle$`), `FILESETS` (10 file selections), and `run(exe, args, stdin=None) -> (returncode, stdout)`. Prints a `DIFF %r` block per mismatch and ends with `checked %d combos, %d unexplained diffs`.
- `python3 ptytest.py` — the POSIX-pty console check. Public surface: `run_pty(cmd) -> bytes`, which opens a `pty`, attaches it to the child's stdout, reads the master until EOF and returns the bytes. 17 cases; prints `SAME(pty) <args>` or `DIFF(pty) <args>` with both sides' bytes.
- `python3 conpty.py` — the Windows ConPTY console check. Public surface: `run_conpty(cmdline, cwd) -> bytes`, plus the `ctypes` bindings it needs — `CreatePseudoConsole`, `CreateProcessW` with `EXTENDED_STARTUPINFO_PRESENT`, `UpdateProcThreadAttribute` with `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`, `ReadFile`, `GetExitCodeProcess` — and the `COORD`, `STARTUPINFOW`, `STARTUPINFOEXW` and `PROCESS_INFORMATION` structures. 20 cases; prints the same `SAME(pty)` / `DIFF(pty)` tags.
- `fx/` — the fixture corpus the matrix and the two console checks read.

## Invariants

- Each harness resolves its own binaries from the script's own location, so a run from any working directory compares the same two executables. `RGX` is the debug build when it exists and the release build otherwise; `rg` is `$RG`, then `PATH`, then the Git-for-Windows ripgrep — except in `cmp.sh`, which runs bare `rg` and honours `$RGX` alone. `fuzz.py`, `ptytest.py` and `cmp.sh` try `rgx.exe` and then fall back to bare `rgx`, so the Unix host finds its binary; `conpty.py` alone hardcodes the `.exe` suffix.
- A difference in output *order* alone is not a difference: `fuzz.py` sorts the output lines before declaring a mismatch, because ripgrep's multi-file ordering is not deterministic.
- The corpus is deterministic. The three files `fuzz.py` writes — `fx/empty.txt`, `fx/blank.txt`, `fx/oneword.txt` — are rewritten with the same bytes on every run, so a difference between two runs is a difference in the binaries and not in the input.
- The console harnesses compare the bytes written to the terminal, not the exit code and not the redirected stdout: the point is what the process does when stdout *is* a console.
- A flag whose absence rgx cannot emulate is excluded from the matrix rather than reported as a difference; the exclusion is stated in the file, next to the flags it applies to.
- `conpty.py` is Windows-only: it binds `kernel32` through `ctypes.wintypes`. `ptytest.py` is the Unix counterpart and needs a POSIX `pty`.

## Side Effects

- Writes `.rg.err` and `.rgx.err` into this directory when `cmp.sh` is run with `-`; both are gitignored.
- Rewrites `fx/empty.txt`, `fx/blank.txt` and `fx/oneword.txt` on every `fuzz.py` run.
- Spawns `rg` and `rgx` as child processes, with their stdin closed and their stdout piped, captured or attached to a pseudo-terminal.
- Creates a pseudo-terminal per case in `ptytest.py` (`pty.openpty`) and a ConPTY plus two pipes per case in `conpty.py`; both are closed when the case ends.
- `conpty.py` reads the child process's output through a pipe until the child exits, and leaves no process running.
- Python's bytecode cache is gitignored (`__pycache__/`, `*.pyc`), so a run that leaves one behind does not dirty the tree.

## Verification

- Run: `cargo test --release --locked --workspace`
- The harness checks itself: `cd benchmark/diffrig && bash cmp.sh "fn main" ../../src/main.rs && python fuzz.py`.
