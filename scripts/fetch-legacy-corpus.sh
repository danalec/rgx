#!/usr/bin/env bash
# Fetch the legacy-format integration-test corpus into
# tests/fixtures/legacy-formats/. Idempotent: re-running refreshes what
# is missing and skips what is already there. Files are downloaded
# from two public sources, both of which rgx does not control:
#
#   - https://github.com/mdbtools/mdbtestdata  (Jet/ACE .mdb and .accdb)
#   - https://sembiance.com/fileFormatSamples (Lotus 1-2-3 and DIF)
#
# Nothing is written outside tests/fixtures/legacy-formats/. The .gitignore
# at tests/fixtures/.gitignore keeps the binaries out of every clone, so the
# test step cannot assume they are there: .github/workflows/ci.yml runs this
# script before `cargo test` in both jobs that run tests, and
# tests/legacy_formats.rs FAILS (rather than skips) when a fixture is
# missing. A run that reports 7 passes without this script having run is no
# longer possible.
#
# WAB has no public corpus: tests/legacy_formats.rs synthesises a
# minimal OLE Compound File in memory for the CFB parser path.

set -euo pipefail

# Resolve the repo root from this script's path so the script works from
# any cwd. Read-only — never touches anything outside fixtures_root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES="$REPO_ROOT/tests/fixtures/legacy-formats"

mkdir -p "$FIXTURES"

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# mdbtools/mdbtestdata — Jet (mdb) and ACE (accdb) sample databases.
# The data/ subdirectory of the repository is the canonical fixture set;
# we keep the whole subdirectory because the three files we exercise
# live there and the upstream tree is small.
# ---------------------------------------------------------------------------

MDBTEST="$FIXTURES/mdbtestdata"
MDBTEST_FILES=(
    "$MDBTEST/data/ASampleDatabase.accdb"
    "$MDBTEST/data/DateTestDatabase.mdb"
    "$MDBTEST/data/nwind.mdb"
)
need_mdb=0
for f in "${MDBTEST_FILES[@]}"; do
    if [[ ! -f "$f" ]]; then need_mdb=1; break; fi
done

if (( need_mdb )); then
    if ! have git; then
        echo "fetch-legacy-corpus: 'git' not on PATH; cannot fetch mdbtestdata." >&2
        exit 1
    fi
    echo "fetch-legacy-corpus: cloning mdbtools/mdbtestdata (depth=1) ..."
    # If a partial clone is around, refresh it; otherwise start fresh.
    if [[ -d "$MDBTEST/.git" ]]; then
        (cd "$MDBTEST" && git fetch --depth=1 origin master) || true
    else
        rm -rf "$MDBTEST"
        git clone --depth=1 https://github.com/mdbtools/mdbtestdata "$MDBTEST"
    fi
fi

# ---------------------------------------------------------------------------
# sembiance.com — Lotus 1-2-3 and DIF samples. The sembiance index is
# stable; each file is downloaded individually so the corpus stays small
# (only the files rgx's integration tests reference) and re-runs are
# cheap.
#
# If sembiance is unreachable on a CI box, the script prints the URL list
# and continues — Lotus and DIF tests skip on missing fixtures.
# ---------------------------------------------------------------------------

LOTUS_URL="https://sembiance.com/fileFormatSamples/document/lotus123"
DIF_URL="https://sembiance.com/fileFormatSamples/text/dataInterchangeFormat"

LOTUS_FILES=(
    1530MTGE.WKB AUTOLOAN.WKB DEMO.WK4 example.123
    example.wk1 example.wk3 example.wk4 example.wks
    PEYNEVAL.WK1 PEYTREND.WK3 PF.WK1 TILE.WKS
)
DIF_FILES=(
    DIFTEST.DIF EXAMPLE.DIF EXAMPLE2.DIF HDINFO.DIF
    MASK1.DIF SAMPLE.DIF beispiel.dif
)

if ! have curl; then
    echo "fetch-legacy-corpus: 'curl' not on PATH; cannot fetch sembiance samples." >&2
    exit 1
fi

mkdir -p "$FIXTURES/lotus" "$FIXTURES/dif"

fetch_one() {
    local url="$1" out="$2"
    if [[ -f "$out" ]] && [[ -s "$out" ]]; then
        return 0
    fi
    if curl --fail --silent --show-error --location --output "$out" "$url"; then
        echo "  + $(basename "$out")"
    else
        rm -f "$out"
        echo "  - $(basename "$out") (download failed; the test that needs it will fail until the host is reachable)" >&2
        return 1
    fi
}

echo "fetch-legacy-corpus: Lotus 1-2-3 samples ($LOTUS_URL) ..."
for f in "${LOTUS_FILES[@]}"; do
    fetch_one "$LOTUS_URL/$f" "$FIXTURES/lotus/$f" || true
done

# The `.wk2` extension is a rename, not a format. 1-2-3 v2.0 shipped the
# worksheet as `.wk1` and changed the extension to `.wk2` "quickly", so that
# the number in the extension would match the version number; the record
# layout did not change with it, and both files carry the BOF version code
# 0x0406. No `.wk2` sample is published where this script can reach one --
# the host above answers 404 for `example.wk2` -- so the corpus makes one:
# a copy of the `.wk1` under the `.wk2` name.
#
# It is a DISPATCH fixture. It shows that the extension reaches the v2
# reader and that the bytes under it are the v2 bytes; it says nothing new
# about the bytes, which the `.wk1` already exercises.
if [[ -f "$FIXTURES/lotus/example.wk1" ]] && [[ ! -f "$FIXTURES/lotus/example.wk2" ]]; then
    cp "$FIXTURES/lotus/example.wk1" "$FIXTURES/lotus/example.wk2"
    echo "  + example.wk2 (a copy of example.wk1: the extension is a rename)"
fi

echo "fetch-legacy-corpus: DIF samples ($DIF_URL) ..."
for f in "${DIF_FILES[@]}"; do
    fetch_one "$DIF_URL/$f" "$FIXTURES/dif/$f" || true
done

# ---------------------------------------------------------------------------
# Summary: number of files actually present after the run.
# ---------------------------------------------------------------------------

count_in() {
    local d="$1"
    if [[ -d "$d" ]]; then
        find "$d" -type f | wc -l | tr -d ' '
    else
        echo 0
    fi
}

echo "fetch-legacy-corpus: done."
echo "  dif:        $(count_in "$FIXTURES/dif") file(s)"
echo "  lotus:      $(count_in "$FIXTURES/lotus") file(s)"
echo "  mdbtestdata:$(count_in "$MDBTEST/data") file(s) in data/"
echo "  total:      $(find "$FIXTURES" -type f | wc -l | tr -d ' ') file(s)"
echo "fixtures root: $FIXTURES"