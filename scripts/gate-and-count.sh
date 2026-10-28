#!/usr/bin/env bash
# gate-and-count.sh -- the workspace gate, and the test count of THIS tree.
#
# The count belongs in the commit that is about to be made, so it has to be
# measured on the tree the commit carries, and not on the tree the other
# blocks will add later. The caller stashes the later blocks' files before
# calling this, and pops the stash after.
#
# The three steps are the ones the project gates on: `cargo fmt --check`,
# `cargo clippy` with the warnings as errors, and `cargo test` over the
# whole workspace with `--no-fail-fast`, so a failure in one suite does not
# hide the others.
#
# The line that starts with `COUNT:` is what the caller reads: the number of
# tests that passed, the number that failed, the number ignored, and the
# number of test binaries. The logs are in target/gate/.
#
# The Linux counterpart of scripts/gate-and-count.ps1.
#
# Usage:
#   bash scripts/gate-and-count.sh              # the whole gate
#   bash scripts/gate-and-count.sh --skip-tests # fmt and clippy only
set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
out="$repo/target/gate"
skip_tests=0
[ "${1:-}" = "--skip-tests" ] && skip_tests=1

mkdir -p "$out"

echo '=== fmt ==='
cargo fmt --manifest-path "$repo/Cargo.toml" --all -- --check > "$out/fmt.log" 2>&1
fmt_exit=$?
tail -4 "$out/fmt.log"
echo "fmt exit=$fmt_exit"

echo '=== clippy ==='
cargo clippy --manifest-path "$repo/Cargo.toml" --release --locked --workspace --all-targets -- -D warnings > "$out/clippy.log" 2>&1
clippy_exit=$?
echo "clippy exit=$clippy_exit"
if [ "$clippy_exit" -ne 0 ]; then tail -20 "$out/clippy.log"; fi

if [ "$skip_tests" -eq 1 ]; then
    if [ "$fmt_exit" -gt "$clippy_exit" ]; then exit "$fmt_exit"; fi
    exit "$clippy_exit"
fi

echo '=== test ==='
cargo test --manifest-path "$repo/Cargo.toml" --release --locked --workspace --no-fail-fast > "$out/test.log" 2>&1
test_exit=$?

# The counts of the "test result:" lines: the numbers in front of "passed;",
# "failed;" and "ignored;", and the number of those lines.
read -r passed failed ignored suites <<EOF
$(awk '/^test result:/ {
    for (i = 1; i <= NF; i++) {
        if ($i == "passed;") p += $(i - 1)
        else if ($i == "failed;") f += $(i - 1)
        else if ($i == "ignored;") g += $(i - 1)
    }
    s += 1
} END { printf "%d %d %d %d", p, f, g, s }' "$out/test.log")
EOF

echo "test exit=$test_exit"
echo "COUNT: passed=$passed failed=$failed ignored=$ignored suites=$suites"
if [ "$failed" -gt 0 ]; then
    grep -E '^(failures:|test .* FAILED)' "$out/test.log" | head -10
fi

if [ "$fmt_exit" -gt "$clippy_exit" ]; then exit "$fmt_exit"; fi
if [ "$clippy_exit" -gt "$test_exit" ]; then exit "$clippy_exit"; fi
exit "$test_exit"
