#!/usr/bin/env bash
# build-release.sh -- build the shippable rgx binaries: portable x86-64 and
# four instruction-set tuned variants (x86-64-v2, AVX2 / x86-64-v3,
# x86-64-v4 and Zen-4 / znver4).
#
# The Linux counterpart of scripts/build-release.ps1.
#
#   bash scripts/build-release.sh              # clippy gate + tests + both tarballs
#   bash scripts/build-release.sh --skip-tests # iterate faster
#
# Unless --skip-tests, the build fails on any clippy warning
# (`cargo clippy --release --workspace --all-targets -- -D warnings`) --
# the workspace stays warning-free by policy.
#
# Outputs (.dist/local/):
#   rgx-v<version>-x86_64-linux.tar.gz   baseline, runs on any x86-64 CPU
#   rgx-v<version>-v2-linux.tar.gz       tuned for x86-64-v2 CPUs
#   rgx-v<version>-avx2-linux.tar.gz     tuned for AVX2 CPUs (x86-64-v3)
#   rgx-v<version>-v4-linux.tar.gz       tuned for AVX-512 CPUs (x86-64-v4)
#   rgx-v<version>-znver4-linux.tar.gz   tuned for Zen 4 (incl. 7950X3D)
# Each tarball packs rgx + README.md + COPYING + LICENSE-APACHE + NOTICE at
# its root, matching the asset layout published on the forgejo release.
#
# Why a separate directory: the release artifacts themselves are built by
# scripts/build-linux.sh, in Docker, and they land in .dist/ -- the glibc
# tarball, the musl tarball and the distro packages. This script is the
# local, docker-free twin of the Windows build: what runs on this machine,
# for the machine it runs on. Its artifacts go to .dist/local/ so that the
# release directory holds only what the release publishes.
#
# Each tuned variant sets ONLY -C target-cpu, through the per-target
# CARGO_TARGET_<triple>_RUSTFLAGS variable: build scripts and proc-macros
# are host binaries and must not be built for a CPU the build machine may
# not have. The linker still comes from .cargo/config.toml. Measured effect
# (bench-linkers.sh, 7950X3D): ~+1% corpus, ~+2.5% big-file literal, ~+5%
# big-file regex for znver4.
set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
cd "$repo"

skip_tests=0
version=""

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-tests) skip_tests=1; shift ;;
        --version) version=${2:-}; shift 2 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

command -v cargo > /dev/null 2>&1 || {
    echo "cargo not found; install Rust: https://rustup.rs" >&2
    exit 1
}

[ -n "$version" ] || version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ -n "$version" ] || { echo "no version in Cargo.toml" >&2; exit 1; }

if [ "$skip_tests" -eq 0 ]; then
    # the workspace stays warning-free: any clippy warning fails the release
    cargo clippy --release --workspace --all-targets -- -D warnings || {
        echo "clippy warnings found; workspace must stay warning-free" >&2
        exit 1
    }
    cargo test --release --locked --workspace || { echo "tests failed" >&2; exit 1; }
fi

out=".dist/local"
mkdir -p "$out"

# build_variant <name> <target-dir> <rustflags>
#
# The flags are passed to the one cargo command through the per-target
# variable, so they reach the target's own artifacts and not the host build
# scripts. `env` scopes them to that command: a RUSTFLAGS left in the
# environment would silently apply to the next cargo command in the same
# shell, which is the kind of thing that makes a later build
# un-reproducible.
build_variant() {
    local name="$1" target_dir="$2" rustflags="$3"
    local host flags_var

    host="$(rustc -vV | sed -n 's/^host: //p')"
    flags_var="CARGO_TARGET_$(printf '%s' "$host" | tr 'a-z-' 'A-Z_')_RUSTFLAGS"

    env "$flags_var=$rustflags" CARGO_TARGET_DIR="$target_dir" \
        cargo build --release || {
        echo "cargo build failed ($name)" >&2
        exit 1
    }
    echo "$target_dir/release/rgx"
}

# portable baseline (no target-cpu)
exe_generic=$(build_variant "generic" "$repo/target" "")

# The four instruction-set tiers, in ascending baseline order. A CPU older
# than the tier cannot run its binary (illegal instruction at startup).
exe_v2=$(build_variant "v2" "$repo/target/release-v2" "-C target-cpu=x86-64-v2")
exe_avx2=$(build_variant "avx2" "$repo/target/release-avx2" "-C target-cpu=x86-64-v3")
exe_v4=$(build_variant "v4" "$repo/target/release-v4" "-C target-cpu=x86-64-v4")
exe_znver4=$(build_variant "znver4" "$repo/target/release-znver4" "-C target-cpu=znver4")

# smoke: version + a real search over the repo's own sources. A variant
# built for an ISA this machine does not have cannot start here, so its
# smoke is skipped with the reason rather than reported as a bad build.
smoke() {
    local exe="$1"
    "$exe" --version > /dev/null || { echo "smoke --version failed: $exe" >&2; exit 1; }
    hits=$("$exe" -c "fn main" src || true)
    case "$hits" in
        *main.rs:*) ;;
        *) echo "smoke search failed: $exe" >&2; exit 1 ;;
    esac
    echo "smoke ok: $exe"
}
cpu_has() { grep -qi "$1" /proc/cpuinfo 2>/dev/null; }
smoke "$exe_generic"
if cpu_has sse4_2; then smoke "$exe_v2"; else echo "smoke: skipped v2 (no SSE4.2 on this machine)"; fi
if cpu_has avx2; then smoke "$exe_avx2"; else echo "smoke: skipped avx2 (no AVX2 on this machine)"; fi
if cpu_has avx512; then smoke "$exe_v4"; else echo "smoke: skipped v4 (no AVX-512 on this machine)"; fi
if cpu_has avx512; then smoke "$exe_znver4"; else echo "smoke: skipped znver4 (no AVX-512 on this machine)"; fi

# new_tarball <binary> <path>
#
# The tarball holds the binary and the documents at its root, the way the
# zip does on Windows, so that the two platforms' artifacts unpack the
# same way for whoever downloads them.
new_tarball() {
    local exe="$1" tarball="$2"
    local stage
    stage=$(mktemp -d)
    cp "$exe" "$stage/rgx"
    for doc in README.md COPYING LICENSE-APACHE NOTICE; do
        [ -f "$doc" ] && cp "$doc" "$stage"
    done
    tar -czf "$tarball" -C "$stage" .
    rm -rf "$stage"
}

# .dist, not dist: the directory the .gitignore lists is the one this
# script creates, and a plain `dist/` would be an unignored pile of
# binaries sitting in git status as work to review.
tar_generic="$out/rgx-v$version-x86_64-linux.tar.gz"
tar_v2="$out/rgx-v$version-v2-linux.tar.gz"
tar_avx2="$out/rgx-v$version-avx2-linux.tar.gz"
tar_v4="$out/rgx-v$version-v4-linux.tar.gz"
tar_znver4="$out/rgx-v$version-znver4-linux.tar.gz"
new_tarball "$exe_generic" "$tar_generic"
new_tarball "$exe_v2" "$tar_v2"
new_tarball "$exe_avx2" "$tar_avx2"
new_tarball "$exe_v4" "$tar_v4"
new_tarball "$exe_znver4" "$tar_znver4"
echo "built: $tar_generic"
echo "built: $tar_v2"
echo "built: $tar_avx2"
echo "built: $tar_v4"
echo "built: $tar_znver4"
