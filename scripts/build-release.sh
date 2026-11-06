#!/usr/bin/env bash
# build-release.sh -- build the shippable rgx binaries: portable x86-64 and
# a Zen-4 (znver4) variant.
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
#   rgx-v<version>-znver4-linux.tar.gz    tuned for Zen 4 (incl. 7950X3D)
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
# The znver4 variant sets ONLY -C target-cpu: the linker still comes from
# .cargo/config.toml. Measured effect (bench-linkers.sh, 7950X3D): ~+1%
# corpus, ~+2.5% big-file literal, ~+5% big-file regex.
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
# The flags are set for the one build and unset after it: a RUSTFLAGS left
# in the environment would silently apply to the next cargo command in the
# same shell, which is the kind of thing that makes a later build
# un-reproducible.
build_variant() {
    local name="$1" target_dir="$2" rustflags="$3"

    RUSTFLAGS="$rustflags" CARGO_TARGET_DIR="$target_dir" cargo build --release || {
        echo "cargo build failed ($name)" >&2
        exit 1
    }
    echo "$target_dir/release/rgx"
}

# portable baseline (no target-cpu)
exe_generic=$(build_variant "generic" "$repo/target" "")

# Zen 4 tuned: AVX-512 + full Zen-4 scheduling. Baseline x86-64 CPUs must
# NOT run this binary (illegal instruction at startup).
exe_znver4=$(build_variant "znver4" "$repo/target/release-znver4" "-C target-cpu=znver4")

# smoke both: version + a real search over the repo's own sources
for exe in "$exe_generic" "$exe_znver4"; do
    "$exe" --version > /dev/null || { echo "smoke --version failed: $exe" >&2; exit 1; }
    hits=$("$exe" -c "fn main" src || true)
    case "$hits" in
        *main.rs:*) ;;
        *) echo "smoke search failed: $exe" >&2; exit 1 ;;
    esac
    echo "smoke ok: $exe"
done

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
tar_znver4="$out/rgx-v$version-znver4-linux.tar.gz"
new_tarball "$exe_generic" "$tar_generic"
new_tarball "$exe_znver4" "$tar_znver4"
echo "built: $tar_generic"
echo "built: $tar_znver4"
