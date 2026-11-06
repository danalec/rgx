#!/bin/bash
# build-linux.sh — build every Linux artifact for an rgx release, entirely
# in Docker. Run on any docker host (developed on unraid).
#
#   ./build-linux.sh <git-url> <ref> <out-dir>
#
# Produces in <out-dir>:
#   rgx-v<V>-x86_64-linux-gnu.tar.gz
#   rgx-v<V>-x86_64-linux-musl.tar.gz
#   rgx-v<V>-znver4-linux.tar.gz
#   rgx_<V>_amd64.deb          (Debian/Ubuntu, glibc >= 2.31)
#   rgx-<V>-1.x86_64.rpm       (Fedora/RHEL)
#   rgx_<V>_x86_64.apk         (Alpine, musl)
#   rgx-<V>-1-x86_64.pkg.tar.zst (Arch)
#
# Every package is installed and smoke-tested inside a container of its own
# distro before being written to <out-dir>.
#
# Hard-won constraints baked in here (do not "simplify"):
#   * gnu binary MUST build on rust:*-slim-bullseye — glibc 2.31 is the floor
#     for deb/rpm targets; the default rust image (trixie) emits glibc 2.39
#     symbols and breaks bookworm/ubuntu-22.04.
#   * bzip2 is statically linked via feature unification (see
#     crates/rgx-adapters-archive/Cargo.toml); the rpm smoke test catches
#     regressions (fedora has no libbz2 in the base image).
#   * apk payload MUST be the musl binary; alpine cannot run gnu binaries.
set -euo pipefail

GIT_URL="${1:?usage: build-linux.sh <git-url> <ref> <out-dir>}"
REF="${2:?usage: build-linux.sh <git-url> <ref> <out-dir>}"
OUT_DIR="${3:?usage: build-linux.sh <git-url> <ref> <out-dir>}"
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

WORK="$(mktemp -d /tmp/rgx-linux.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
SRC="$WORK/src"
git clone --depth 1 --branch "$REF" "$GIT_URL" "$SRC" 2>&1 | tail -1
# shallow clones of a branch keep the tag name in REF; fall back to main if
# the ref is a branch that --branch already handled. For tags, this is a no-op.
cd "$SRC"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
TAG="rgx-v$VERSION"

RUST_IMG="rust:1.98-slim-bullseye"
GEM_IMG="ruby:3.3-slim"

echo ">> version $VERSION (ref $REF)"

# The containers' networking. Docker's bridge needs the `veth` driver, and
# a virtualised kernel can be built without it -- the CachyOS bench host is
# one, and there the containers have to share the host's network namespace
# instead (RGX_DOCKER_NET=host). The public resolver is only asked for when
# the bridge is in use: with the host's namespace the host's own resolver
# does the name lookup, and a resolver that does not exist is a container
# that cannot pull its packages.
DOCKER_NET_ARGS=(--dns 8.8.8.8)
if [ -n "${RGX_DOCKER_NET:-}" ]; then
  DOCKER_NET_ARGS=(--network "$RGX_DOCKER_NET")
fi
export RGX_DOCKER_NET="${RGX_DOCKER_NET:-}"

docker_pull() {
  for i in 1 2 3; do docker pull "$1" >/dev/null 2>&1 && return 0; sleep 5; done
  docker pull "$1" 2>&1 | tail -1
}
docker_pull "$RUST_IMG" >/dev/null
docker_pull "$GEM_IMG" >/dev/null

# --- binaries ---------------------------------------------------------------
# Target dir and registry live on named docker volumes: /tmp on small docker
# hosts (unraid) is RAM-backed and three full dep builds exhaust it; volumes
# are disk-backed and warm up subsequent runs.
# Inner shells run `set -eo pipefail` and dump the full cargo log on failure —
# without it, `cargo ... | tail -1` masks compile errors (regex-syntax died
# silently this way) and the smoke step fails on a missing binary instead.
cargo_build() { # cargo_build <target> [extra cargo args...]
  local target="$1"; shift
  docker run --rm "${DOCKER_NET_ARGS[@]}" \
    -v "$SRC":/src -w /src \
    -v rgx-target:/src/target \
    -v rgx-registry:/usr/local/cargo/registry \
    "$RUST_IMG" bash -c "
      set -eo pipefail
      cargo build --release --locked --target $target $* > /tmp/cargo.log 2>&1 || { cat /tmp/cargo.log; exit 1; }
      tail -1 /tmp/cargo.log"
}

echo ">> building gnu (bullseye/glibc 2.31)"
cargo_build x86_64-unknown-linux-gnu

echo ">> building musl (static)"
docker run --rm "${DOCKER_NET_ARGS[@]}" \
  -v "$SRC":/src -w /src \
  -v rgx-target:/src/target \
  -v rgx-registry:/usr/local/cargo/registry \
  "$RUST_IMG" bash -c "
    set -eo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null && apt-get install -y -qq musl-tools >/dev/null
    # unraid's container DNS flakes intermittently; rustup keeps partial
    # downloads, so a plain retry succeeds.
    for i in 1 2 3 4 5; do
      rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 && break
      echo \"rustup retry \$i\"; sleep 5
      [ \$i = 5 ] && { echo 'rustup target add failed'; exit 1; }
    done
    cargo build --release --locked --target x86_64-unknown-linux-musl > /tmp/cargo.log 2>&1 || { cat /tmp/cargo.log; exit 1; }
    tail -1 /tmp/cargo.log"

echo ">> building znver4 (Zen-4 tuned, same glibc floor)"
docker run --rm "${DOCKER_NET_ARGS[@]}" \
  -v "$SRC":/src -w /src \
  -v rgx-target:/src/target \
  -v rgx-registry:/usr/local/cargo/registry \
  -e RUSTFLAGS="-C target-cpu=znver4" \
  "$RUST_IMG" bash -c "
    set -eo pipefail
    cargo build --release --locked --target x86_64-unknown-linux-gnu --target-dir /src/target/znver4 > /tmp/cargo.log 2>&1 || { cat /tmp/cargo.log; exit 1; }
    tail -1 /tmp/cargo.log"

# Binaries live in the named volume; copy them out for staging/packaging.
mkdir -p "$WORK/bins"
docker run --rm "${DOCKER_NET_ARGS[@]}" -v rgx-target:/t -v "$WORK/bins":/out "$RUST_IMG" bash -c "
  cp /t/x86_64-unknown-linux-gnu/release/rgx /out/rgx-gnu
  cp /t/x86_64-unknown-linux-musl/release/rgx /out/rgx-musl
  cp /t/znver4/x86_64-unknown-linux-gnu/release/rgx /out/rgx-znver4"
GNU_BIN="$WORK/bins/rgx-gnu"
MUSL_BIN="$WORK/bins/rgx-musl"
ZNV_BIN="$WORK/bins/rgx-znver4"
for b in "$GNU_BIN" "$MUSL_BIN" "$ZNV_BIN"; do
  "$b" --version >/dev/null || { echo "smoke failed: $b"; exit 1; }
done
echo ">> all binaries smoke ok"

# --- packaging: tarballs + distro packages + verifies -------------------------
bash "$SRC/scripts/package-linux.sh" "$SRC" "$GNU_BIN" "$MUSL_BIN" "$ZNV_BIN" "$VERSION" "$OUT_DIR"
