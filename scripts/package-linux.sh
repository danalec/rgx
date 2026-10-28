#!/usr/bin/env bash
# package-linux.sh — turn already-built Linux binaries into release
# artifacts: tarballs, distro packages (deb/rpm/apk/pacman), each install-
# verified in a container of its own distro. Requires only docker.
#
#   ./package-linux.sh <src-dir> <gnu-bin> <musl-bin> <znver4-bin> <version> <out-dir>
#
# <src-dir> must contain the docs that ship beside the binary
# (README.md COPYING LICENSE-APACHE NOTICE).
#
# The verify step is not decorative: glibc and dynamic-linking regressions
# only appear on real installs (fedora's missing libbz2, bookworm's older
# glibc both escaped `cargo build` and were caught here).
set -euo pipefail

SRC_DIR="$(cd "${1:?usage: package-linux.sh <src-dir> <gnu-bin> <musl-bin> <znver4-bin> <version> <out-dir>}" && pwd)"
GNU_BIN="${2:?missing gnu binary}"
MUSL_BIN="${3:?missing musl binary}"
ZNV_BIN="${4:?missing znver4 binary}"
VERSION="${5:?missing version}"
OUT_DIR="${6:?missing out-dir}"
mkdir -p "$OUT_DIR"; OUT_DIR="$(cd "$OUT_DIR" && pwd)"
TAG="rgx-v$VERSION"

GEM_IMG="ruby:3.3-slim"
WORK="$(mktemp -d /tmp/rgx-pkg.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
PKG="$WORK/pkgs"; mkdir -p "$PKG"

# The containers' networking. Docker's bridge needs the `veth` driver, and
# a virtualised kernel can be built without it -- the CachyOS bench host is
# one, and there the containers have to share the host's network namespace
# instead (RGX_DOCKER_NET=host). The public resolver is only asked for when
# the bridge is in use: with the host's namespace the host's own resolver
# does the name lookup.
DOCKER_NET_ARGS=(--dns 8.8.8.8)
if [ -n "${RGX_DOCKER_NET:-}" ]; then
  DOCKER_NET_ARGS=(--network "$RGX_DOCKER_NET")
fi

for b in "$GNU_BIN" "$MUSL_BIN" "$ZNV_BIN"; do
  [ -x "$b" ] || { echo "missing or not executable: $b"; exit 1; }
done
echo ">> binaries present"

# --- tarballs ----------------------------------------------------------------
stage_docs() {
  mkdir -p "$1"
  cp "$2" "$1/rgx"
  cp "$SRC_DIR/README.md" "$SRC_DIR/COPYING" "$SRC_DIR/LICENSE-APACHE" \
     "$SRC_DIR/NOTICE" "$1/"
}
stage_docs "$PKG/$TAG-x86_64-linux-gnu" "$GNU_BIN"
stage_docs "$PKG/$TAG-x86_64-linux-musl" "$MUSL_BIN"
stage_docs "$PKG/$TAG-znver4-linux" "$ZNV_BIN"
for d in "$PKG"/*/; do
  (cd "$PKG" && tar -czf "$(basename "$d").tar.gz" "$(basename "$d")")
done

# --- distro packages (fpm) ---------------------------------------------------
DESC="Search inside everything: ripgrep-compatible search with in-process adapters for PDF, Office, archives, 3D models, LLM checkpoints, databases, e-mail"
# This one lands inside the .deb/.rpm/.apk metadata, so it is what a consumer
# reads with `dpkg -s` or `rpm -qi`: the public project URL, never the LAN
# address of the forgejo the release is pushed to.
URL="https://github.com/danalec/rgx"

make_stage() {
  mkdir -p "$2/usr/bin" "$2/usr/share/doc/rgx"
  cp "$1" "$2/usr/bin/rgx"
  cp "$SRC_DIR/README.md" "$SRC_DIR/COPYING" "$SRC_DIR/LICENSE-APACHE" \
     "$SRC_DIR/NOTICE" "$2/usr/share/doc/rgx/"
}

run_fpm() {
  docker run --rm "${DOCKER_NET_ARGS[@]}" -v "$2":/stage:ro -v "$PKG":/out "$GEM_IMG" bash -c "
    export DEBIAN_FRONTEND=noninteractive
    if ! command -v fpm >/dev/null; then
      apt-get update -qq >/dev/null
      apt-get install -y -qq rpm zstd binutils libarchive-tools >/dev/null 2>&1
      for i in 1 2 3 4 5; do
        gem install fpm --no-document >/dev/null 2>&1 && break
        sleep 5
        [ \$i = 5 ] && { echo 'gem install fpm failed'; exit 1; }
      done
    fi
    cd /out
    fpm -t $1 -s dir -n rgx -v $VERSION \
        --license 'Apache-2.0' --vendor danalec --maintainer danalec \
        --architecture x86_64 --description \"$DESC\" --url $URL \
        -C /stage usr 2>&1 | tail -1"
}

S_GNU="$WORK/stage-gnu"; make_stage "$GNU_BIN" "$S_GNU"
S_MUSL="$WORK/stage-musl"; make_stage "$MUSL_BIN" "$S_MUSL"

echo ">> fpm deb/rpm/pacman (gnu payload)"
run_fpm deb "$S_GNU"
run_fpm rpm "$S_GNU"
run_fpm pacman "$S_GNU"
echo ">> fpm apk (musl payload)"
run_fpm apk "$S_MUSL"

# --- install smoke tests, one container per distro ---------------------------
verify() {
  local img="$1"; shift
  echo ">> verify $img"
  docker pull "$img" >/dev/null 2>&1 || true
  docker run --rm "${DOCKER_NET_ARGS[@]}" -v "$PKG":/p "$img" bash -c "
    set -e
    $@ >/dev/null 2>&1
    rgx --version
    echo smoke > /tmp/x && rgx smoke /tmp/x" \
    || { echo "VERIFY FAILED: $img"; exit 1; }
}

verify debian:bookworm-slim "dpkg -i /p/rgx_${VERSION}_amd64.deb"
verify ubuntu:20.04 "dpkg -i /p/rgx_${VERSION}_amd64.deb"
verify fedora:41 "rpm -i /p/rgx-${VERSION}-1.x86_64.rpm"
verify archlinux:base "pacman -U --noconfirm /p/rgx-${VERSION}-1-x86_64.pkg.tar.zst"
echo ">> verify alpine:3.20"
docker pull alpine:3.20 >/dev/null 2>&1 || true
docker run --rm "${DOCKER_NET_ARGS[@]}" -v "$PKG":/p alpine:3.20 sh -c "
  apk add --allow-untrusted --no-network /p/rgx_${VERSION}_x86_64.apk >/dev/null
  rgx --version && echo smoke > /tmp/x && rgx smoke /tmp/x" \
  || { echo "VERIFY FAILED: alpine"; exit 1; }

cp "$PKG"/*.tar.gz "$PKG"/*.deb "$PKG"/*.rpm "$PKG"/*.apk "$PKG"/*.pkg.tar.zst "$OUT_DIR/"
echo ">> done. artifacts in $OUT_DIR:"
ls -la "$OUT_DIR"
