#!/usr/bin/env bash
# install.sh -- install rgx on Linux.
#
# The Linux counterpart of install.ps1.
#
#   curl -fsSL https://raw.githubusercontent.com/danalec/rgx/main/install.sh | bash
#   bash install.sh --channel musl
#   bash install.sh --channel znver4 --install-dir /usr/local/bin
#
# Downloads the rgx release tarball, verifies its SHA256, unpacks rgx into
# the install directory and prepends it to the user's PATH.
#
# The digest is PINNED HERE, one per channel, exactly as install.ps1 pins
# the two Windows zips. That is the whole point of a pin: the installer
# carries the digest of the artifact it is allowed to install, so a
# tampered or substituted download is refused before anything is
# unpacked.
#
# The pins are release data, and the release owns them: scripts/release-all.sh
# rewrites them from the artifacts it has just built, and refuses to finish
# if the rewrite did not move. A hand-maintained table is a table that is
# wrong on the day after the release -- which is exactly how install.ps1's
# two pins came to be rewritten by the release flow in the first place.
#
# The channels are the three Linux artifacts scripts/build-linux.sh
# publishes: the glibc build, the static musl build, and the Zen-4 tuned
# one. The Zen-4 build runs only on a Zen-4 CPU; the generic one runs
# anywhere.
set -u

channel="gnu"
install_dir="$HOME/.local/bin"
base_url="https://github.com/danalec/rgx/releases/download"
version="rgx-v0.1.1"
skip_checksum=0

# The digest of each channel's asset.
#
# The digests are uppercase hex, like the ones in install.ps1, and they are
# rewritten in place by scripts/release-all.sh -- so the shape of these
# lines is part of the contract, not a formatting choice.
declare -A EXPECTED=(
    [gnu]="FAFC2CC04DD43FC8E68B10703F09F6654CE1B40DB0B1C93399EDFF52C54C1E12"
    [musl]="5FDBBE600451613673ABDE477794FF3823F0CD353E85D2799A94AB665D0C208E"
    [znver4]="989DDC2A96C613C70B9CA771EF622F20BA484DE77DEDE7B2DF57ACA06E3AF316"
)

while [ $# -gt 0 ]; do
    case "$1" in
        --channel) channel=${2:-}; shift 2 ;;
        --install-dir) install_dir=${2:-}; shift 2 ;;
        --base-url) base_url=${2:-}; shift 2 ;;
        --version) version=${2:-}; shift 2 ;;
        --skip-checksum) skip_checksum=1; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

# The asset is named AFTER the arguments are parsed: the version is one of
# them, and a name built before the parse names the version this file was
# written with -- not the one the caller asked for. The digest is the only
# thing the release rewrites, so the map above keeps the shape the rewrite
# expects.
case "$channel" in
    gnu)    asset="$version-x86_64-linux-gnu.tar.gz" ;;
    musl)   asset="$version-x86_64-linux-musl.tar.gz" ;;
    znver4) asset="$version-znver4-linux.tar.gz" ;;
    *) echo "unknown channel: $channel (gnu, musl, znver4)" >&2; exit 2 ;;
esac
expected="${EXPECTED[$channel]}"

url="$base_url/$version/$asset"

command -v curl > /dev/null 2>&1 || { echo "curl not found" >&2; exit 1; }
command -v tar > /dev/null 2>&1 || { echo "tar not found" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $url ..."
curl -fsSL -o "$tmp/$asset" "$url" || { echo "the download failed" >&2; exit 1; }

if [ "$skip_checksum" -eq 0 ]; then
    actual=$(sha256sum "$tmp/$asset" | awk '{print toupper($1)}')
    if [ "$actual" != "$expected" ]; then
        echo "SHA256 mismatch for $asset" >&2
        echo " expected $expected" >&2
        echo " got      $actual" >&2
        exit 1
    fi
    echo "SHA256 verified."
else
    echo "SHA256 verification skipped."
fi

stage="$tmp/stage"
mkdir -p "$stage"
tar -xzf "$tmp/$asset" -C "$stage"
# The tarball holds the binary at its root; a build that put it in a
# subdirectory would otherwise install nothing and say nothing.
if [ ! -f "$stage/rgx" ]; then
    found=$(find "$stage" -name rgx -type f | head -1)
    [ -n "$found" ] || { echo "no rgx binary in $asset" >&2; exit 1; }
    stage=$(dirname "$found")
fi

mkdir -p "$install_dir"
cp "$stage/rgx" "$install_dir/rgx"
chmod +x "$install_dir/rgx"
for doc in README.md COPYING LICENSE-APACHE NOTICE; do
    [ -f "$stage/$doc" ] && cp "$stage/$doc" "$install_dir"
done

# user PATH (idempotent prepend)
profile="$HOME/.profile"
if [ -f "$HOME/.bashrc" ]; then
    profile="$HOME/.bashrc"
fi
if ! grep -qF "$install_dir" "$profile" 2>/dev/null; then
    printf '\n# rgx\nexport PATH="%s:$PATH"\n' "$install_dir" >> "$profile"
    echo "Added $install_dir to $profile (open a new terminal to pick it up)."
else
    echo "$install_dir is already on the PATH in $profile."
fi

installed=$("$install_dir/rgx" --version 2>/dev/null || echo "rgx")
echo "Installed: $installed -> $install_dir"
