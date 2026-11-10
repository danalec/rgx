#!/usr/bin/env bash
# install.sh -- install rgx on Linux and FreeBSD.
#
# The Unix counterpart of install.ps1.
#
#   curl -fsSL https://raw.githubusercontent.com/danalec/rgx/main/install.sh | bash
#   bash install.sh --channel musl
#   bash install.sh --channel freebsd --install-dir /usr/local/bin
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
# The channels are the seven artifacts the release carries for unix: the glibc
# build, the static musl build, four instruction-set tuned ones (x86-64-v2,
# AVX2 / x86-64-v3, x86-64-v4 and Zen 4), and the FreeBSD build. Each tuned
# build needs a CPU with those instructions; the generic one runs anywhere.
# FreeBSD has one artifact and no glibc/musl choice, so its name is the
# default there -- and `gnu` is the default everywhere else.
set -u

channel="gnu"
if [ "$(uname -s 2>/dev/null)" = "FreeBSD" ]; then
    channel=freebsd
fi
install_dir="$HOME/.local/bin"
base_url="https://github.com/danalec/rgx/releases/download"
version="rgx-v0.1.10"
skip_checksum=0

# The digest of each channel's asset.
#
# The digests are uppercase hex, like the ones in install.ps1, and they are
# rewritten in place by scripts/release-all.sh -- so the shape of these
# lines is part of the contract, not a formatting choice.
declare -A EXPECTED=(
    [gnu]="A47153015AE6136FB31B4CD57424D84323AAD655D93A61C838820A5062EBCD38"
    [musl]="7059AF7F7D92D2347055B6B6C5D2FE35F4DD5A2E4CB3BE977BE113C749E6DA6B"
    [v2]="A895E9BAABE96858B39759194C2E2F4989B95A05C34A5F20E3BEA3512DFFBA85"
    [avx2]="F1332BA39CCAD2B4DF3274C5103652798F14C9D085E7AB41EA5A23209028A45E"
    [v4]="CB88729D47C2A1175D59404BAE298D1B027B4BC01B01D0B97B9611C150C3E259"
    [znver4]="F868DA1080B3CFD49AB2940BA716BB01C3CEE3B897ACB7A9650D0621CCD2AD4E"
    [freebsd]="68EBACF8F2313F6E659F661CF3BADADCE92D27FE7542E8318C88707C2EE9CF4F"
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
    gnu)     asset="$version-x86_64-linux-gnu.tar.gz" ;;
    musl)    asset="$version-x86_64-linux-musl.tar.gz" ;;
    v2)      asset="$version-v2-linux.tar.gz" ;;
    avx2)    asset="$version-avx2-linux.tar.gz" ;;
    v4)      asset="$version-v4-linux.tar.gz" ;;
    znver4)  asset="$version-znver4-linux.tar.gz" ;;
    freebsd) asset="$version-x86_64-freebsd.tar.gz" ;;
    *) echo "unknown channel: $channel (gnu, musl, v2, avx2, v4, znver4, freebsd)" >&2; exit 2 ;;
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
    # The digest tool is the platform's, and FreeBSD does not carry
    # `sha256sum`: the base system has `sha256`, whose `-q` is the hex and
    # nothing else. A machine with neither is a machine that cannot verify,
    # and the installer says so instead of comparing against nothing.
    if command -v sha256sum > /dev/null 2>&1; then
        actual=$(sha256sum "$tmp/$asset" | awk '{print toupper($1)}')
    elif command -v sha256 > /dev/null 2>&1; then
        actual=$(sha256 -q "$tmp/$asset" | awk '{print toupper($1)}')
    elif command -v shasum > /dev/null 2>&1; then
        actual=$(shasum -a 256 "$tmp/$asset" | awk '{print toupper($1)}')
    else
        echo "no sha256 tool on this machine: neither sha256sum, sha256 nor shasum" >&2
        exit 1
    fi
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
