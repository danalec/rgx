#!/usr/bin/env bash
# rewrite-digests.sh -- rewrite the digests the two installers pin, from the
# artifacts in .dist/.
#
#   ./scripts/rewrite-digests.sh [tag]
#
# install.ps1 pins the two Windows zips and install.sh pins the three Linux
# tarballs, and both refuse a download whose digest is not the one written
# there. The pins are release data and the release owns them: they are
# rewritten from the artifacts that are about to be published, never by
# hand. A rewrite that does not move is a refusal and not a warning --
# an installer that pins the digest of an artifact nobody published throws
# "SHA256 mismatch" at every user, and it throws it on their machine and
# not here.
#
# The VERSION the installers download is release data too, so it is
# rewritten here as well: the digest of the new release written under the
# name of the old one is a mismatch at every user's machine.
#
# The tag defaults to the one the tree's version names. The script needs
# the artifacts to be in .dist/ already; a missing one is an error, because
# a pin that cannot be written is a pin that stays wrong.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
TAG="${1:-rgx-v$VERSION}"

sha256() { # sha256 <file>
  python -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest().upper())' "$1"
}

# --- the Windows pair -----------------------------------------------------------
SHA_X64="$(sha256 ".dist/$TAG-x86_64-windows.zip")"
SHA_ZN="$(sha256 ".dist/$TAG-znver4-windows.zip")"
sed -i \
  -e "s/^\( *'x64' *{ *'\)[A-F0-9]\{64\}\(' *}\)$/\1$SHA_X64\2/" \
  -e "s/^\( *'znver4' *{ *'\)[A-F0-9]\{64\}\(' *}\)$/\1$SHA_ZN\2/" \
  install.ps1
# A sed that matched nothing is a silent no-op, and the installer breaks at
# a user's machine rather than here.
grep -q "$SHA_X64" install.ps1 || { echo "install.ps1 x64 digest not rewritten" >&2; exit 1; }
grep -q "$SHA_ZN" install.ps1 || { echo "install.ps1 znver4 digest not rewritten" >&2; exit 1; }
echo ">> install.ps1: x64 $SHA_X64, znver4 $SHA_ZN"

# --- the Linux three ------------------------------------------------------------
# The Linux installer pins one line per channel, the digest in uppercase hex.
for chan in gnu musl znver4; do
  case "$chan" in
    gnu)    art=".dist/$TAG-x86_64-linux-gnu.tar.gz" ;;
    musl)   art=".dist/$TAG-x86_64-linux-musl.tar.gz" ;;
    znver4) art=".dist/$TAG-znver4-linux.tar.gz" ;;
  esac
  if [ ! -f "$art" ]; then
    echo "install.sh $chan digest not rewritten: no $art" >&2
    exit 1
  fi
  sha="$(sha256 "$art")"
  sed -i -e "s/^\( *\[$chan\]=\)\"[A-F0-9]\{64\}\"$/\1\"$sha\"/" install.sh
  # Same guard as the Windows pair: a sed that matched nothing leaves an
  # installer that refuses its own release.
  grep -q "$sha" install.sh || { echo "install.sh $chan digest not rewritten" >&2; exit 1; }
done
echo ">> install.sh: gnu, musl, znver4"

# --- the pinned version ---------------------------------------------------------
# The two installers pin the version as well as the digest, and the pin is
# release data in the same way the digest is: a hand-maintained version is a
# version that is wrong on the day after the release. Worse than wrong -- a
# rewrite of the digest alone leaves an installer that downloads the OLD
# release and expects the NEW digest, which is a mismatch at every user's
# machine.
sed -i -e "s|^version=\"rgx-v[^\"]*\"|version=\"$TAG\"|" install.sh
sed -i -e "s|^\([[:space:]]*\)\[string\]\$Version = 'rgx-v[^']*'|\1[string]\$Version = '$TAG'|" install.ps1
# Same guard as the digests: a sed that matched nothing leaves an installer
# that installs the release before this one.
grep -q "^version=\"$TAG\"\$" install.sh || { echo "install.sh version not rewritten" >&2; exit 1; }
grep -q "\[string\]\$Version = '$TAG'" install.ps1 || { echo "install.ps1 version not rewritten" >&2; exit 1; }
echo ">> installers: version $TAG"

echo ">> installer pins rewritten for $TAG"
