#!/usr/bin/env bash
# rewrite-digests.sh -- the digests the two installers pin, from the
# artifacts of a release.
#
#   ./scripts/rewrite-digests.sh [tag]                  # from .dist/
#   ./scripts/rewrite-digests.sh --from-release [tag]   # from the GitHub release
#   ./scripts/rewrite-digests.sh --check [tag]          # say whether they are right
#
# install.ps1 pins the two Windows zips and install.sh pins the four unix
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
# **Where the artifacts come from.** By default they are in .dist/, where
# the local release flow built them. `--from-release` reads the release
# itself: the archives are downloaded from the GitHub release of <tag> and
# the pins are written from those bytes. That is the only source there is
# when the release was cut by the CI and not on this machine -- and it is
# the case this flag was written for: 0.1.9.0 shipped with the previous
# release's digests because the tag-push workflow built the archives and
# nothing rewrote the pins from what it had published.
#
# **--check writes nothing.** It copies the installers, runs the same
# rewrite on the copies, and compares: the answer is "the pins name <tag>"
# or it is not, and the working tree is untouched either way. That is the
# command an operator runs after a publish -- and the gate a flow can run
# where the tree is, because it needs no release data of its own.
#
# The tag defaults to the one the tree's version names, and a missing
# artifact is an error: a pin that cannot be written is a pin that stays
# wrong.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

FROM_RELEASE=0
CHECK=0
TAG=""
for arg in "$@"; do
  case "$arg" in
    --from-release) FROM_RELEASE=1 ;;
    --check) CHECK=1 ;;
    -*) echo "unknown option: $arg" >&2; exit 2 ;;
    *) TAG="$arg" ;;
  esac
done

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
[ -n "$TAG" ] || TAG="rgx-v$VERSION"

sha256() { # sha256 <file>
  python -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest().upper())' "$1"
}

# The directory the artifacts are read from. `--from-release` fills it from
# the release, and the temporary one goes when the script does.
WORK=""
if [ "$FROM_RELEASE" = 1 ]; then
  command -v gh > /dev/null 2>&1 || {
    echo "gh not found: --from-release reads the artifacts from the release" >&2
    exit 1
  }
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
  gh release download "$TAG" --repo danalec/rgx --dir "$WORK" || {
    echo "the assets of $TAG could not be downloaded" >&2
    exit 1
  }
  DIST="$WORK"
else
  DIST=".dist"
fi

# Where the installers are written. `--check` writes to copies, so the
# answer costs the working tree nothing.
INSTALLERS="$ROOT"
if [ "$CHECK" = 1 ]; then
  INSTALLERS="$(mktemp -d)"
  trap 'rm -rf "$WORK" "$INSTALLERS"' EXIT
  cp install.sh install.ps1 "$INSTALLERS/"
fi
PS1="$INSTALLERS/install.ps1"
SH="$INSTALLERS/install.sh"

# --- the Windows pair -----------------------------------------------------------
SHA_X64="$(sha256 "$DIST/$TAG-x86_64-windows.zip")"
SHA_ZN="$(sha256 "$DIST/$TAG-znver4-windows.zip")"
sed -i \
  -e "s/^\( *'x64' *{ *'\)[A-F0-9]\{64\}\(' *}\)$/\1$SHA_X64\2/" \
  -e "s/^\( *'znver4' *{ *'\)[A-F0-9]\{64\}\(' *}\)$/\1$SHA_ZN\2/" \
  "$PS1"
# A sed that matched nothing is a silent no-op, and the installer breaks at
# a user's machine rather than here.
grep -q "$SHA_X64" "$PS1" || { echo "install.ps1 x64 digest not rewritten" >&2; exit 1; }
grep -q "$SHA_ZN" "$PS1" || { echo "install.ps1 znver4 digest not rewritten" >&2; exit 1; }
echo ">> install.ps1: x64 $SHA_X64, znver4 $SHA_ZN"

# --- the unix four --------------------------------------------------------------
# The unix installer pins one line per channel, the digest in uppercase hex.
# FreeBSD is one of them, and it is the one the release workflow builds inside
# a VM: a channel the rewriter does not know is a channel whose pin stays at
# the previous release, and the installer refuses its own release on the one
# platform whose archive is not built on a runner.
for chan in gnu musl znver4 freebsd; do
  case "$chan" in
    gnu)     art="$DIST/$TAG-x86_64-linux-gnu.tar.gz" ;;
    musl)    art="$DIST/$TAG-x86_64-linux-musl.tar.gz" ;;
    znver4)  art="$DIST/$TAG-znver4-linux.tar.gz" ;;
    freebsd) art="$DIST/$TAG-x86_64-freebsd.tar.gz" ;;
  esac
  if [ ! -f "$art" ]; then
    echo "install.sh $chan digest not rewritten: no $art" >&2
    exit 1
  fi
  sha="$(sha256 "$art")"
  sed -i -e "s/^\( *\[$chan\]=\)\"[A-F0-9]\{64\}\"$/\1\"$sha\"/" "$SH"
  # Same guard as the Windows pair: a sed that matched nothing leaves an
  # installer that refuses its own release.
  grep -q "$sha" "$SH" || { echo "install.sh $chan digest not rewritten" >&2; exit 1; }
done
echo ">> install.sh: gnu, musl, znver4, freebsd"

# --- the pinned version ---------------------------------------------------------
# The two installers pin the version as well as the digest, and the pin is
# release data in the same way the digest is: a hand-maintained version is a
# version that is wrong on the day after the release. Worse than wrong -- a
# rewrite of the digest alone leaves an installer that downloads the OLD
# release and expects the NEW digest, which is a mismatch at every user's
# machine.
sed -i -e "s|^version=\"rgx-v[^\"]*\"|version=\"$TAG\"|" "$SH"
sed -i -e "s|^\([[:space:]]*\)\[string\]\$Version = 'rgx-v[^']*'|\1[string]\$Version = '$TAG'|" "$PS1"
# Same guard as the digests: a sed that matched nothing leaves an installer
# that installs the release before this one.
grep -q "^version=\"$TAG\"\$" "$SH" || { echo "install.sh version not rewritten" >&2; exit 1; }
grep -q "\[string\]\$Version = '$TAG'" "$PS1" || { echo "install.ps1 version not rewritten" >&2; exit 1; }
echo ">> installers: version $TAG"

# --- the check ------------------------------------------------------------------
# The copies were rewritten and the originals were not: if the two agree,
# the originals already named this release, and the tree needs nothing. If
# they do not, the pins are the previous release's and the diff says which.
if [ "$CHECK" = 1 ]; then
  stale=0
  for pair in "install.sh:install.sh" "install.ps1:install.ps1"; do
    name="${pair%%:*}"
    if ! cmp -s "$INSTALLERS/$name" "$ROOT/$name"; then
      echo "the pins in $name do not name $TAG:" >&2
      diff -u "$ROOT/$name" "$INSTALLERS/$name" | sed -n '1,24p' >&2 || true
      stale=1
    fi
  done
  if [ "$stale" = 0 ]; then
    echo ">> the pins name $TAG"
    exit 0
  fi
  echo "run scripts/rewrite-digests.sh $TAG --from-release, and commit the installers" >&2
  exit 1
fi

echo ">> installer pins rewritten for $TAG"
