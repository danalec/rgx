#!/usr/bin/env bash
# release-linux.sh — one command: build all Linux artifacts for the current
# rgx release and land them in .dist/ on this machine.
#
#   ./scripts/release-linux.sh [ref]
#
# Flow: push <ref> to forgejo -> on the docker host (unraid), clone <ref> and
# run scripts/build-linux.sh -> copy the verified artifacts back to .dist/.
# Requires only git, ssh and scp on this side. Built to run from WSL
# or Git Bash.
#
# The ref defaults to main. The host comes from RGX_RELEASE_HOST, and the
# forgejo from RGX_FORGEJO_URL and RGX_FORGEJO_REPO, so the script does not
# hardcode one person's box.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

REF="${1:-main}"
# Where the Linux build runs. Overridable so the published script does not
# hardcode one person's box; the default is the host this was written on.
HOST="${RGX_RELEASE_HOST:-root@192.168.0.10}"
# The forgejo the clone comes from, for the same reason: the address of a
# private box is not a fact about the project.
FORGEJO_URL="${RGX_FORGEJO_URL:-http://192.168.0.10:3000}"
FORGEJO_REPO="${RGX_FORGEJO_REPO:-danalec/rgx}"
FORGEJO="$FORGEJO_URL/$FORGEJO_REPO.git"
REMOTE="/tmp/rgx-release"
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"

echo ">> pushing $REF to forgejo"
git push forgejo "$REF" 2>&1 | tail -1 || true

echo ">> syncing source on $HOST"
ssh "$HOST" "rm -rf '$REMOTE' && mkdir -p '$REMOTE' && git clone --depth 1 --branch '$REF' '$FORGEJO' '$REMOTE/src' 2>&1 | tail -1"

echo ">> building linux artifacts on $HOST (this takes several minutes)"
ssh "$HOST" "RGX_DOCKER_NET='${RGX_DOCKER_NET:-}' bash '$REMOTE/src/scripts/build-linux.sh' '$FORGEJO' '$REF' '$REMOTE/out'"

echo ">> fetching artifacts to .dist/"
mkdir -p .dist
scp -q "$HOST:$REMOTE/out/"* .dist/
ssh "$HOST" "rm -rf '$REMOTE'"

echo ">> .dist/ now holds:"
ls -la .dist/
echo ">> next: publish-release.ps1 -Version $VERSION (bumps winget SHA/URLs)"
