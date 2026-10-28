#!/usr/bin/env bash
# release-all.sh — the whole rgx release from one command, in bash
# (Git Bash or WSL; cargo must be on PATH for the Windows builds).
#
#   ./scripts/release-all.sh [--skip-tests] [--dry-run] [--no-commit]
#
# Pipeline: gate (fmt/clippy/tests) -> Windows zips (x86_64 + znver4)
# -> Linux (ssh to the docker host, build-linux.sh) -> publish (tag +
# forgejo release + assets + winget manifests + validate + commit).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

SKIP_TESTS=0; DRY_RUN=0; COMMIT_MANIFESTS=1
while [ $# -gt 0 ]; do
  case "$1" in
    --skip-tests) SKIP_TESTS=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --no-commit) COMMIT_MANIFESTS=0 ;;
    *) echo "unknown flag: $1"; exit 2 ;;
  esac
  shift
done

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
TAG="rgx-v$VERSION"
# The forgejo is this machine's development upstream, and where it lives is
# the operator's business, not the project's: the address of a private box
# is not a fact about rgx. It comes from the environment, and the values
# below are only the defaults the owner runs with.
FORGEJO_URL="${RGX_FORGEJO_URL:-http://192.168.0.10:3000}"
FORGEJO_REPO="${RGX_FORGEJO_REPO:-danalec/rgx}"
FORGEJO="$FORGEJO_URL/$FORGEJO_REPO"
REPO_API="$FORGEJO_URL/api/v1/repos/$FORGEJO_REPO"
# The host and the port the credentials are stored under, taken from the
# URL, so that a different forgejo needs no second place to be written.
FORGEJO_HOST="$(printf '%s' "$FORGEJO_URL" | sed -e 's|^[a-zA-Z]*://||' -e 's|/.*$||')"
HOST="${RGX_RELEASE_HOST:-root@192.168.0.10}"
REMOTE="/tmp/rgx-release"

echo ">> rgx $VERSION ($TAG)"

# --- 0. gate ------------------------------------------------------------------
if [ "$SKIP_TESTS" = 0 ]; then
  echo ">> gate: clippy -D warnings + tests"
  cargo clippy --release --workspace --all-targets -- -D warnings
  # --workspace for the same reason as .github/workflows/ci.yml: without it
  # the gate runs 315 of the 2,558 tests and the release is signed against
  # the root package alone.
  cargo test --release --locked --workspace
else
  echo ">> gate skipped"
fi

# --- 1. Windows zips -----------------------------------------------------------
echo ">> windows: x86_64"
cargo build --release --locked 2>&1 | tail -1
echo ">> windows: znver4"
RUSTFLAGS="-C target-cpu=znver4" CARGO_TARGET_DIR=target/release-znver4 \
  cargo build --release --locked 2>&1 | tail -1

mkdir -p .dist
make_zip() { # make_zip <exe> <name>
  local stage=".dist/$2"
  rm -rf "$stage"; mkdir -p "$stage"
  cp "$1" "$stage/rgx.exe"
  cp README.md COPYING LICENSE-APACHE NOTICE "$stage/"
  rm -f ".dist/$2.zip"
  (cd .dist && python -m zipfile -c "$2.zip" "$2")
  rm -rf "$stage"
  echo ">> built .dist/$2.zip"
}
make_zip target/release/rgx.exe "$TAG-x86_64-windows"
make_zip target/release-znver4/release/rgx.exe "$TAG-znver4-windows"

# smoke
./target/release/rgx.exe --version >/dev/null
SMOKE_FILE="$(mktemp)"; echo smoke > "$SMOKE_FILE"
./target/release/rgx.exe smoke "$SMOKE_FILE" >/dev/null
rm -f "$SMOKE_FILE"

# --- 2. Linux via docker host --------------------------------------------------
echo ">> linux: build on $HOST"
if [ "$DRY_RUN" = 0 ]; then
  git push forgejo main 2>&1 | tail -1 || true
  ssh "$HOST" "rm -rf '$REMOTE' && mkdir -p '$REMOTE' && git clone --depth 1 -q '$FORGEJO.git' '$REMOTE/src'"
  ssh "$HOST" "bash '$REMOTE/src/scripts/build-linux.sh' '$FORGEJO.git' main '$REMOTE/out'"
  scp -q "$HOST:$REMOTE/out/"* .dist/
  ssh "$HOST" "rm -rf '$REMOTE'"
  echo ">> linux artifacts fetched"
else
  echo "[dry-run] would build linux artifacts on $HOST"
fi

# --- 3. publish ----------------------------------------------------------------
# forgejo auth from stored git credentials (same trick as publish-release.ps1)
CRED="$(git credential fill <<EOF
protocol=http
host=$FORGEJO_HOST
EOF
)"
FUSER="$(printf '%s\n' "$CRED" | sed -n 's/^username=//p')"
TOKEN="$(printf '%s\n' "$CRED" | sed -n 's/^password=//p')"
[ -n "$TOKEN" ] || { echo "no forgejo credentials in git credential store"; exit 1; }
# forgejo accepts basic auth from stored git credentials; a bare
# 'Authorization: token' header 401s with password-type credentials.
AUTH=(-u "$FUSER:$TOKEN")

BODY="Search inside everything — PDFs, Office documents, archives, 3D models, LLM checkpoints, databases, e-mail. Ripgrep-compatible, adapters in-process.

**Windows** (portable zip): \`$TAG-x86_64-windows.zip\` (generic x86-64), \`$TAG-znver4-windows.zip\` (AMD Zen 4)

**Linux**: \`$TAG-x86_64-linux-gnu.tar.gz\` (glibc ≥ 2.31), \`$TAG-x86_64-linux-musl.tar.gz\` (static), \`$TAG-znver4-linux.tar.gz\` (Zen 4); distro packages: \`.deb\` (Debian/Ubuntu), \`.rpm\` (Fedora/RHEL), \`.apk\` (Alpine), \`.pkg.tar.zst\` (Arch) — each install-tested in its own container.

Apache-2.0."

api() { curl -sf "${AUTH[@]}" "$@"; }

# --- 4. winget manifests -------------------------------------------------------
SHA="$(python -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest().upper())' ".dist/$TAG-x86_64-windows.zip")"
TODAY="$(date +%F)"
setyaml() { # setyaml <file> <sed-expr...>
  if [ "$DRY_RUN" = 1 ]; then echo "[dry-run] sed -i $*"; else sed -i "$@"; fi
}
echo ">> winget manifests: version $VERSION, sha256 $SHA, date $TODAY"
setyaml .winget/danalec.rgx.installer.yaml \
  -e "s/^PackageVersion: .*/PackageVersion: $VERSION/" \
  -e "s/^ReleaseDate: .*/ReleaseDate: $TODAY/" \
  -e "s|^\([[:space:]]*\)InstallerUrl: .*|\1InstallerUrl: $FORGEJO/releases/download/$TAG/$TAG-x86_64-windows.zip|" \
  -e "s/^\([[:space:]]*\)InstallerSha256: .*/\1InstallerSha256: $SHA/"
setyaml .winget/danalec.rgx.yaml -e "s/^PackageVersion: .*/PackageVersion: $VERSION/"
setyaml .winget/danalec.rgx.locale.en-US.yaml \
  -e "s/^PackageVersion: .*/PackageVersion: $VERSION/" \
  -e "s|^ReleaseNotesUrl: .*|ReleaseNotesUrl: $FORGEJO/releases/tag/$TAG|"

WINGET="$LOCALAPPDATA/Microsoft/WindowsApps/winget.exe"
if [ -x "$WINGET" ] && [ "$DRY_RUN" = 0 ]; then
  "$WINGET" validate --manifest .winget
  echo ">> winget validate: ok"
else
  echo ">> winget validate skipped"
fi

if [ "$COMMIT_MANIFESTS" = 1 ] && [ "$DRY_RUN" = 0 ]; then
  git add .winget
  git commit -m "release: $TAG winget manifests" || true
  git push forgejo "$(git rev-parse --abbrev-ref HEAD)" 2>&1 | tail -1
fi

# --- 5. installer checksums ----------------------------------------------------
# BOTH installers pin the digests of the assets they are allowed to install,
# and both refuse a download that does not match: install.ps1 for the two
# Windows zips, install.sh for the three Linux tarballs. Those digests used
# to be hand-maintained, which means a release cut by hand shipped an
# installer that threw "SHA256 mismatch" at every user until someone noticed
# and edited a constant. They are rewritten here for the same reason the
# winget manifests are: the release owns the values it publishes.
#
# The rewriting lives in scripts/rewrite-digests.sh, and not here, because
# the GitHub publish path has to do the same thing: an artifact rebuilt
# outside this script leaves the pins naming an artifact that is no longer
# published, and the installer throws at every user who runs it.
if [ "$DRY_RUN" = 1 ]; then
  echo "[dry-run] scripts/rewrite-digests.sh $TAG"
else
  bash scripts/rewrite-digests.sh "$TAG"
fi

# --- 6. the commit, the tag, and the release ----------------------------------
# The commit carries the release's own data -- the winget manifests and the
# two installers -- and the tag goes on that commit. The order is the whole
# point: a tag placed before the rewrite points at the previous release's
# pins, and the installer in that tree throws "SHA256 mismatch" at every
# user who runs it.
if [ "$COMMIT_MANIFESTS" = 1 ] && [ "$DRY_RUN" = 0 ]; then
  git add .winget install.sh install.ps1
  git commit -m "release: $TAG winget manifests and installer pins" || true
  git push forgejo "$(git rev-parse --abbrev-ref HEAD)" 2>&1 | tail -1
fi

if [ "$DRY_RUN" = 1 ]; then
  echo "[dry-run] would create/patch release $TAG and upload $(ls .dist | wc -l) assets"
else
  echo ">> publish: tag $TAG"
  git tag -f "$TAG" >/dev/null 2>&1 || git tag "$TAG"
  git push -f forgejo "$TAG" 2>&1 | tail -1 || true

  echo ">> publish: release $TAG"
  if ! REL="$(api "$REPO_API/releases/tags/$TAG")"; then
    REL="$(api -X POST "$REPO_API/releases" -H 'Content-Type: application/json' \
      -d "$(python -c 'import json,sys; print(json.dumps({"tag_name": sys.argv[1], "name": "rgx v"+sys.argv[2], "body": sys.argv[3]}))' "$TAG" "$VERSION" "$BODY")")"
  else
    REL_ID="$(printf '%s' "$REL" | python -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
    api -X PATCH "$REPO_API/releases/$REL_ID" -H 'Content-Type: application/json' \
      -d "$(python -c 'import json,sys; print(json.dumps({"name": "rgx v"+sys.argv[1], "body": sys.argv[2]}))' "$VERSION" "$BODY")" >/dev/null
    REL="$(api "$REPO_API/releases/tags/$TAG")"
  fi
  REL_ID="$(printf '%s' "$REL" | python -c 'import json,sys; print(json.load(sys.stdin)["id"])')"

  for f in .dist/*; do
    name="$(basename "$f")"
    # Only this version's artifacts. `.dist/` is not wiped between runs, so
    # a previous build's zips are still sitting in it -- `for f in .dist/*`
    # uploaded 0.1.0's nine files into the 0.2.0 release the first time.
    case "$name" in
      *"$VERSION"*) ;;
      *) continue ;;
    esac
    STALE="$(printf '%s' "$REL" | python -c 'import json,sys
for a in json.load(sys.stdin).get("assets", []):
    if a["name"] == "'"$name"'": print(a["id"])')"
    [ -n "$STALE" ] && api -X DELETE "$REPO_API/releases/$REL_ID/assets/$STALE" >/dev/null
    curl -sf "${AUTH[@]}" \
      -X POST "$REPO_API/releases/$REL_ID/assets?name=$name" \
      -H "Content-Type: application/octet-stream" --data-binary "@$f" >/dev/null
    echo ">> uploaded $name"
  done
fi

echo ">> release $TAG complete: $FORGEJO/releases/tag/$TAG"
