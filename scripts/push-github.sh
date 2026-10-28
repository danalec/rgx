#!/usr/bin/env bash
# push-github.sh — mirror the rgx release to GitHub, one command, in bash.
#
#   ./scripts/push-github.sh              # dry-run: print every step, touch nothing
#   ./scripts/push-github.sh --push       # do it (Forgejo is pushed FIRST)
#   ./scripts/push-github.sh --push --public   # create the GitHub repo public
#   ./scripts/push-github.sh --push --public --flat  # one commit, no history
#
# The Forgejo instance is the development upstream; GitHub is the public
# mirror. This script:
#   1. re-points the winget manifests at the GitHub release URLs (commit)
#   2. moves the rgx-v<version> tag onto that commit and pushes Forgejo first
#   3. creates danalec/rgx on GitHub (--public or private) and pushes
#   4. creates the GitHub release with the 9 assets already in .dist/
#   5. re-runs winget validate on the re-pointed manifests
#
# --flat pushes a mirror with one commit -- the tree as it is -- so a clone
# of it reads like a project that started today. The history stays on the
# Forgejo.
#
# Requires: gh (authenticated), the release tag present locally, and .dist/
# populated by a previous release-all.sh run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PUSH=0; PUBLIC="--private"; FLAT=0
while [ $# -gt 0 ]; do
  case "$1" in
    --push) PUSH=1 ;;
    --public) PUBLIC="--public" ;;
    --flat) FLAT=1 ;;
    *) echo "unknown flag: $1"; exit 2 ;;
  esac
  shift
done

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
TAG="rgx-v$VERSION"
GH_REPO="danalec/rgx"
GH="https://github.com/$GH_REPO"

# The assets the release carries, by name. The list is explicit because
# .dist/ also holds the working files of whoever built the release -- a
# corpus, a samples directory, a handful of probe scripts -- and a glob
# over it would upload all of that to the world.
ASSETS=(
  "$TAG-x86_64-windows.zip"
  "$TAG-znver4-windows.zip"
  "$TAG-x86_64-linux-gnu.tar.gz"
  "$TAG-x86_64-linux-musl.tar.gz"
  "$TAG-znver4-linux.tar.gz"
  "rgx_${VERSION}_amd64.deb"
  "rgx-${VERSION}-1.x86_64.rpm"
  "rgx_${VERSION}_x86_64.apk"
  "rgx-${VERSION}-1-x86_64.pkg.tar.zst"
)

# The macOS archives. The CI builds them on its macos runners; the local
# pipeline builds the windows ones and the docker host the linux ones, so
# the release is a joint act. Homebrew installs from the macOS archive, so
# a release without one is a release `brew install` cannot use -- and the
# formula's digests are the digests of the archives that are about to be
# published, not of the ones an older release carried.
MAC_ASSETS=(
  "$TAG-aarch64-macos.tar.gz"
  "$TAG-x86_64-macos.tar.gz"
)

# The formula the release repository holds and that
# scripts/publish-homebrew.sh opens the homebrew-core pull request with.
formula="Formula/rgx.rb"

# The digest of a file.
#
# MSYS2's sha256sum puts a backslash in front of a digest it computed in
# binary mode, and the mode follows the name of the file: a path with a
# backslash in it gets one. The digest is the digest, so the marker is
# taken off -- a digest with a backslash in it is a digest of nothing, and
# a backslash in a regular expression is an invalid back reference.
sha256() { # sha256 <file>
  sha256sum "$1" | cut -d' ' -f1 | tr -d '\\'
}

run() { # run <description> <command...>
  local desc="$1"; shift
  if [ "$PUSH" = 1 ]; then
    echo ">> $desc"
    "$@"
  else
    echo "[dry-run] $desc: $*"
  fi
}

# --- preflight ------------------------------------------------------------------
git rev-parse "$TAG" >/dev/null 2>&1 || { echo "tag $TAG not found — run release-all.sh first"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "gh not authenticated"; exit 1; }
N_ASSETS="$(ls .dist 2>/dev/null | wc -l | tr -d ' ')"
[ "$N_ASSETS" -ge 9 ] || { echo ".dist/ has $N_ASSETS assets, expected 9 — run release-all.sh first"; exit 1; }

echo ">> rgx $VERSION ($TAG) -> $GH"

# --- 0. the macOS archives ---------------------------------------------------
# The CI run of this tag is where the macOS archives are made, so they are
# fetched from it when it has produced them. A machine with no macOS
# archive has no digest to write, and the script says so instead of
# carrying a digest of nothing.
mac_assets=""
for a in "${MAC_ASSETS[@]}"; do
  [ -f ".dist/$a" ] && mac_assets="$mac_assets .dist/$a"
done
if [ -z "$mac_assets" ] && [ "$PUSH" = 1 ]; then
  echo ">> macOS archives: not in .dist/, asking the CI run of $TAG"
  # `gh run download` takes the ID of the run, not the tag that started it,
  # and the run only exists once the tag is on GitHub. So the tag is looked
  # up among the runs of the release workflow. Each artifact is fetched BY
  # NAME: without the name the run puts every artifact in a directory of its
  # own, and the archives would land one level deeper than the place the
  # rest of the script looks in -- and the script would then say the release
  # carries no macOS archive when the CI had built two.
  run_id="$(gh run list --repo "$GH_REPO" --workflow release.yml --event push --limit 50 \
    --json databaseId,headBranch --jq ".[] | select(.headBranch == \"$TAG\") | .databaseId" 2>/dev/null | head -1 || true)"
  if [ -n "$run_id" ]; then
    for a in "${MAC_ASSETS[@]}"; do
      gh run download "$run_id" --repo "$GH_REPO" --name "${a%.tar.gz}" --dir .dist || true
    done
    for a in "${MAC_ASSETS[@]}"; do
      [ -f ".dist/$a" ] && mac_assets="$mac_assets .dist/$a"
    done
  else
    echo ">> no CI run for $TAG: the tag has to be on GitHub before the archives exist" >&2
  fi
fi
if [ -z "$mac_assets" ]; then
  echo ">> macOS archives: none -- the release carries none and the brew formula is not touched"
else
  # The formula names one archive per architecture and the rewrite follows
  # that order, so a release carrying only one of the two would leave the
  # other url with no archive and its sha256 empty -- a digest of nothing,
  # which is the one thing the rewrite exists not to carry. The publish
  # stops here, before it touches the tree.
  formula_urls=$(grep -c '^[[:space:]]*url "' "$formula" || true)
  archive_count=0
  for f in $mac_assets; do archive_count=$((archive_count + 1)); done
  if [ "$formula_urls" -ne "$archive_count" ]; then
    echo ">> brew formula: $archive_count macOS archive(s) for $formula_urls url(s) in the formula" >&2
    echo ">> the release carries one architecture only; publish both, then run this again" >&2
    exit 1
  fi
  for f in $mac_assets; do echo ">> macOS archive: $f"; done
fi

# --- 1. winget manifests point at GitHub ---------------------------------------
echo ">> winget manifests: re-point installer/release URLs at $GH"
if [ "$PUSH" = 1 ]; then
  sed -i \
    -e "s|^\([[:space:]]*\)InstallerUrl: .*|\1InstallerUrl: $GH/releases/download/$TAG/$TAG-x86_64-windows.zip|" \
    .winget/danalec.rgx.installer.yaml
  sed -i \
    -e "s|^\([[:space:]]*\)ReleaseNotesUrl: .*|\1ReleaseNotesUrl: $GH/releases/tag/$TAG|" \
    .winget/danalec.rgx.locale.en-US.yaml
  # The manifest names the same zip the release carries, so its hash is the
  # hash of the file that is about to be uploaded -- not the hash of the one
  # the manifest was written for. This happens before the mirror is built:
  # the mirror is the tree as it is at this point, and a manifest that names
  # a hash the release does not have is a manifest that installs nothing.
  ZIP="$TAG-x86_64-windows.zip"
  SHA="$(sha256 ".dist/$ZIP" | tr '[:lower:]' '[:upper:]')"
  sed -i \
    -e "s|^\([[:space:]]*\)InstallerSha256: .*|\1InstallerSha256: $SHA|" \
    .winget/danalec.rgx.installer.yaml
  echo ">> winget installer hash: $SHA"
  # The two installers pin the digests of the assets they are allowed to
  # install, and both refuse a download that does not match. The pins are
  # rewritten from the assets this release carries: an artifact rebuilt
  # outside the release flow leaves the pins naming an artifact that is no
  # longer published, and the installer then throws "SHA256 mismatch" at
  # every user who runs it.
  bash scripts/rewrite-digests.sh "$TAG"
  # --- the brew formula -----------------------------------------------------
  # The formula names the macOS archives, so its digests are the digests of
  # the files that are about to be published. A machine with no macOS
  # archive has no digest to write, and the formula says so instead of
  # carrying a digest of nothing.
  #
  # The formula lists the archives in the order they appear in it -- arm
  # first, then intel -- and the rewrite follows that order: the n-th url
  # line gets the n-th archive's URL, the n-th sha256 line its digest.
  if [ -z "$mac_assets" ]; then
    echo ">> brew formula: not touched (no macOS archive)"
  else
    names=""
    shas=""
    for f in $mac_assets; do
      names="$names${names:+,}$(basename "$f")"
      shas="$shas${shas:+,}$(sha256 "$f")"
    done
    awk -v names="$names" -v shas="$shas" -v base="$GH/releases/download/$TAG" -v ver="$VERSION" '
      BEGIN { split(names, N, ","); split(shas, S, ","); ui = 1; si = 1; vi = 0 }
      $0 ~ /^[[:space:]]*url "/ {
        match($0, /^[[:space:]]*/)
        printf "%surl \"%s/%s\"\n", substr($0, 1, RLENGTH), base, N[ui++]; next
      }
      $0 ~ /^[[:space:]]*sha256 "/ {
        match($0, /^[[:space:]]*/)
        printf "%ssha256 \"%s\"\n", substr($0, 1, RLENGTH), S[si++]; next
      }
      $0 ~ /^[[:space:]]*version "/ && vi++ == 0 {
        match($0, /^[[:space:]]*/)
        printf "%sversion \"%s\"\n", substr($0, 1, RLENGTH), ver; next
      }
      { print }
    ' "$formula" > "$formula.tmp"
    # A rewrite that does not move is a refusal and not a warning. The awk
    # above prints the lines it does not recognise as it found them, so a
    # formula whose shape changed keeps the old URLs and the old digests
    # under a new version: a formula that installs the release before this
    # one, and one that refuses its own archive with "SHA256 mismatch" at
    # the user's machine and not here. The check runs on the temporary
    # file, so a refusal leaves the tree as it was.
    ok=1
    grep -qF "version \"$VERSION\"" "$formula.tmp" || {
      echo ">> brew formula: the version was not rewritten" >&2; ok=0; }
    for f in $mac_assets; do
      b="$(basename "$f")"
      d="$(sha256 "$f")"
      grep -qF "releases/download/$TAG/$b\"" "$formula.tmp" || {
        echo ">> brew formula: the url of $b was not rewritten" >&2; ok=0; }
      grep -qF "\"$d\"" "$formula.tmp" || {
        echo ">> brew formula: the digest of $b was not rewritten" >&2; ok=0; }
    done
    if [ "$ok" != 1 ]; then
      rm -f "$formula.tmp"
      exit 1
    fi
    mv "$formula.tmp" "$formula"
    echo ">> brew formula: version $VERSION"
    for f in $mac_assets; do
      echo "    $(sha256 "$f")  $(basename "$f")"
    done
  fi
  git add .winget install.sh install.ps1 Formula
  git commit -m "port: point the winget manifests, the installer pins and the brew formula at the GitHub release" || true
  WINGET="$LOCALAPPDATA/Microsoft/WindowsApps/winget.exe"
  [ -x "$WINGET" ] && "$WINGET" validate --manifest .winget && echo ">> winget validate: ok"
fi

# --- 2. Forgejo first ------------------------------------------------------------
# The forgejo is the development upstream, so it goes first -- but a mirror
# that is down must not hold the public one hostage: the push is reported
# and the port goes ahead.
if ! run "push forgejo main" git push forgejo main; then
  echo ">> the forgejo did not take the push; the public mirror goes ahead anyway"
fi
if ! run "move tag $TAG onto the port commit + push forgejo" bash -c "git tag -f '$TAG' && git push -f forgejo '$TAG'"; then
  echo ">> the forgejo did not take the tag; the public mirror goes ahead anyway"
fi

# --- 3. GitHub repo + push --------------------------------------------------------
if [ "$FLAT" = 1 ]; then
  # The mirror carries one commit: the tree as it is now. The history stays
  # on the forgejo, which is the development upstream, and a clone of the
  # mirror reads like a project that started today.
  echo ">> flat mirror: one commit, the tree as it is"
  FLAT_DIR="$(mktemp -d)"
  git archive HEAD | tar -x -C "$FLAT_DIR"
  (
    cd "$FLAT_DIR"
    git init -q -b main
    # The file set is the source tree's, and it comes from its index. A
    # plain `git add -A` applies the .gitignore rules and drops the files
    # the tree tracks on purpose -- tests/fixtures/.gitignore is one of
    # them -- while the rules that keep the legacy corpus out are the same
    # rules. So the paths come from the index, added with the rules out of
    # the way.
    git -C "$ROOT" ls-files -z | xargs -0 -r git add -f --
    # The modes come from the source tree's index too. A fresh `git add` on
    # Windows records what the filesystem says, and the filesystem there has
    # no exec bit to say: the archive extraction leaves some files with it
    # and some without, and a script that lost it answers "Permission
    # denied" when it is called directly, which is what the CI does with
    # `scripts/package-linux.sh`. So every mode is set here, to the one the
    # source tree has.
    while IFS= read -r -d '' entry; do
      meta="${entry%%$'\t'*}"
      path="${entry#*$'\t'}"
      mode="${meta%% *}"
      if [ "$mode" = "100755" ]; then
        git update-index --chmod=+x -- "$path"
      else
        git update-index --chmod=-x -- "$path"
      fi
    done < <(git -C "$ROOT" ls-files -s -z)
    git commit -q -m "rgx $VERSION"
    git tag "$TAG"
  )
  if ! gh repo view "$GH_REPO" >/dev/null 2>&1; then
    run "create GitHub repo ($PUBLIC)" gh repo create "$GH_REPO" $PUBLIC
  fi
  (
    cd "$FLAT_DIR"
    git remote add github "$GH.git" 2>/dev/null || true
    git remote set-url github "$GH.git"
    git push -f -u github main
    git push -f github "$TAG"
  )
  rm -rf "$FLAT_DIR"
else
  if gh repo view "$GH_REPO" >/dev/null 2>&1; then
    echo ">> repo $GH_REPO already exists"
  else
    run "create GitHub repo ($PUBLIC)" gh repo create "$GH_REPO" $PUBLIC --source . --remote github
  fi
  git remote get-url github >/dev/null 2>&1 || \
    run "add github remote" git remote add github "$GH.git"
  run "push github main" git push -u github main
  run "push github tag" git push -f github "$TAG"
fi

# --- 4. GitHub release with the same 9 assets, plus the macOS ones -------------
BODY="Search inside everything — PDFs, Office documents, archives, 3D models, LLM checkpoints, databases, e-mail. Ripgrep-compatible, adapters in-process.

**Windows** (portable zip): \`$TAG-x86_64-windows.zip\` (generic x86-64), \`$TAG-znver4-windows.zip\` (AMD Zen 4)

**Linux**: \`$TAG-x86_64-linux-gnu.tar.gz\` (glibc ≥ 2.31), \`$TAG-x86_64-linux-musl.tar.gz\` (static), \`$TAG-znver4-linux.tar.gz\` (Zen 4); distro packages: \`.deb\` (Debian/Ubuntu), \`.rpm\` (Fedora/RHEL), \`.apk\` (Alpine), \`.pkg.tar.zst\` (Arch) — each install-tested in its own container.

**macOS**: \`$TAG-aarch64-macos.tar.gz\` (Apple Silicon), \`$TAG-x86_64-macos.tar.gz\` (Intel) — the archives Homebrew installs from.

Also on crates.io as \`rgx-search\`, which installs the same \`rgx\` binary.

Apache-2.0."

if [ "$PUSH" = 1 ]; then
  if gh release view "$TAG" --repo "$GH_REPO" >/dev/null 2>&1; then
    # The repository is named here because the local clone has no GitHub
    # remote to infer it from -- the mirror is pushed from a scratch
    # directory, and the tree this script runs in knows the forgejo and
    # nothing else. Without it `gh` looks for a GitHub remote, does not find
    # one, and the delete fails on a release the script is about to
    # recreate: the port then stops with the old release still published.
    gh release delete "$TAG" --repo "$GH_REPO" --yes
  fi
  FILES=()
  for a in "${ASSETS[@]}"; do
    [ -f ".dist/$a" ] || { echo "missing asset: .dist/$a"; exit 1; }
    FILES+=(".dist/$a")
  done
  # The macOS archives ride along when the CI has produced them. A release
  # created without them is a release `brew install` cannot use, and the
  # release is deleted and recreated here -- so the ones an older publish
  # carried are only kept when they are fetched again first.
  for f in $mac_assets; do FILES+=("$f"); done
  gh release create "$TAG" "${FILES[@]}" --repo "$GH_REPO" --title "rgx v$VERSION" --notes "$BODY"
  echo ">> github release: $GH/releases/tag/$TAG"
else
  echo "[dry-run] gh release create $TAG (${#ASSETS[@]} assets)"
fi

echo ">> port complete: $GH/releases/tag/$TAG"
