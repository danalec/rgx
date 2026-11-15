#!/usr/bin/env bash
# publish-cratesio.sh -- publish every package of the workspace to crates.io,
# in the order the dependency graph asks for.
#
#   ./scripts/publish-cratesio.sh              # dry-run: print the order
#   ./scripts/publish-cratesio.sh --publish     # do it
#
# The order is the graph: a crate can only be uploaded once the crates it
# depends on are on the registry, because the registry resolves the
# dependency by name and version. `rgx-core` and `rar-codec` stand alone;
# the adapters stand on `rgx-core`; `rgx-adapters-docs` stands on two
# adapters; the root package stands on all of them.
#
# The registry name of the root package is `rgx-search` -- `rgx` is taken on
# crates.io by an unrelated project -- and the binary it installs is `rgx`.
#
# crates.io publishes an index entry within a minute or two of the upload,
# so each package is retried for a while: the first attempt of the next
# package can arrive before the registry can see the previous one.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PUBLISH=0
ALLOW_EXISTING=0
while [ $# -gt 0 ]; do
  case "$1" in
    --publish) PUBLISH=1 ;;
    --allow-existing) ALLOW_EXISTING=1 ;;
    *) echo "unknown flag: $1"; exit 2 ;;
  esac
  shift
done

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
# crates.io limits how many NEW crates an account may publish in a short
# period, and answers a 429 with the minute the next one is accepted. The
# bucket holds five tokens and refills one every ten minutes -- not a quota
# that empties once a day -- so a first release of thirteen packages is two
# hours of uploads. The wait is shorter than the window on purpose: the
# attempt after the window opens is the one that succeeds, and twenty
# attempts at five minutes is an hour and a half of tolerance for a gap of
# ten minutes.
ATTEMPTS=20
WAIT=300

# The order the graph asks for.
ORDER=(
  rgx-core
  rar-codec
  rgx-adapters-archive
  rgx-adapters-inspect
  rgx-adapters-llm
  rgx-adapters-mail
  rgx-adapters-media
  rgx-adapters-office
  rgx-adapters-pdf
  rgx-adapters-tabular
  rgx-adapters-threed
  rgx-adapters-docs
  rgx-search
)

published() { # published <package> <version>
  # The registry answers with the versions a crate has; the one this
  # workspace wants is there when the package is already up.
  curl -fsS "https://crates.io/api/v1/crates/$1/versions" \
    -H "User-Agent: rgx-publish" 2>/dev/null | grep -q "\"num\":\"$2\""
}

echo ">> rgx $VERSION -> crates.io, ${#ORDER[@]} packages"

for pkg in "${ORDER[@]}"; do
  if published "$pkg" "$VERSION"; then
    if [ "$ALLOW_EXISTING" = 1 ]; then
      echo ">> $pkg $VERSION is already on crates.io, skipping"
      continue
    fi
    echo ">> $pkg $VERSION is already on crates.io."
    echo ">> A published version cannot be edited: to publish this one with"
    echo ">> the current licence and author, delete it on crates.io first."
    echo ">> crates.io allows a version to be deleted within 72 hours of the"
    echo ">> upload, and then holds the NAME for 24 hours before it can be"
    echo ">> used again."
    exit 1
  fi
  if [ "$PUBLISH" != 1 ]; then
    echo "[dry-run] cargo publish -p $pkg"
    continue
  fi
  echo ">> publishing $pkg"
  ok=0
  for attempt in $(seq 1 "$ATTEMPTS"); do
    if cargo publish -p "$pkg" --locked; then
      ok=1
      break
    fi
    echo ">> $pkg not accepted yet (attempt $attempt/$ATTEMPTS); the registry may not see the package it depends on yet"
    sleep "$WAIT"
  done
  if [ "$ok" != 1 ]; then
    echo ">> $pkg could not be published after $ATTEMPTS attempts"
    exit 1
  fi
done

if [ "$PUBLISH" = 1 ]; then
  echo ">> every package is on crates.io"
else
  echo ">> dry run: nothing was published"
fi
