#!/usr/bin/env bash
# publish-release.sh -- publish an rgx release end to end, from Linux.
#
# The Linux counterpart of scripts/publish-release.ps1.
#
#   bash scripts/publish-release.sh                 # full pipeline
#   bash scripts/publish-release.sh --skip-tests    # trust the build
#   bash scripts/publish-release.sh --dry-run       # show, don't touch
#
# Pipeline: build the Linux artifacts -> tag rgx-v<version> + push -> create
# or update the forgejo release and (re)upload the assets.
#
# The forgejo API uses the same stored git credentials (`git credential
# fill`); no tokens live in this script.
#
# TWO PLATFORM DIFFERENCES FROM THE WINDOWS SCRIPT, both because the
# thing they touch does not exist on Linux:
#
#   1. the winget manifests are a Windows package manager's, and there is
#      no `winget` here to validate them. The step is skipped and says
#      so; the manifests are the Windows script's business, and they are
#      updated by the release flow on the Windows side.
#   2. the Windows script commits the manifest changes at the end. There
#      is nothing to commit here, so there is nothing to push.
#
# The assets that go on the release page are everything in .dist/ -- the
# glibc tarball, the musl tarball and the distro packages that
# scripts/build-linux.sh produced -- plus the local build this script
# makes, under .dist/local/.
set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
cd "$repo"

version=""
skip_tests=0
dry_run=0

while [ $# -gt 0 ]; do
    case "$1" in
        --version) version=${2:-}; shift 2 ;;
        --skip-tests) skip_tests=1; shift ;;
        --dry-run) dry_run=1; shift ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[ -n "$version" ] || version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ -n "$version" ] || { echo "no version in Cargo.toml" >&2; exit 1; }

tag="rgx-v$version"
# The forgejo is the development upstream, and where it lives is the
# operator's business: the address of a private box is not a fact about the
# project. It comes from the environment, and the values below are only the
# defaults the owner runs with.
forgejo_url="${RGX_FORGEJO_URL:-http://192.168.0.10:3000}"
forgejo_repo="${RGX_FORGEJO_REPO:-danalec/rgx}"
repo_api="$forgejo_url/api/v1/repos/$forgejo_repo"
forgejo="$forgejo_url/$forgejo_repo"
# The host and the port the credentials are stored under, taken from the URL.
forgejo_host="$(printf '%s' "$forgejo_url" | sed -e 's|^[a-zA-Z]*://||' -e 's|/.*$||')"

# --- 1. build --------------------------------------------------------------
if [ "$skip_tests" -eq 0 ]; then
    bash "$here/build-release.sh" || { echo "the build failed" >&2; exit 1; }
else
    bash "$here/build-release.sh" --skip-tests || { echo "the build failed" >&2; exit 1; }
fi

# The assets: everything the release directory holds, and everything the
# local build just made.
assets=$(ls -1 .dist/*.tar.gz .dist/*.deb .dist/*.rpm .dist/*.apk .dist/*.pkg.tar.zst .dist/local/*.tar.gz 2>/dev/null)
if [ -z "$assets" ]; then
    echo "no assets to publish: .dist/ is empty" >&2
    echo "run scripts/build-linux.sh (docker) or scripts/build-release.sh first" >&2
    exit 1
fi

# --- 2. tag + push ---------------------------------------------------------
if git tag -l "$tag" | grep -q .; then
    echo "tag $tag already exists"
elif [ "$dry_run" -eq 1 ]; then
    echo "[dry-run] git tag $tag; git push forgejo $tag"
else
    git tag "$tag"
    git push forgejo "$tag"
fi

# --- 3. forgejo release + assets -------------------------------------------
# The credentials are the ones git already has for this host. `git
# credential fill` is a program, not a shell builtin, and the pipe into it
# is what makes it answer; the empty line ends the request.
cred=$(printf 'protocol=http\nhost=%s\n\n' "$forgejo_host" | git credential fill 2>/dev/null)
user=$(printf '%s\n' "$cred" | sed -n 's/^username=//p')
pass=$(printf '%s\n' "$cred" | sed -n 's/^password=//p')
if [ -z "$user" ] || [ -z "$pass" ]; then
    echo "no git credentials for the forgejo" >&2
    exit 1
fi
auth=$(printf '%s:%s' "$user" "$pass" | base64 | tr -d '\n')

# A JSON string: the backslash, the quote and the newline are the three
# that a release body can carry.
json_escape() {
    printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e :a -e 'N' -e '$!ba' -e 's/\n/\\n/g'
}

body="Search inside everything — PDFs, Office documents, archives, 3D models, LLM checkpoints, databases, e-mail. Ripgrep-compatible, adapters in-process.

**Linux builds** (portable tarball: rgx + README + licences):
- \`$tag-x86_64-linux-gnu.tar.gz\` — glibc, runs on any x86-64 CPU
- \`$tag-x86_64-linux-musl.tar.gz\` — static, runs anywhere
- \`$tag-znver4-linux.tar.gz\` — tuned for AMD Zen 4 (znver4)

Feature-parity with the rga adapter set: archives (zip/7z/tar/cpio/decompress),
3D models, LLM model files, media metadata, SQLite/DBF/SHP/Parquet, e-mail,
external tools (ffmpeg/ffprobe, tesseract, soffice).

Apache-2.0."

release=$(curl -fsSL -H "Authorization: Basic $auth" "$repo_api/releases/tags/$tag" 2>/dev/null || true)
if [ -n "$release" ]; then
    echo "release exists: $forgejo/releases/tag/$tag"
else
    echo "release $tag does not exist yet"
fi

if [ "$dry_run" -eq 1 ]; then
    echo "[dry-run] create/patch release $tag and upload:"
    printf '%s\n' "$assets" | sed 's/^/    /'
else
    release_id=""
    if [ -n "$release" ]; then
        release_id=$(printf '%s' "$release" | sed -n 's/.*"id":\([0-9]\+\).*/\1/p' | head -1)
        current_body=$(printf '%s' "$release" | sed -n 's/.*"body":"\(.*\)","created_at".*/\1/p' | head -1)
        if [ "$current_body" != "$(json_escape "$body")" ]; then
            curl -fsSL -X PATCH -H "Authorization: Basic $auth" \
                -H "Content-Type: application/json" \
                -d "{\"name\":\"rgx v$version\",\"body\":\"$(json_escape "$body")\"}" \
                "$repo_api/releases/$release_id" > /dev/null \
                || { echo "the release could not be updated" >&2; exit 1; }
            echo "release updated"
        fi
    else
        created=$(curl -fsSL -X POST -H "Authorization: Basic $auth" \
            -H "Content-Type: application/json" \
            -d "{\"tag_name\":\"$tag\",\"name\":\"rgx v$version\",\"body\":\"$(json_escape "$body")\"}" \
            "$repo_api/releases") || { echo "the release could not be created" >&2; exit 1; }
        release_id=$(printf '%s' "$created" | sed -n 's/.*"id":\([0-9]\+\).*/\1/p' | head -1)
        echo "release created: $forgejo/releases/tag/$tag"
    fi

    for asset in $assets; do
        name=$(basename "$asset")
        # A stale asset of the same name has to go first: the forgejo
        # refuses a second upload under a name that is already taken, and
        # a release that still serves the previous build is worse than no
        # release.
        stale=$(printf '%s' "$release" | grep -o "\"id\":[0-9]*,\"name\":\"$name\"" | head -1 | grep -o '[0-9]\+' | head -1)
        if [ -n "$stale" ]; then
            curl -fsSL -X DELETE -H "Authorization: Basic $auth" \
                "$repo_api/releases/$release_id/assets/$stale" > /dev/null
            echo "replaced asset: $name"
        fi
        curl -fsSL -X POST -H "Authorization: Basic $auth" \
            -H "Content-Type: application/octet-stream" \
            --data-binary "@$asset" \
            "$repo_api/releases/$release_id/assets?name=$name" > /dev/null \
            || { echo "the upload of $name failed" >&2; exit 1; }
        size=$(du -m "$asset" | cut -f1)
        echo "uploaded: $name (${size} MB)"
    done
fi

# --- 4. winget -------------------------------------------------------------
# The winget manifests are the Windows package manager's, and there is no
# winget here. The Windows script owns that step; this one says so
# instead of pretending to have done it.
echo "winget manifests: not touched (winget is a Windows package manager; scripts/publish-release.ps1 owns that step)"

# --- 5. done ---------------------------------------------------------------
echo ""
echo "published $tag : $forgejo/releases/tag/$tag"
