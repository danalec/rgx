#!/usr/bin/env bash
# use-with-dsh.sh -- point DeepSeek Harness's grep/glob at rgx, or put the
# ripgrep it ships back.
#
# The Linux/macOS counterpart of scripts/use-with-dsh.ps1.
#
# DeepSeek Harness does not look for `rg` on PATH. Its `grep` and `glob`
# tools spawn the ripgrep binary the harness ships -- under
# `resources/app.asar.unpacked/dsh/node_modules/@vscode/ripgrep-*/bin/` --
# and always prefix `--no-config` to the argv. There is no environment
# variable and no settings field for that path, so the way to make those
# tools run rgx is to replace that one file, keeping a backup so --restore
# can put the shipped binary back.
#
# Both halves are discovered wherever they are installed:
#
#   * the harness by its unpacked `app.asar.unpacked` directory -- a
#     per-user install under `~/.local/share`, a system-wide one under
#     `/opt`, a macOS bundle under `/Applications`, or whatever
#     `--harness-root` names;
#   * rgx by `--rgx PATH`, else `$RGX_BIN`, else every `rgx*` command on
#     PATH (`rgx`, and the `rgx-znver4`/`rgx-avx2` spelling a package
#     manager may install) -- the first candidate that can answer the
#     harness's argv is the one used, so a package-manager install, a
#     sourced release tarball and a hand-unpacked zip all work.
#
# Before copying anything the script asks each rgx build the same questions
# the harness will ask it: `--no-config` with `--files`, `--regexp=VALUE`,
# and `--sort=modified`. A build that cannot answer one is reported with the
# flag it failed, and nothing is touched.
#
# Run it again after a harness update: the installer puts ripgrep back, and a
# second --apply is what re-points it. --status is the default.
#
# Usage:
#   bash scripts/use-with-dsh.sh [--status|--apply|--restore]
#                                [--rgx PATH] [--harness-root DIR]
#
# Exit codes: 0 ok, 2 usage, 3 rgx not found, 4 harness not found,
# 5 no rgx build can answer the harness's argv.
set -u

usage() {
    sed -n 's/^#   //p' "$0" | sed -n '/^bash scripts\/use-with-dsh.sh/,/^$/p'
}

# The first line of --version is the identity: ripgrep says `ripgrep x.y.z`
# and rgx says `rgx x.y.z` (its second line is the format list).
version_line() {
    "$1" --version 2>/dev/null | head -n 1
}

# A Windows path from the environment, in the spelling a bash glob can walk.
# Empty stays empty: the caller guards on it.
to_unix() {
    [ -n "$1" ] || return 0
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -u "$1"
    else
        printf '%s\n' "$1"
    fi
}

is_rgx() {
    case "$1" in
        rgx\ *) return 0 ;;
        *) return 1 ;;
    esac
}

mode="status"
mode_flags=0
rgx_path_arg=""
harness_root=""

while [ $# -gt 0 ]; do
    case "$1" in
        --status) mode="status"; mode_flags=$((mode_flags + 1)) ;;
        --apply) mode="apply"; mode_flags=$((mode_flags + 1)) ;;
        --restore) mode="restore"; mode_flags=$((mode_flags + 1)) ;;
        --rgx) shift; [ $# -gt 0 ] || { echo "rgx: --rgx needs a value" >&2; exit 2; }; rgx_path_arg="$1" ;;
        --rgx=*) rgx_path_arg="${1#--rgx=}" ;;
        --harness-root) shift; [ $# -gt 0 ] || { echo "rgx: --harness-root needs a value" >&2; exit 2; }; harness_root="$1" ;;
        --harness-root=*) harness_root="${1#--harness-root=}" ;;
        -h|--help) usage; exit 0 ;;
        *) echo "rgx: unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

if [ "$mode_flags" -gt 1 ]; then
    echo "rgx: choose one of --status, --apply and --restore, not more" >&2
    exit 2
fi

# Every rgx build the machine offers, in the order to try them: the one named
# explicitly, then the environment's, then PATH. The package managers of this
# project install `rgx`, `rgx-znver4` and `rgx-avx2` as separate commands, and
# a machine may hold more than one, so the caller picks by capability rather
# than by name.
rgx_candidates() {
    local seen="" name path

    if [ -n "$rgx_path_arg" ]; then
        [ -f "$rgx_path_arg" ] || { echo "rgx: no rgx at the path given: $rgx_path_arg" >&2; exit 3; }
        # Absolute, so the copy below never depends on the caller's cwd.
        (cd "$(dirname "$rgx_path_arg")" && printf '%s/%s\n' "$(pwd)" "$(basename "$rgx_path_arg")")
        return 0
    fi
    if [ -n "${RGX_BIN:-}" ]; then
        [ -f "$RGX_BIN" ] || { echo "rgx: RGX_BIN names a path that does not exist: $RGX_BIN" >&2; exit 3; }
        printf '%s\n' "$RGX_BIN"
        return 0
    fi

    for name in $(compgen -c 2>/dev/null | grep -E '^rgx(-[a-z0-9]+)?$' | sort -u); do
        path=$(command -v "$name" 2>/dev/null) || continue
        [ -n "$path" ] || continue
        case " $seen " in
            *" $path "*) continue ;;
        esac
        seen="$seen $path"
        printf '%s\n' "$path"
    done
}

# The unpacked directory is the harness's own name for "these files are real
# files on disk", and the packaged ripgrep is the only executable in there
# that the search tools spawn. Searching for it by name finds the harness
# whatever installed it.
find_harness_binaries() {
    local -a candidates=() binaries=()
    local base entry unpacked binary

    if [ -n "$harness_root" ]; then
        candidates+=("$harness_root/resources/app.asar.unpacked")
        candidates+=("$harness_root/app.asar.unpacked")
    else
        for base in "${HOME:-}/.local/share" "/opt" "/usr/lib" "${HOME:-}/Applications" "/Applications"; do
            [ -n "$base" ] && [ -d "$base" ] || continue
            for entry in "$base"/*/resources/app.asar.unpacked \
                         "$base"/*/*/resources/app.asar.unpacked \
                         "$base"/*.app/Contents/Resources/app.asar.unpacked; do
                [ -d "$entry" ] && candidates+=("$entry")
            done
        done
        # The Windows bases, when the environment names them: this twin runs
        # under git-bash/MSYS2 on the same machine the PowerShell twin runs
        # on, and a pair that finds the harness on one side and not the other
        # is a pair that drifts. The environment spells them with backslashes,
        # which a bash glob reads as escapes, so they go through cygpath first.
        local localappdata programfiles programfilesx86 userprofile winbase
        localappdata="$(to_unix "${LOCALAPPDATA:-}")"
        programfiles="$(to_unix "${PROGRAMFILES:-}")"
        programfilesx86="$(to_unix "$(printenv 'ProgramFiles(x86)' 2>/dev/null || true)")"
        userprofile="$(to_unix "${USERPROFILE:-}")"
        for base in "${localappdata:+$localappdata/Programs}" "$programfiles" "$programfilesx86"; do
            [ -n "$base" ] && [ -d "$base" ] || continue
            for entry in "$base"/*/resources/app.asar.unpacked; do
                [ -d "$entry" ] && candidates+=("$entry")
            done
        done
        winbase="${localappdata:+$localappdata/Microsoft/WinGet/Packages}"
        if [ -n "$winbase" ] && [ -d "$winbase" ]; then
            for entry in "$winbase"/*/resources/app.asar.unpacked \
                         "$winbase"/*/*/resources/app.asar.unpacked; do
                [ -d "$entry" ] && candidates+=("$entry")
            done
        fi
        if [ -n "$userprofile" ] && [ -d "$userprofile/scoop/apps" ]; then
            for entry in "$userprofile/scoop/apps"/*/current/resources/app.asar.unpacked; do
                [ -d "$entry" ] && candidates+=("$entry")
            done
        fi
    fi

    for unpacked in "${candidates[@]}"; do
        [ -d "$unpacked" ] || continue
        # The harness's own layout: the packed app's `dsh` tree is what holds
        # the search package. Matching `@vscode/ripgrep` alone finds every
        # Electron app on the machine, and pointing another one's search at
        # rgx is not this script's business.
        while IFS= read -r binary; do
            [ -n "$binary" ] && binaries+=("$binary")
        done < <(find "$unpacked" -type f \
                      -path '*/dsh/node_modules/@vscode/ripgrep-*/bin/rg*' \
                      \( -name 'rg' -o -name 'rg.exe' \) 2>/dev/null)
    done

    if [ "${#binaries[@]}" -gt 0 ]; then
        printf '%s\n' "${binaries[@]}" | awk '!seen[$0]++'
    fi
}

# The three questions the harness asks, one at a time, so a failure names the
# flag that could not be answered instead of "incompatible".
probe_failures() {
    local rgx_exe="$1"
    local probe_dir="$2"
    local errfile="$probe_dir/probe.err"
    local failures="" code

    printf 'rgx-probe\n' > "$probe_dir/rgx-probe.txt"

    "$rgx_exe" --no-config --files "$probe_dir" >/dev/null 2>"$errfile"
    code=$?
    if [ "$code" -gt 1 ]; then
        failures="${failures}--no-config: $(head -n 1 "$errfile")
"
    fi

    "$rgx_exe" --json --regexp=rgx-probe "$probe_dir" >/dev/null 2>"$errfile"
    code=$?
    if [ "$code" -gt 1 ]; then
        failures="${failures}--regexp: $(head -n 1 "$errfile")
"
    fi

    "$rgx_exe" --files --sort=modified "$probe_dir" >/dev/null 2>"$errfile"
    code=$?
    if [ "$code" -gt 1 ]; then
        failures="${failures}--sort=modified: $(head -n 1 "$errfile")
"
    fi

    printf '%s' "$failures"
}

# ---------------------------------------------------------------- discovery

binaries=$(find_harness_binaries)
if [ -z "$binaries" ]; then
    echo "rgx: no DeepSeek Harness installation found: pass --harness-root pointing at the directory that holds resources/app.asar.unpacked" >&2
    exit 4
fi

# What gets asked depends on what is being answered. --apply has to know
# whether a candidate may be installed, so it probes the candidates; --status
# reports on the binary the harness is *already* running, so it probes that
# one -- a machine whose PATH rgx is old can still be running a good one.
rgx=""
rgx_version=""
if [ "$mode" = "apply" ]; then
    candidates=$(rgx_candidates) || exit $?
    if [ -z "$candidates" ]; then
        echo "rgx: rgx not found: put it on PATH, pass --rgx, or set RGX_BIN" >&2
        exit 3
    fi

    probe_dir=$(mktemp -d "${TMPDIR:-/tmp}/rgx-dsh-probe-XXXXXX") || exit 2
    failures=""
    first_candidate=""
    candidate_count=0
    while IFS= read -r candidate; do
        [ -n "$candidate" ] || continue
        candidate_count=$((candidate_count + 1))
        candidate_failures=$(probe_failures "$candidate" "$probe_dir")
        if [ -z "$candidate_failures" ]; then
            rgx="$candidate"
            rgx_version=$(version_line "$candidate")
            break
        fi
        if [ -z "$first_candidate" ]; then
            # The first candidate is the one the report speaks for: naming
            # every build on a machine with three would bury the reason.
            first_candidate="$candidate"
            failures="$candidate_failures"
            rgx_version=$(version_line "$candidate")
        fi
    done <<EOF
$candidates
EOF
    rm -rf "$probe_dir"

    if [ -z "$rgx" ]; then
        echo "rgx:     $first_candidate ($rgx_version)"
        echo "probe:   failed"
        # The accumulator ends every line with a newline, and a `printf '%s'`
        # that kept it would leave the next line on the same one; the extra
        # newline plus the blank-line drop gives one output line per failure.
        printf '%s\n' "$failures" | sed -e '/^$/d' -e 's/^/         /'
        if [ "$candidate_count" -gt 1 ]; then
            echo "note:    none of the $candidate_count rgx builds on PATH answers the harness argv"
        fi
        exit 5
    fi
    echo "rgx:     $rgx ($rgx_version)"
    echo "probe:   ok (--no-config, --regexp, --sort=modified)"
fi

failed=0
while IFS= read -r binary; do
    [ -n "$binary" ] || continue
    backup="$binary.rgx-backup"
    version=$(version_line "$binary")

    echo "harness: $binary ($version)"

    if [ "$mode" = "restore" ]; then
        if [ -f "$backup" ]; then
            cp -f "$backup" "$binary"
            rm -f "$backup"
            echo "action:  restored the packaged ripgrep"
        else
            echo "state:   not applied (no backup to restore)"
        fi
        continue
    fi

    if is_rgx "$version"; then
        applied=yes
    else
        applied=no
    fi

    if [ "$mode" = "status" ]; then
        if [ "$applied" = "yes" ]; then
            echo "state:   applied"
            if [ ! -f "$backup" ]; then
                echo "note:    no ripgrep backup beside the binary (--restore cannot undo this one)"
            fi
            probe_dir=$(mktemp -d "${TMPDIR:-/tmp}/rgx-dsh-probe-XXXXXX") || exit 2
            applied_failures=$(probe_failures "$binary" "$probe_dir")
            rm -rf "$probe_dir"
            if [ -z "$applied_failures" ]; then
                echo "probe:   ok (--no-config, --regexp, --sort=modified)"
            else
                echo "probe:   failed (this build cannot answer the harness argv)"
                printf '%s\n' "$applied_failures" | sed -e '/^$/d' -e 's/^/         /'
                failed=$((failed + 1))
            fi
        else
            echo "state:   not applied"
        fi
        continue
    fi

    if [ "$applied" = "yes" ]; then
        # Already rgx: only a *different* rgx build is worth a copy, so that
        # upgrading rgx and re-running this lands the new one while a later
        # --restore still restores the ripgrep this harness shipped.
        if cmp -s "$binary" "$rgx"; then
            echo "action:  already rgx (nothing to do)"
            continue
        fi
        cp -f "$rgx" "$binary"
        if [ -f "$backup" ]; then
            echo "action:  replaced the installed rgx with this build"
        else
            echo "action:  replaced the installed rgx with this build (no ripgrep backup beside it: --restore cannot undo this one)"
        fi
        continue
    fi

    # The harness ships ripgrep: the backup must be *this* build, not one a
    # previous harness version shipped, or --restore would put back a binary
    # the tools were never tested against.
    cp -f "$binary" "$backup"
    cp -f "$rgx" "$binary"
    echo "action:  installed rgx (backup kept beside the binary)"
done <<EOF
$binaries
EOF

if [ "$failed" -gt 0 ]; then
    exit 5
fi
exit 0
