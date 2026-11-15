#!/usr/bin/env bash
# Compare rg vs rgx byte-for-byte. Usage: cmp.sh <label> <stdin-file-or-"-"> args...
# Scratch beside this script rather than a hardcoded /tmp path.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
RGX="${RGX:-$ROOT/target/debug/rgx.exe}"
[ -f "$RGX" ] || RGX="$ROOT/target/release/rgx.exe"
# The Windows name first, then the bare one: the Unix host has no
# `.exe`. The same fallback scripts/bench-status.sh makes.
[ -f "$RGX" ] || RGX="$ROOT/target/debug/rgx"
[ -f "$RGX" ] || RGX="$ROOT/target/release/rgx"
[ -f "$RGX" ] || { echo "no rgx at $RGX; build it first: cargo build --release" >&2; exit 2; }
label="$1"; shift
inp="$1"; shift

if [ "$inp" = "-" ]; then
  ro=$(rg "$@" 2>"$HERE/.rg.err" </dev/null | od -c)
  xo=$("$RGX" "$@" 2>"$HERE/.rgx.err" </dev/null | od -c)
else
  ro=$(rg "$@" <"$inp" | od -c)
  xo=$("$RGX" "$@" <"$inp" | od -c)
fi
if [ "$ro" = "$xo" ]; then
  echo "SAME  $label"
else
  echo "DIFF  $label   [args: $*]"
  echo "  --- rg ---"
  echo "$ro" | head -30
  echo "  --- rgx ---"
  echo "$xo" | head -30
fi
