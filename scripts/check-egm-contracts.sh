#!/usr/bin/env bash
# check-egm-contracts.sh -- validate the EGM contracts of THIS tree.
#
# The Linux counterpart of scripts/check-egm-contracts.ps1. Both twins are
# deliberately thin: the checks live in check-egm-contracts.py, so the pair
# cannot disagree about what a valid contract is.
#
# Usage:
#   bash scripts/check-egm-contracts.sh [--root DIR] [--self-test] [--reindex] [--fix]
set -u

here=$(cd "$(dirname "$0")" && pwd)
script="$here/check-egm-contracts.py"

if command -v python3 > /dev/null 2>&1; then
    exec python3 "$script" "$@"
elif command -v python > /dev/null 2>&1; then
    exec python "$script" "$@"
else
    echo "EGM CONTRACTS: no python3 or python on PATH" >&2
    exit 2
fi
