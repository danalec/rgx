"""Byte-for-byte parity: rgx-tv pack search vs direct search over the same tree.

Both run with no shell in the way, so Git-Bash path mangling cannot touch either
side. Only the multiset of `path:line:text` records is compared: workers append
in completion order, so the sequence is not a stable thing on either side.
"""
import io
import pathlib
import subprocess
import sys
from collections import Counter

ROOT = sys.argv[1]
STORE = sys.argv[2]
PATTERN = sys.argv[3]
BACKSLASH = chr(92)

def find_rgx():
    """The binary, wherever cargo put it and whatever the host calls it.

    The Windows name first, then the bare one: the Unix host has no
    `.exe`. The same fallback `benchmark/diffrig/fuzz.py` makes.
    """
    root = pathlib.Path(__file__).resolve().parent.parent
    for profile in ("debug", "release"):
        for name in ("rgx.exe", "rgx"):
            candidate = root / "target" / profile / name
            if candidate.is_file():
                return str(candidate)
    return str(root / "target" / "release" / "rgx")

RGX = find_rgx()
if not pathlib.Path(RGX).is_file():
    raise SystemExit(f"no rgx at {RGX}; build it first: cargo build --release")


def run(cmd):
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode != 0 and p.returncode != 1:
        raise SystemExit(f'{cmd[0]} exited {p.returncode}: {p.stderr[:400]!r}')
    return p.stdout.decode('utf-8', errors='replace')


def norm_direct(text):
    prefix = ROOT.replace(BACKSLASH, '/').rstrip('/') + '/'
    out = []
    for ln in text.splitlines():
        if ln.startswith(prefix):
            ln = ln[len(prefix):]
        if ln.count(':') < 2:
            continue
        path, rest = ln.split(':', 1)
        lno, body = rest.split(':', 1)
        out.append(path + ':' + lno + ':' + body.rstrip('\r'))
    return out


def norm_tv(text):
    return [ln.rstrip('\r') for ln in text.splitlines()]


direct = norm_direct(run(['rg', '-n', '--no-heading', '--color', 'never', PATTERN, ROOT]))
tv = norm_tv(run([
    RGX, PATTERN, '--engine', 'tv', '--tv-store', STORE, '-j', '8',
]))

print('direct (rg) lines:', len(direct))
print('rgx-tv pack lines:', len(tv))
if Counter(direct) == Counter(tv):
    print('BYTE-FOR-BYTE PARITY WITH DIRECT SEARCH')
else:
    cd, ct = Counter(direct), Counter(tv)
    only_d = list((cd - ct).elements())
    only_t = list((ct - cd).elements())
    print('DIFFERS')
    print('only in direct :', len(only_d), only_d[:3])
    print('only in rgx-tv :', len(only_t), only_t[:3])
