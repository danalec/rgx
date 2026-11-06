import os
import pathlib
import subprocess
import sys
from collections import Counter

def registry_prefix():
    """The directory cargo unpacks crates into, with a trailing slash.

    Its last component carries a hash that changes with the cargo version
    (the sparse index and the git index hash differently), so the prefix is
    found rather than written down: a path written into this file is a
    path of one machine, and a machine whose cargo hashes differently would
    strip nothing.
    """
    home = os.environ.get('CARGO_HOME') or os.path.join(os.path.expanduser('~'), '.cargo')
    src = os.path.join(home, 'registry', 'src')
    if os.path.isdir(src):
        for name in sorted(os.listdir(src)):
            return (os.path.join(src, name) + '/').replace('\\', '/')
    return ''


ROOT = registry_prefix()
STORE = os.environ.get('RGX_TV_STORE', '.rgx-tv')
PATTERN = sys.argv[1]

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
    return p.stdout.decode('utf-8', errors='replace')


def norm_direct(text):
    out = []
    for ln in text.splitlines():
        if ln.startswith(ROOT):
            ln = ln[len(ROOT):]
        if ln.count(':') < 2:
            continue
        path, rest = ln.split(':', 1)
        lno, body = rest.split(':', 1)
        out.append(path + ':' + lno + ':' + body.rstrip('\r'))
    return out


d = Counter(norm_direct(run(['rg', '-n', '--no-heading', '--color', 'never', '--hidden',
                             '--no-ignore', PATTERN, ROOT])))
t = Counter([ln.rstrip('\r') for ln in run([
    RGX, PATTERN, '--engine', 'tv', '--tv-store', STORE, '-j', '8']).splitlines()])
only_d = list((d - t).elements())
only_t = list((t - d).elements())
print(f'{PATTERN!r}: direct={sum(d.values())} rgx-tv={sum(t.values())} '
      f'only_direct={len(only_d)} only_tv={len(only_t)}')
for x in only_t[:6]:
    print('   tv only:', x)
