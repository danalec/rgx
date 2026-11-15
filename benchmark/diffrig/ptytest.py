import os, pty, shutil, sys, subprocess

def run_pty(cmd):
    """Run cmd with stdout attached to a pty; return the bytes written."""
    if shutil.which(cmd[0]) is None:
        raise SystemExit(
            f"no binary at {cmd[0]}; build it first: cargo build --release"
        )
    master, slave = pty.openpty()
    p = subprocess.Popen(cmd, stdout=slave, stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL, close_fds=True)
    os.close(slave)
    out = b""
    try:
        while True:
            try:
                d = os.read(master, 65536)
            except OSError:
                break
            if not d:
                break
            out += d
    finally:
        os.close(master)
        p.wait()
    return out

# Resolved, not hardcoded: this file lives in benchmark/diffrig/, so the
# repo root is one level up and the build is wherever cargo put it. `RG`
# honours an explicit env override first (cmp.sh does the same for RGX),
# then PATH, then the ripgrep Git for Windows ships.
# benchmark/diffrig/x.py -> up three to the repo root.
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Debug first, release as the fallback -- the same order cmp.sh uses.
# The Windows name first, then the bare one: the Unix host has no
# `.exe`, and this harness exists for the Unix host. The same fallback
# scripts/bench-status.sh makes.
def _find_rgx():
    for profile in ("debug", "release"):
        for name in ("rgx.exe", "rgx"):
            candidate = os.path.join(ROOT, "target", profile, name)
            if os.path.isfile(candidate):
                return candidate
    return os.path.join(ROOT, "target", "release", "rgx")


RGX = _find_rgx()
RG = os.environ.get("RG") or shutil.which("rg") or r"C:\Program Files\Git\usr\bin\rg.exe"

cases = [
    ["needle", "fx/hello.txt"],
    ["-n", "needle", "fx/hello.txt"],
    ["--no-line-number", "needle", "fx/hello.txt"],
    ["-I", "needle", "fx/hello.txt"],
    ["-n", "-I", "needle", "fx/hello.txt"],
    ["-c", "needle", "fx/hello.txt"],
    ["-l", "needle", "fx/hello.txt"],
    ["-o", "needle", "fx/multi.txt"],
    ["-A1", "needle", "fx/hello.txt"],
    ["-A1", "-n", "needle", "fx/hello.txt"],
    ["-A1", "--no-line-number", "needle", "fx/hello.txt"],
    ["-v", "needle", "fx/hello.txt"],
    ["-r", "R", "needle", "fx/multi.txt"],
    ["-o", "-r", "R", "needle", "fx/multi.txt"],
    ["needle", "fx/hello.txt", "fx/two.txt"],
    ["needle", "fx/crlf.txt"],
    ["-n", "needle", "fx/crlf.txt"],
]
os.chdir(os.path.dirname(os.path.abspath(__file__)))
for c in cases:
    a = run_pty([RG] + c)
    b = run_pty([RGX] + c)
    if a == b:
        print("SAME(pty) " + " ".join(c))
    else:
        print("DIFF(pty) " + " ".join(c))
        print("   rg : %r" % a)
        print("   rgx: %r" % b)
