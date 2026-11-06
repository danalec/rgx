import itertools, os, shutil, subprocess, sys

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
CWD = os.path.dirname(os.path.abspath(__file__))

# flags whose absence rgx cannot emulate (verified unimplemented) are excluded
FLAGS = [
    [], ["-n"], ["--no-line-number"], ["-I"], ["-n", "-I"],
    ["--no-line-number", "-I"], ["-c"], ["-l"], ["-o"], ["-v"],
    ["-r", "R"], ["-o", "-r", "R"], ["-A", "1"], ["-B", "1"], ["-C", "1"],
    ["-A", "1", "-n"], ["-A", "1", "--no-line-number"],
    ["-C", "1", "-n"], ["-C", "1", "--no-line-number"],
    ["-o", "-n"], ["-o", "--no-line-number"], ["-r", "R", "-n"],
    ["-r", "R", "--no-line-number"], ["-o", "-r", "R", "-n"],
    ["-n", "-c"], ["-n", "-l"], ["-i", "-n"], ["-w", "-n"], ["-F", "-n"],
    ["-i", "-o", "-n"], ["-w", "-o", "-n"], ["-F", "-o", "-n"],
    ["-n", "-A", "2"], ["-n", "-B", "2"], ["-n", "-C", "2"],
    ["-n", "-v", "-A", "1"], ["-n", "-o", "-A", "1"],
    ["-n", "-r", "R", "-A", "1"], ["-n", "--", "-"], ["-n", "-m", "5"],
]
PATTERNS = ["needle", "needle|foo", "n.edle", "^needle", "needle$"]
FILESETS = [
    ["fx/hello.txt"],
    ["fx/two.txt"],
    ["fx/multi.txt"],
    ["fx/nonl.txt"],
    ["fx/ctx.txt"],
    ["fx/hello.txt", "fx/two.txt"],
    ["fx/hello.txt", "fx/multi.txt", "fx/ctx.txt"],
    ["fx/empty.txt"],
    ["fx/blank.txt"],
    ["fx/oneword.txt"],
]

def run(exe, args, stdin=None):
    p = subprocess.run([exe] + args, cwd=CWD, capture_output=True,
                       input=stdin if stdin is not None else b"")
    return p.returncode, p.stdout

# deterministic corpora
open(os.path.join(CWD, "fx/empty.txt"), "wb").write(b"")
open(os.path.join(CWD, "fx/blank.txt"), "wb").write(b"\n\n\nneedle\n\n\n")
open(os.path.join(CWD, "fx/oneword.txt"), "wb").write(b"needle\n")

diffs = 0
total = 0
for pat, fl, files in itertools.product(PATTERNS, FLAGS, FILESETS):
    args = fl + [pat] + files
    rc1, o1 = run(RG, args)
    rc2, o2 = run(RGX, args)
    total += 1
    # normalise rg's nondeterministic multi-file ordering by sorting lines
    def norm(b):
        ls = b.split(b"\n")
        return b"\n".join(sorted(ls))
    if o1 != o2 and norm(o1) != norm(o2):
        diffs += 1
        print("DIFF %r" % (args,))
        print("   rg : %r" % o1)
        print("   rgx: %r" % o2)
print("checked %d combos, %d unexplained diffs" % (total, diffs))
