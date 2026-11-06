#!/usr/bin/env python3
"""Cross-run regression detector for the benchmark transcripts.

WHY THIS EXISTS
---------------
benchmark/kalman-drift.py held the algorithm; this wires it to the runs.
The two are separate because the question they answer is different: the
first asks "can a model predict this?", the second asks "did anything move?".

The second question is the one with an answer. On 2026-10-17 the pack
store's cold penalty moved from 4.50 ms to 228.50 ms -- a 50x regression
introduced by a manifest bump -- and nothing in the tree said so. The two
per-file arms did not move, which is what identifies it as a change on the
store path and not host drift. That judgement, in a table, is what this
prints.

It is NOT a predictor. It does not tell you why something moved or what it
will do next. It tells you what moved, by how many sigma, and which arms
held still and are therefore the control.

USAGE
-----
    python3 benchmark/regress.py RUN1 [RUN2 RUN3 ...]

Each RUN is a tv-cold.sh transcript. Runs are compared in the order given,
oldest first. Lines recognised:

    <arm> cold: v1 v2 v3 ...
    <arm> warm: v1 v2 v3 ...
    <arm> summary: cold min A / med B | warm min C / med D
    <arm> penalty: NNN.NN ms (...)

Stdlib only. Output is stdout; nothing is written.
"""

import math
import re
import sys

# A reading is (arm, condition, [values]). The MAD pass of findings.md 20
# lives here too: the first sample after a drop_caches prices the binary and
# the store manifest as well as the corpus, so it is not drawn with the rest.
COLD_RE = re.compile(r"^(\S+)\s+(cold|warm):\s+([0-9. ]+?)\s*$")
PEN_RE = re.compile(r"^(\S+)\s+penalty:\s+([0-9.]+)\s*ms")
HDR_RE = re.compile(r"^=== .*?:\s*(\S+) ===")


def median(xs):
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else 0.5 * (s[n // 2 - 1] + s[n // 2])


def mad_flag(pairs):
    """Flag off-distribution cold samples before fitting, not after.

    See findings.md 20 item 2: a filter that rejects what it cannot explain
    and then reports an estimate from what is left is measuring its own
    prior. The threshold is 3 x 1.4826 x MAD, the normal-consistent scale.
    """
    warm = [t for c, t in pairs if not c]
    cold = [t for c, t in pairs if c]
    if not warm or not cold:
        return set()
    base = median(warm)
    pen = median(cold) - base
    resid = [t - (base + (pen if c else 0.0)) for c, t in pairs]
    m = median([abs(r) for r in resid])
    if m <= 0:
        return set()
    thr = 3.0 * 1.4826 * m
    return {i for i, r in enumerate(resid) if abs(r) > thr}


class ScalarKalman:
    """Random-walk level in log space. Q and R are dimensionless there."""

    def __init__(self, x0, p0, q, r):
        self.x, self.p, self.q, self.r = x0, p0, q, r

    def step(self, z_log):
        x_pred, p_pred = self.x, self.p + self.q
        nu = z_log - x_pred
        s = p_pred + self.r
        k = p_pred / s
        self.x = x_pred + k * nu
        self.p = (1.0 - k) * p_pred
        return nu / math.sqrt(s)


def parse(path):
    """-> {arm: {"cold": [...], "warm": [...]}} plus the timestamp."""
    arms = {}
    stamp = "?"
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = HDR_RE.match(line)
            if m:
                stamp = m.group(1)
                continue
            m = COLD_RE.match(line)
            if not m:
                continue
            arm, cond, vals = m.group(1), m.group(2), m.group(3)
            arms.setdefault(arm, {"cold": [], "warm": []})
            arms[arm][cond] = [float(v) for v in vals.split()]
    return stamp, arms


def summarise(arms):
    """-> {arm: {"base": ms, "pen": ms, "share": %, "dropped": [labels]}}"""
    out = {}
    for arm, d in arms.items():
        if not d["cold"] or not d["warm"]:
            continue
        pairs = []
        for c, w in zip(d["cold"], d["warm"]):
            pairs.append((True, c))
            pairs.append((False, w))
        drop = mad_flag(pairs)
        kc = [d["cold"][i] for i in range(len(d["cold"])) if 2 * i not in drop]
        kw = [d["warm"][i] for i in range(len(d["warm"])) if 2 * i + 1 not in drop]
        if not kc:
            kc, kw = d["cold"], d["warm"]
        base, pen = median(kw), median(kc) - median(kw)
        labels = []
        for i in sorted(drop):
            idx = i // 2
            if i % 2 == 0 and idx < len(d["cold"]):
                labels.append("cold[%d]=%.0f" % (idx, d["cold"][idx]))
        out[arm] = {
            "base": base,
            "pen": pen,
            "share": 100.0 * pen / base if base else float("nan"),
            "dropped": labels,
        }
    return out


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    paths = argv[1:]
    runs = []
    for p in paths:
        stamp, arms = parse(p)
        runs.append((p, stamp, summarise(arms)))

    print("rgx benchmark regression detector")
    print("runs compared in the order given; each column is one run")
    print()
    for p, stamp, _ in runs:
        print("  %-42s %s" % (p, stamp))
    print()

    names = sorted({a for _, _, s in runs for a in s})
    if not names:
        print("no <arm> cold/warm lines found in any run")
        return 1

    hdr = "%-6s %-6s " % ("arm", "stat") + " ".join(
        "%12s" % (s if len(s) <= 12 else s[-12:]) for _, s, _ in runs)
    print(hdr)
    print("-" * len(hdr))

    # The tracker: one series per (arm, stat) across runs, in log space so
    # one Q/R pair fits every row regardless of the absolute scale.
    q_var, r_var, thresh = 0.01, 0.0009, 3.0
    flagged = []
    for arm in names:
        for stat, key in (("base", "base"), ("pen", "pen")):
            series = [(s[arm][key]) for _, _, s in runs if arm in s and s[arm][key] > 0]
            if len(series) < 2:
                continue
            filt = ScalarKalman(math.log(series[0]), 0.0, q_var, r_var)
            row = "%-6s %-6s " % (arm, stat)
            row += "%12s" % "init"
            worst, worst_at = 0.0, None
            for i, v in enumerate(series[1:], start=1):
                z = filt.step(math.log(v))
                row += "%12.2f" % z
                if abs(z) > abs(worst):
                    worst, worst_at = z, i
            mark = ""
            if abs(worst) > thresh:
                mark = "  <-- MOVED (%+.2f sigma)" % worst
                flagged.append((arm, stat, worst_at, worst))
            print(row + mark)

    print()
    if flagged:
        print("MOVED (%d):" % len(flagged))
        for arm, stat, at, z in flagged:
            label = runs[at][1] if at is not None and at < len(runs) else "?"
            print("   %-6s %-6s at run %s  z = %+.2f" % (arm, stat, label, z))
        held = [a for a in names
                if a not in {f[0] for f in flagged}]
        if held:
            print()
            print("HELD (the control): %s" % ", ".join(held))
            print("   These did not move, so the change above is on the path")
            print("   that moved alone -- not host drift, not cache state.")
    else:
        print("MOVED: nothing left its band.")
    print()
    print("Q = %.4f  R = %.5f (= 0.03^2)  flag at |z| > %.1f" % (q_var, r_var, thresh))
    print("see benchmark/kalman-drift.py module C for the sensitivity of that window")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
