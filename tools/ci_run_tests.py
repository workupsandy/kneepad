#!/usr/bin/env python3
"""Run the unit tests and turn every failure into a GitHub Actions annotation.

GitHub does not expose job logs to unauthenticated readers, but it does expose annotations. One summary annotation that
names each failing test and its first error line lets a reviewer see exactly what broke without downloading logs.

    python tools/ci_run_tests.py                     # whole suite
    python tools/ci_run_tests.py -p "test_platforms.py"   # any `unittest discover` arguments
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main(argv: list) -> int:
    args = argv or []
    cmd = [sys.executable, "-m", "unittest", "discover", "-s", os.path.join(ROOT, "tests")] + args
    env = dict(os.environ)
    env["PYTHONPATH"] = os.path.join(ROOT, "src") + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONUTF8"] = "1"
    p = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    sys.stdout.write(p.stdout)
    sys.stderr.write(p.stderr)
    if p.returncode == 0:
        return 0
    text = p.stderr
    ran = re.search(r"^Ran (\d+) tests?", text, re.M)
    summary = re.search(r"^(FAILED|OK)\b.*$", text, re.M)
    blocks = re.split(r"^={70}$", text, flags=re.M)
    lines = []
    for b in blocks:
        m = re.match(r"\s*(FAIL|ERROR): (\S+) \(([^)]+)\)", b)
        if not m:
            continue
        body = [l for l in b.strip().splitlines() if l.strip() and not set(l.strip()) <= {"-"}]
        errs = [l.strip() for l in body if re.match(r"\s*[A-Za-z_.]*(Error|Exception|Failure)\b", l)]
        last = errs[-1] if errs else (body[-1].strip() if body else "")
        lines.append(f"{m.group(1)} {m.group(3)} :: {last[:700]}")
    head = f"{ran.group(0) if ran else 'unittest'}; {summary.group(0) if summary else 'failed'} on {sys.platform}"
    if not os.environ.get("GITHUB_ACTIONS"):
        print(head + " | " + " | ".join(lines))
        return p.returncode
    # One annotation holds about 4,000 characters and a step shows at most ten, so split the list across several. Anyone
    # reading the run through the public API then sees every failing test, not just the first screenful.
    short = [l.replace("test_", "", 1) if l.startswith(("FAIL test_", "ERROR test_")) else l for l in lines]
    chunks, cur = [], ""
    for l in short:
        if cur and len(cur) + len(l) + 3 > 3200:
            chunks.append(cur)
            cur = ""
        cur += (" | " if cur else "") + l
    if cur:
        chunks.append(cur)
    chunks = chunks[:9]
    print(f"::error title=unit tests failed::{head} | {len(lines)} failing, listed in {len(chunks)} annotation(s)", flush=True)
    for i, c in enumerate(chunks, 1):
        c = c.replace("%", "%25").replace("\r", " ").replace("\n", " ")
        print(f"::error title=unit tests failed ({i}/{len(chunks)})::{c}", flush=True)
    return p.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
