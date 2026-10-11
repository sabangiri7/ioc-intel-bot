#!/usr/bin/env python3
"""One-time / on-demand secret scan over the FULL git history.

Unlike the pre-commit hook (which only inspects staged files), this walks every
blob ever committed on any ref and flags real-looking credentials.

Usage:
    python3 .githooks/scan_history.py            # scan all history
    git filter-repo --analyze                    # (not required; see note below)

Known-benign self-match: the scanner file itself contains the private-key
*detection regex* (the literal "-----BEGIN ... PRIVATE KEY-----"), so it flags
itself. That single self-hit is expected and is not a leak.

Exit codes: 0 = clean, 1 = real secret(s) found.
"""
from __future__ import annotations

import importlib.machinery
import importlib.util
import subprocess
import sys
from pathlib import Path

HOOK = Path(__file__).resolve().parent / "pre-commit"
spec = importlib.util.spec_from_file_location(
    "pc", str(HOOK), loader=importlib.machinery.SourceFileLoader("pc", str(HOOK))
)
pc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pc)


def all_blobs() -> dict[str, str]:
    out = subprocess.run(
        ["git", "rev-list", "--objects", "--all"], capture_output=True, text=True
    ).stdout.splitlines()
    blobs: dict[str, str] = {}
    for line in out:
        parts = line.split(" ", 1)
        blobs.setdefault(parts[0], parts[1] if len(parts) > 1 else "")
    return blobs


def main() -> int:
    blobs = all_blobs()
    findings = []
    for sha, path in sorted(blobs.items()):
        if subprocess.run(["git", "cat-file", "-t", sha], capture_output=True,
                          text=True).stdout.strip() != "blob":
            continue
        blob = subprocess.run(["git", "cat-file", "-p", sha], capture_output=True).stdout
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            continue
        # Reuse the hook's detection rules so history and staged-file scans
        # can never drift apart. Mirror only the self-match suppression.
        for rule, _pat, snippet in pc.detect(text):
            if rule == "private-key" and path.endswith(HOOK.name):
                continue  # the hook contains the detection regex itself
            ln = text.count("\n", 0, text.find(snippet)) + 1
            findings.append((path, sha[:8], ln, rule, snippet))

    print(f"scanned {len(blobs)} unique blobs across all history")
    if not findings:
        print("CLEAN: no real-looking secrets in any historical blob.")
        return 0
    print(f"\n!! {len(findings)} potential secret(s):")
    for path, sha, ln, rule, snip in findings:
        red = snip if len(snip) <= 8 else snip[:4] + "…" + snip[-2:]
        print(f"  {path or '(no path)'} @ {sha} line {ln} [{rule}] {red}")
    print("\nIf real: purge the blob from history with git filter-repo / BFG,")
    print("then force-push and rotate the exposed credential immediately.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())