#!/usr/bin/env python3
"""
CI Check: Ensure labels.sqlite is not tracked anywhere in the Git repository.
Exit codes:
  0: Clean repository (no labels.sqlite tracked)
  1: Violation detected (labels.sqlite tracked)
  2: Command or Git execution failure
"""

import subprocess
import sys


def check_no_tracked_labels() -> int:
    try:
        proc = subprocess.run(
            ["git", "ls-files"],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:
        sys.stderr.write(f"CI ERROR: Failed to invoke git ls-files: {exc}\n")
        return 2

    if proc.returncode != 0:
        sys.stderr.write(
            f"CI ERROR: git ls-files failed with code {proc.returncode}:\n{proc.stderr}\n"
        )
        return 2

    violations = []
    for line in proc.stdout.splitlines():
        normalized = line.strip().replace("\\", "/")
        if normalized == "labels.sqlite" or normalized.endswith("/labels.sqlite"):
            violations.append(normalized)

    if violations:
        sys.stderr.write("SECURITY VIOLATION: Tracked label store detected in repository:\n")
        for v in violations:
            sys.stderr.write(f"  - {v}\n")
        return 1

    print("CI SUCCESS: No labels.sqlite tracked in git.")
    return 0


if __name__ == "__main__":
    sys.exit(check_no_tracked_labels())
