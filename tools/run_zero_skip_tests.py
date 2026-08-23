#!/usr/bin/env python3
"""Run the complete unittest suite and reject every skip."""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tests", type=Path, default=Path("tests"))
    arguments = parser.parse_args(argv)
    suite = unittest.defaultTestLoader.discover(str(arguments.tests.resolve()))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.skipped:
        print(f"SOS_RELEASE_SKIPS_FORBIDDEN:{len(result.skipped)}", file=sys.stderr)
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
