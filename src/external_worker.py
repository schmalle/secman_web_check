"""Trusted single-thread prelude: limit native output, then enter OS confinement."""

from __future__ import annotations

import os
import resource
import sys


def main() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (2_000_000, 2_000_000))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.execv(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
