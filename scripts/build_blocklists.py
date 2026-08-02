#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from blocklist_builder.builder import build, load_config, main
from blocklist_builder.parsing import normalize_domain, parse_content, parse_lines

__all__ = [
    "build",
    "load_config",
    "main",
    "normalize_domain",
    "parse_content",
    "parse_lines",
]


if __name__ == "__main__":
    main()
