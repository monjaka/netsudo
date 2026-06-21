#!/usr/bin/env python3
"""Run the netsudo installer from a source checkout."""

from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netsudo.installer import main


if __name__ == "__main__":
    raise SystemExit(main())
