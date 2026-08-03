#!/usr/bin/env python3
"""
This file is used by Setuptools to fetch the version from the changelog.
"""

from pathlib import Path

PROJECT_DIR = Path(__file__).parent.parent.resolve()
DEBIAN_CHANGELOG = PROJECT_DIR / "debian" / "changelog"


def get_version() -> str:
    firstline = DEBIAN_CHANGELOG.read_text().splitlines()[0]
    return firstline.split()[1].strip("()")


version = get_version()
