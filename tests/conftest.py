"""
Root pytest configuration and path setup.
"""

import sys
from pathlib import Path

REPO_ROOT = str(Path(__file__).resolve().parent.parent)
while REPO_ROOT in sys.path:
    sys.path.remove(REPO_ROOT)
sys.path.insert(0, REPO_ROOT)
