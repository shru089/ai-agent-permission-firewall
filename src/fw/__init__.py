"""
Compatibility alias package: fw -> firewall.
"""

import sys

import firewall  # noqa: F401

sys.modules["fw"] = firewall
