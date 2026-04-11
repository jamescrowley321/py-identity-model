"""Pytest configuration for conformance harness tests.

Adds the ``conformance/`` directory to ``sys.path`` so the harness modules
(``run_tests``, ``app``) can be imported by tests without reorganising the
conformance layout into a package.

The conformance harness is intentionally not a Python package — it's a
standalone runner script and a FastAPI app. Tests for pure helpers inside
those scripts use this shim to import them.
"""

from pathlib import Path
import sys


CONFORMANCE_DIR = Path(__file__).parent.parent
if str(CONFORMANCE_DIR) not in sys.path:
    sys.path.insert(0, str(CONFORMANCE_DIR))
