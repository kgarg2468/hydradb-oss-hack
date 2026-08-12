import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The `hindsight` package is imported from the repo root without installing it.
sys.path.insert(0, str(ROOT))

# PoC modules (lockparse, hydra client) live in poc/ and are imported by tests.
sys.path.insert(0, str(ROOT / "poc"))
