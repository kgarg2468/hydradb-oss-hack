import sys
from pathlib import Path

# PoC modules (lockparse, hydra client) live in poc/ and are imported by tests.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "poc"))
