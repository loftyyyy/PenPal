"""Export the FastAPI OpenAPI schema to docs/openapi.json.

Run from the Backend directory:
    python scripts/export_openapi.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.main import create_app

OUTPUT = Path(__file__).resolve().parents[2] / "docs" / "openapi.json"


def main() -> None:
    spec = create_app().openapi()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(spec, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
