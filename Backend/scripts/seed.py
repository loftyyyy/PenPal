"""Seed and bootstrap script.

Usage:
    python scripts/seed.py --admin-only
    python scripts/seed.py --demo
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings
from app.db.session import dispose_engine, get_session_factory
from app.services.auth import bootstrap_admin


async def run(admin_only: bool) -> None:
    settings = get_settings()
    settings.validate_for_startup()
    factory = get_session_factory()
    async with factory() as db:
        admin = await bootstrap_admin(db, settings)
        if admin is not None:
            print(f"Created administrator {admin.email}")
        else:
            print("Administrator already present; nothing to do")

    if not admin_only:
        print("Demo data is added in a later build step; no assessment was created.")
    await dispose_engine()


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed PenPal data")
    parser.add_argument("--admin-only", action="store_true", help="bootstrap first admin only")
    parser.add_argument("--demo", action="store_true", help="bootstrap admin and demo assessment")
    args = parser.parse_args()
    asyncio.run(run(admin_only=args.admin_only and not args.demo))


if __name__ == "__main__":
    main()
