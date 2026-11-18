#!/usr/bin/env python3
"""Assign a role to an existing user directly in the database (first-admin bootstrap).

  python scripts/create_admin.py <username> [role] [authority_type]

Only the API's admins can change roles afterwards (POST /admin/users/{id}/role).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from db import SessionLocal  # noqa: E402
import db_models  # noqa: E402
from security import AUTHORITY_TYPES, ROLES  # noqa: E402


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    username, role = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "admin")
    authority_type = sys.argv[3] if len(sys.argv) > 3 else None
    if role not in ROLES or (role == "authority" and authority_type not in AUTHORITY_TYPES):
        print(f"invalid role/authority_type: {role} {authority_type}")
        return 2
    db = SessionLocal()
    user = db.query(db_models.User).filter(db_models.User.username == username).first()
    if user is None:
        print(f"user {username} not found")
        return 1
    user.role, user.authority_type = role, (authority_type if role == "authority" else None)
    user.token_version = (user.token_version or 0) + 1
    db.commit()
    print(f"{username}: role={user.role} authority_type={user.authority_type}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
