"""Migrations create exactly the schema of the models (no differences)."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _alembic(args, url):
    env = {**os.environ, "DATABASE_URL": url}
    return subprocess.run([sys.executable, "-m", "alembic", *args], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=120)


def test_upgrade_head_matches_models(tmp_path):
    url = f"sqlite:///{tmp_path / 'm.db'}"
    up = _alembic(["upgrade", "head"], url)
    assert up.returncode == 0, up.stderr
    check = _alembic(["check"], url)
    assert check.returncode == 0, check.stdout + check.stderr


def test_downgrade_base_and_back(tmp_path):
    url = f"sqlite:///{tmp_path / 'm2.db'}"
    assert _alembic(["upgrade", "head"], url).returncode == 0
    down = _alembic(["downgrade", "base"], url)
    assert down.returncode == 0, down.stderr
    assert _alembic(["upgrade", "head"], url).returncode == 0
