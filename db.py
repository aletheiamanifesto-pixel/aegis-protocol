#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
db.py - Database engine and session management for AEGIS Protocol
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://aegis:aegis@localhost:5432/aegis_db",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables if they do not exist yet."""
    from db_models import Base as ModelBase  # noqa: F401 - import triggers metadata registration
    ModelBase.metadata.create_all(bind=engine)
