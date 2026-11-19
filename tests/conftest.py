#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
conftest.py - Pytest fixtures for AEGIS Protocol tests.
"""

import pytest
import os

# Set env vars before imports
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret-key-32-bytes-for-test")
# The tests run without nargo: mock proofs are allowed ONLY here.
os.environ.setdefault("AEGIS_ALLOW_MOCK_PROOFS", "1")
# ...and so are the simulated chain/bridge/wallet (see aegis_env.py).
os.environ.setdefault("AEGIS_ALLOW_MOCKS", "1")
# Test EURC token: transactions arrive signed by the client for this contract.
os.environ.setdefault("EURC_TOKEN_ADDRESS", "0x" + "e0" * 20)
os.environ.setdefault("CHAIN_ID", "80002")
os.environ.setdefault("RPC_URL", "http://localhost:8545")


@pytest.fixture
def sample_address():
    return "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"


@pytest.fixture
def sample_private_key():
    return "0x" + "a" * 64


@pytest.fixture
def compliance_engine():
    from compliance_engine import ComplianceEngine
    return ComplianceEngine()
