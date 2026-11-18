"""Insecure defaults must fail closed outside explicit development mode."""

import pytest

import aegis_env
from aegis_env import InsecureConfigError, get_secret_key, require_mocks


@pytest.fixture
def prod(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_MOCKS", "0")
    monkeypatch.setattr(aegis_env, "_dev_secret", None)


@pytest.mark.parametrize("value", ["", "change-me-in-production", "aegis-dev-secret-key-32bytes!!!", "short"])
def test_placeholder_or_short_secret_refused_in_production(prod, monkeypatch, value):
    monkeypatch.setenv("SECRET_KEY", value)
    with pytest.raises(InsecureConfigError):
        get_secret_key()


def test_strong_secret_accepted(prod, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "x" * 40)
    assert get_secret_key() == "x" * 40


def test_dev_mode_generates_random_key(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_MOCKS", "1")
    monkeypatch.setenv("SECRET_KEY", "change-me-in-production")
    monkeypatch.setattr(aegis_env, "_dev_secret", None)
    k = get_secret_key()
    assert len(k) >= 32 and k != "change-me-in-production"


def test_simulations_refused_in_production(prod):
    with pytest.raises(InsecureConfigError):
        require_mocks("on-chain transfer")


def test_proofmint_verification_fails_closed(prod, monkeypatch):
    from proofmint import blockchain_service

    monkeypatch.setattr(blockchain_service, "RPC_URL", "")
    with pytest.raises(InsecureConfigError):
        blockchain_service.verify_passport_onchain(1, "0x" + "00" * 32)
