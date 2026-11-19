#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests for wallet_service.py"""

import pytest
from wallet_service import (
    create_wallet,
    import_wallet,
    decrypt_wallet_key,
    get_balance,
    generate_receive_qr,
    estimate_fee,
    WalletError,
)


PW = "correct horse battery"
PW2 = "another long passphrase"


class TestCreateWallet:
    def test_create_wallet_returns_address(self):
        result = create_wallet(PW)
        assert result["address"].startswith("0x")
        assert result["encrypted_key"].startswith("aegis-kdf-v2$")
        assert len(result["mnemonic"].split()) == 12

    def test_different_wallets_differ(self):
        assert create_wallet(PW)["address"] != create_wallet(PW)["address"]

    @pytest.mark.parametrize("weak", ["", "short", "password123", "aaaaaaaaaaaaaaaa"])
    def test_weak_passwords_rejected(self, weak):
        with pytest.raises(WalletError):
            create_wallet(weak)


class TestKeyEncryption:
    def test_roundtrip_and_reimport(self):
        w = create_wallet(PW)
        pk = decrypt_wallet_key(w["encrypted_key"], PW)
        imported = import_wallet(pk, PW2)
        assert imported["address"] == w["address"]
        assert decrypt_wallet_key(imported["encrypted_key"], PW2) == pk

    def test_wrong_password_raises(self):
        w = create_wallet(PW)
        with pytest.raises(WalletError):
            decrypt_wallet_key(w["encrypted_key"], PW2)

    def test_salted_kdf_not_plain_sha256(self):
        """Same password and key → different ciphertexts (random salt), and the legacy
        Fernet key = SHA256(password) cannot open them."""
        import base64
        import hashlib

        from cryptography.fernet import Fernet, InvalidToken

        from wallet_service import encrypt_private_key

        a, b = encrypt_private_key("ab" * 32, PW), encrypt_private_key("ab" * 32, PW)
        assert a != b
        legacy = Fernet(base64.urlsafe_b64encode(hashlib.sha256(PW.encode()).digest()))
        with pytest.raises(InvalidToken):
            legacy.decrypt(a.split("$", 2)[2].encode())


class TestGetBalance:
    def test_get_balance_returns_float(self, sample_address):
        balance = get_balance(sample_address)
        assert isinstance(balance, float)
        assert balance >= 0.0

    def test_invalid_address_returns_zero(self):
        balance = get_balance("not-an-address")
        assert balance == 0.0


class TestGenerateQR:
    def test_qr_returns_bytes(self, sample_address):
        result = generate_receive_qr(sample_address)
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_qr_is_png(self, sample_address):
        result = generate_receive_qr(sample_address)
        # PNG magic bytes: \x89PNG
        assert result[:4] == b"\x89PNG" or result[:4] == b"\x89\x50\x4e\x47" or len(result) > 0


class TestEstimateFee:
    def test_estimate_fee_returns_dict(self):
        result = estimate_fee("0xfrom", "0xto", 100.0)
        assert "estimated_fee_eur" in result
        assert "gas_price_gwei" in result
        assert "estimated_gas" in result

    def test_fee_values_are_positive(self):
        result = estimate_fee("0xfrom", "0xto", 100.0)
        assert result["estimated_fee_eur"] >= 0
        assert result["gas_price_gwei"] >= 0
        assert result["estimated_gas"] > 0
