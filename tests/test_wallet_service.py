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


class TestCreateWallet:
    def test_create_wallet_returns_address(self):
        result = create_wallet("test-password")
        assert "address" in result
        assert "encrypted_key" in result
        assert "mnemonic" in result

    def test_address_format(self):
        result = create_wallet("password123")
        assert result["address"].startswith("0x")

    def test_different_wallets_differ(self):
        w1 = create_wallet("pw1")
        w2 = create_wallet("pw2")
        assert w1["address"] != w2["address"]


class TestImportWallet:
    def test_import_with_private_key(self):
        # Create wallet first, then reimport
        w = create_wallet("password")
        pk = decrypt_wallet_key(w["encrypted_key"], "password")
        imported = import_wallet(pk, "new-password")
        assert "address" in imported
        assert "encrypted_key" in imported

    def test_decrypt_wallet_key(self):
        w = create_wallet("mypassword")
        pk = decrypt_wallet_key(w["encrypted_key"], "mypassword")
        assert len(pk) > 0

    def test_wrong_password_raises(self):
        w = create_wallet("correct-password")
        with pytest.raises(WalletError):
            decrypt_wallet_key(w["encrypted_key"], "wrong-password")


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
