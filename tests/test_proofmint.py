#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

os.environ["DATABASE_URL"] = "sqlite://"
os.environ.setdefault("SECRET_KEY", "test-secret-key-32-bytes-for-test")

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db import get_db
from main_app import app
from proofmint.ai_engine import validate_compliance
from proofmint.gs1_formatter import format_as_epcis
from proofmint.models import Base


_TEST_ENGINE = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
_TEST_SESSION_LOCAL = sessionmaker(autocommit=False, autoflush=False, bind=_TEST_ENGINE)
Base.metadata.create_all(bind=_TEST_ENGINE)


def _get_test_db():
    db = _TEST_SESSION_LOCAL()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = _get_test_db
client = TestClient(app)


def _register_brand():
    response = client.post(
        "/proofmint/brands/register",
        json={"name": "Aegis Brand", "email": "brand@proofmint.test", "plan": "free"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _create_product(api_key: str):
    response = client.post(
        "/proofmint/products",
        json={"product_id": "SKU-001", "product_name": "Luxury Oil", "category": "skincare"},
        headers={"X-API-Key": api_key},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _dpp_payload(carbon=2.5):
    return {
        "productId": "SKU-001",
        "productName": "Luxury Oil",
        "category": "skincare",
        "materials": ["glass", "essential oils"],
        "origin_country": "IT",
        "carbon_footprint_kg": carbon,
        "certifications": ["COSMOS"],
        "recycling_instructions": "Recycle glass bottle in dedicated bins",
        "brand_name": "Aegis Brand",
    }


def test_brand_registration_and_product_creation():
    brand = _register_brand()
    product = _create_product(brand["api_key"])

    assert brand["name"] == "Aegis Brand"
    assert "api_key" in brand
    assert product["product_id"] == "SKU-001"


def test_dpp_creation_hash_and_verification_flow():
    brand = client.post(
        "/proofmint/brands/register",
        json={"name": "Aegis Brand 2", "email": "brand2@proofmint.test", "plan": "pro"},
    ).json()
    client.post(
        "/proofmint/products",
        json={"product_id": "SKU-002", "product_name": "Luxury Serum", "category": "skincare"},
        headers={"X-API-Key": brand["api_key"]},
    )

    payload = _dpp_payload()
    payload["productId"] = "SKU-002"
    payload["productName"] = "Luxury Serum"

    create_resp = client.post("/proofmint/dpp/create", json=payload, headers={"X-API-Key": brand["api_key"]})
    assert create_resp.status_code == 201, create_resp.text
    body = create_resp.json()
    assert body["dpp_hash"].startswith("0x")
    assert body["version"] == 1
    assert body["ipfs_cid"]

    verify_resp = client.get("/proofmint/verify/SKU-002")
    assert verify_resp.status_code == 200
    verify_body = verify_resp.json()
    assert verify_body["is_valid"] is True
    assert verify_body["passport_data"]["product_id"] == "SKU-002"


def test_dpp_update_increments_version():
    brand = client.post(
        "/proofmint/brands/register",
        json={"name": "Aegis Brand 3", "email": "brand3@proofmint.test", "plan": "business"},
    ).json()
    client.post(
        "/proofmint/products",
        json={"product_id": "SKU-003", "product_name": "Luxury Cream", "category": "skincare"},
        headers={"X-API-Key": brand["api_key"]},
    )

    create_resp = client.post("/proofmint/dpp/create", json={**_dpp_payload(), "productId": "SKU-003", "productName": "Luxury Cream"}, headers={"X-API-Key": brand["api_key"]})
    assert create_resp.status_code == 201, create_resp.text
    dpp_id = client.get("/proofmint/verify/SKU-003").json()["passport_data"]["dpp_id"]

    update_payload = {**_dpp_payload(carbon=3.1), "productId": "SKU-003", "productName": "Luxury Cream+"}
    update_resp = client.put(f"/proofmint/dpp/{dpp_id}", json=update_payload, headers={"X-API-Key": brand["api_key"]})
    assert update_resp.status_code == 200, update_resp.text
    assert update_resp.json()["version"] == 2


def test_ai_compliance_validation_and_gs1_formatting():
    compliance = validate_compliance(_dpp_payload())
    assert compliance["is_compliant"] is True
    assert compliance["compliance_score"] == 100

    epcis = format_as_epcis(_dpp_payload())
    assert epcis["type"] == "EPCISDocument"
    assert epcis["schemaVersion"] == "2.0"
    assert epcis["epcisBody"]["eventList"][0]["type"] == "ObjectEvent"
