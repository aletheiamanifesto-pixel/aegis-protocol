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


def _dpp_payload_full():
    payload = _dpp_payload()
    payload.update(
        {
            "materials_detailed": [
                {"name": "glass", "weight_percent": 70.0, "recycled_content_percent": 40.0, "origin_country": "IT"},
                {"name": "plastic", "weight_percent": 30.0, "recycled_content_percent": 20.0, "origin_country": "DE"},
            ],
            "operator_type": "manufacturer",
            "operator_address": "Via Roma 1, Milano, IT",
            "facility_id": "FAC-001",
            "eori_number": "IT1234567890",
            "hazardous_substances": ["Substance-A"],
            "reach_compliant": True,
            "rohs_compliant": True,
            "carbon_footprint_method": "ISO_14067",
            "energy_consumption_kwh": 15.2,
            "water_consumption_liters": 21.0,
            "expected_lifetime_years": 2.0,
            "repair_score": 8.2,
            "spare_parts_available": True,
            "warranty_duration_months": 24,
            "warranty_terms": "Standard warranty",
            "maintenance_instructions": "Keep in cool and dry place",
            "recyclability_percent": 88.5,
            "recycled_content_percent": 34.2,
            "disassembly_instructions": "Separate cap and bottle",
            "collection_points_url": "https://example.com/collection",
            "reuse_potential": "high",
            "ce_marking": True,
            "conformity_declaration_url": "https://example.com/conformity.pdf",
            "test_reports_urls": ["https://example.com/report-1.pdf"],
            "hs_code": "330499",
            "cn_code": "33049900",
            "product_image_url": "https://example.com/product.png",
            "model_variant": "2026-A",
        }
    )
    return payload


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
    compliance = validate_compliance(_dpp_payload_full())
    assert compliance["is_compliant"] is True
    assert compliance["compliance_score"] == 100
    assert compliance["compliance_level"] == "full"
    assert compliance["required_missing"] == []

    epcis = format_as_epcis(_dpp_payload_full())
    assert epcis["type"] == "EPCISDocument"
    assert epcis["schemaVersion"] == "2.0"
    assert epcis["epcisBody"]["eventList"][0]["type"] == "ObjectEvent"
    assert "identity" in epcis["epcisBody"]["eventList"][0]["proofmint:dpp"]


def test_brand_registration_accepts_extended_fields():
    response = client.post(
        "/proofmint/brands/register",
        json={
            "name": "Aegis Brand Extended",
            "email": "brand-extended@proofmint.test",
            "plan": "pro",
            "operator_type": "importer",
            "address": "Via Torino 10, Torino, IT",
            "country": "IT",
            "phone": "+3902123456",
            "website": "https://brand.example",
            "eori_number": "ITX123",
            "facility_id": "FAC-BRAND-99",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["operator_type"] == "importer"
    assert body["eori_number"] == "ITX123"
    assert body["facility_id"] == "FAC-BRAND-99"


def test_dpp_creation_with_extended_fields_and_access_levels():
    os.environ["PROOFMINT_ALLOW_SCOPE_HEADER"] = "true"
    try:
        brand = client.post(
            "/proofmint/brands/register",
            json={"name": "Aegis Brand 4", "email": "brand4@proofmint.test", "plan": "business"},
        ).json()
        client.post(
            "/proofmint/products",
            json={"product_id": "SKU-004", "product_name": "Luxury Balm", "category": "skincare"},
            headers={"X-API-Key": brand["api_key"]},
        )

        payload = _dpp_payload_full()
        payload["productId"] = "SKU-004"
        payload["productName"] = "Luxury Balm"
        payload["brand_name"] = "Aegis Brand 4"

        create_resp = client.post("/proofmint/dpp/create", json=payload, headers={"X-API-Key": brand["api_key"]})
        assert create_resp.status_code == 201, create_resp.text
        created = create_resp.json()
        assert created["materials_detailed"][0]["name"] == "glass"
        assert created["hazardous_substances"] == ["Substance-A"]
        assert created["test_reports_urls"] == ["https://example.com/report-1.pdf"]
        assert created["model_variant"] == "2026-A"

        public_resp = client.get("/proofmint/verify/SKU-004")
        assert public_resp.status_code == 200
        public_data = public_resp.json()["passport_data"]
        assert "hazardous_substances" not in public_data
        assert "eori_number" not in public_data
        assert "facility_id" not in public_data
        assert "test_reports_urls" not in public_data

        full_unauthorized = client.get("/proofmint/verify/SKU-004/full")
        assert full_unauthorized.status_code == 401

        full_resp = client.get("/proofmint/verify/SKU-004/full", headers={"X-Viewing-Key-Scope": "regulator"})
        assert full_resp.status_code == 200, full_resp.text
        full_data = full_resp.json()["passport_data"]
        assert full_data["hazardous_substances"] == ["Substance-A"]
        assert full_data["eori_number"] == "IT1234567890"
        assert full_data["facility_id"] == "FAC-001"

        recycler_resp = client.get("/proofmint/verify/SKU-004/recycler", headers={"X-Viewing-Key-Scope": "recycler"})
        assert recycler_resp.status_code == 200, recycler_resp.text
        recycler_data = recycler_resp.json()["passport_data"]
        assert recycler_data["materials_detailed"][0]["name"] == "glass"
        assert recycler_data["hazardous_substances"] == ["Substance-A"]
        assert recycler_data["disassembly_instructions"] == "Separate cap and bottle"
        assert "eori_number" not in recycler_data
        assert "operator_address" not in recycler_data
    finally:
        os.environ.pop("PROOFMINT_ALLOW_SCOPE_HEADER", None)


def test_compliance_validation_multi_category_scoring():
    compliance = validate_compliance(_dpp_payload())
    assert compliance["is_compliant"] is False
    assert "model_variant" in compliance["required_missing"]
    assert "operator_type" in compliance["required_missing"]
    assert "recyclability_percent" in compliance["required_missing"]
    assert "identity" in compliance["categories"]
    assert compliance["compliance_score"] < 85
    assert compliance["compliance_level"] in {"critical", "low", "medium"}


def test_backward_compatibility_original_dpp_payload_still_works():
    brand = client.post(
        "/proofmint/brands/register",
        json={"name": "Aegis Brand 5", "email": "brand5@proofmint.test", "plan": "free"},
    ).json()
    client.post(
        "/proofmint/products",
        json={"product_id": "SKU-005", "product_name": "Legacy Oil", "category": "skincare"},
        headers={"X-API-Key": brand["api_key"]},
    )

    payload = _dpp_payload()
    payload["productId"] = "SKU-005"
    payload["productName"] = "Legacy Oil"
    payload["brand_name"] = "Aegis Brand 5"

    response = client.post("/proofmint/dpp/create", json=payload, headers={"X-API-Key": brand["api_key"]})
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["productId"] == "SKU-005"
    assert body["materials_detailed"] == []
    assert body["hazardous_substances"] == []


def test_scope_header_requires_feature_flag():
    brand = client.post(
        "/proofmint/brands/register",
        json={"name": "Aegis Brand 6", "email": "brand6@proofmint.test", "plan": "free"},
    ).json()
    client.post(
        "/proofmint/products",
        json={"product_id": "SKU-006", "product_name": "Flag Test", "category": "skincare"},
        headers={"X-API-Key": brand["api_key"]},
    )
    payload = _dpp_payload()
    payload["productId"] = "SKU-006"
    payload["productName"] = "Flag Test"
    payload["brand_name"] = "Aegis Brand 6"
    create_resp = client.post("/proofmint/dpp/create", json=payload, headers={"X-API-Key": brand["api_key"]})
    assert create_resp.status_code == 201, create_resp.text

    os.environ.pop("PROOFMINT_ALLOW_SCOPE_HEADER", None)
    blocked = client.get("/proofmint/verify/SKU-006/full", headers={"X-Viewing-Key-Scope": "regulator"})
    assert blocked.status_code == 401


# --- Piani: enforcement lato server (agenti/2026-11-24) ---------------------

def _register(email: str, plan: str = "free"):
    response = client.post(
        "/proofmint/brands/register",
        json={"name": "Plan Brand", "email": email, "plan": plan},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _add_product(api_key: str, sku: str):
    return client.post(
        "/proofmint/products",
        json={"product_id": sku, "product_name": "Item", "category": "textile"},
        headers={"X-API-Key": api_key},
    )


def test_registration_cannot_self_assign_pro_plan():
    body = _register("self-pro@proofmint.test", plan="pro")
    assert body["plan"] == "free"
    assert body["requested_plan"] == "pro"
    assert body["products_limit"] == 5


def test_free_plan_product_limit_is_enforced():
    brand = _register("limit-free@proofmint.test")
    for i in range(5):
        assert _add_product(brand["api_key"], f"FREE-LIM-{i}").status_code == 201
    blocked = _add_product(brand["api_key"], "FREE-LIM-5")
    assert blocked.status_code == 402, blocked.text


def test_pro_plan_lifts_limit():
    from proofmint.models import Brand

    brand = _register("limit-pro@proofmint.test")
    for i in range(5):
        assert _add_product(brand["api_key"], f"PRO-LIM-{i}").status_code == 201

    db = _TEST_SESSION_LOCAL()
    try:
        row = db.query(Brand).filter(Brand.id == brand["brand_id"]).first()
        row.plan = "pro"
        db.commit()
    finally:
        db.close()

    assert _add_product(brand["api_key"], "PRO-LIM-5").status_code == 201


def test_plan_change_requires_admin_auth():
    brand = _register("plan-admin@proofmint.test")
    response = client.patch(f"/proofmint/brands/{brand['brand_id']}/plan", json={"plan": "pro"})
    assert response.status_code == 401


# --- Correzioni dalla revisione di Hermes (AEG-8) ---------------------------

def _set_brand(brand_id: int, **fields):
    from proofmint.models import Brand

    db = _TEST_SESSION_LOCAL()
    try:
        row = db.query(Brand).filter(Brand.id == brand_id).first()
        for key, value in fields.items():
            setattr(row, key, value)
        db.commit()
    finally:
        db.close()


def _as_admin():
    from proofmint.router import ADMIN_ONLY

    app.dependency_overrides[ADMIN_ONLY] = lambda: {"user_id": "1", "role": "admin"}


def _drop_admin():
    from proofmint.router import ADMIN_ONLY

    app.dependency_overrides.pop(ADMIN_ONLY, None)


def test_admin_can_upgrade_plan_and_unknown_plan_is_rejected():
    brand = _register("admin-ok@proofmint.test")
    _as_admin()
    try:
        ok = client.patch(f"/proofmint/brands/{brand['brand_id']}/plan", json={"plan": " PRO "})
        assert ok.status_code == 200, ok.text
        assert ok.json()["plan"] == "pro"
        assert ok.json()["previous_plan"] == "free"
        assert ok.json()["products_limit"] == 500

        bad = client.patch(f"/proofmint/brands/{brand['brand_id']}/plan", json={"plan": "enterprise"})
        assert bad.status_code == 422

        wrong_type = client.patch(f"/proofmint/brands/{brand['brand_id']}/plan", json={"plan": 1})
        assert wrong_type.status_code == 422
    finally:
        _drop_admin()


def test_plan_value_is_normalized_when_reading_limits():
    brand = _register("legacy-upper@proofmint.test")
    _set_brand(brand["brand_id"], plan="PRO", products_count=5)
    assert _add_product(brand["api_key"], "LEGACY-UPPER-1").status_code == 201


def test_duplicate_sku_at_limit_returns_400_not_402():
    brand = _register("dup-at-limit@proofmint.test")
    for i in range(5):
        assert _add_product(brand["api_key"], f"DUP-LIM-{i}").status_code == 201
    again = _add_product(brand["api_key"], "DUP-LIM-0")
    assert again.status_code == 400, again.text


def test_counter_matches_products_after_limit():
    from proofmint.models import Brand, Product

    brand = _register("counter-sync@proofmint.test")
    for i in range(7):
        _add_product(brand["api_key"], f"SYNC-{i}")
    db = _TEST_SESSION_LOCAL()
    try:
        row = db.query(Brand).filter(Brand.id == brand["brand_id"]).first()
        real = db.query(Product).filter(Product.brand_id == brand["brand_id"]).count()
        assert row.products_count == real == 5
    finally:
        db.close()
