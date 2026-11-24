import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import desc, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from db import Base, get_db
from security import require_roles
from proofmint.ai_engine import validate_compliance
from proofmint.blockchain_service import (
    create_passport_onchain,
    update_passport_onchain,
    verify_passport_onchain,
)
from proofmint.models import Brand, DigitalProductPassport, Product
from proofmint.schemas import (
    BrandPlanUpdate,
    BrandRegister,
    DPPCreate,
    DPPResponse,
    MaterialDetail,
    ProductCreate,
)
from proofmint.storage_service import get_from_ipfs, upload_to_ipfs

router = APIRouter(prefix="/proofmint", tags=["proofmint"])

# Limiti di prodotti per piano, allineati alla pagina prezzi (frontend/app/pricing).
# Il piano e' deciso solo lato server: la registrazione parte sempre da "free"
# e il passaggio a "pro" avviene tramite l'endpoint admin (dopo il pagamento).
PLAN_LIMITS: dict[str, int] = {"free": 5, "pro": 500}
DEFAULT_PLAN = "free"


logger = logging.getLogger(__name__)

# Dipendenza admin a livello di modulo: i test possono sovrascriverla con
# app.dependency_overrides[ADMIN_ONLY] (require_roles crea una funzione nuova a ogni chiamata).
ADMIN_ONLY = require_roles("admin")


def _normalize_plan(plan: str | None) -> str:
    return str(plan or "").strip().lower()


def _plan_limit(plan: str | None) -> int:
    normalized = _normalize_plan(plan)
    if normalized in PLAN_LIMITS:
        return PLAN_LIMITS[normalized]
    # Piano sconosciuto (riga legacy o modifica manuale): lo segnaliamo invece di
    # ricadere in silenzio su "free".
    logger.warning("ProofMint: piano sconosciuto %r, applico il limite di %r", plan, DEFAULT_PLAN)
    return PLAN_LIMITS[DEFAULT_PLAN]

_tables_ready = False


def _env_flag(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes"}


def _ensure_tables(db: Session) -> None:
    global _tables_ready
    if not _tables_ready:
        Base.metadata.create_all(bind=db.get_bind())
        _tables_ready = True


def _get_brand_by_key(db: Session, x_api_key: str | None) -> Brand:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")
    brand = db.query(Brand).filter(Brand.api_key == x_api_key).first()
    if not brand:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return brand


def _dpp_hash(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "0x" + hashlib.sha256(raw.encode()).hexdigest()


def _serialize_materials_detailed(payload: DPPCreate) -> list[dict]:
    return [material.model_dump() for material in payload.materials_detailed]


def _serialize_response(product: Product, dpp: DigitalProductPassport, brand: Brand) -> DPPResponse:
    return DPPResponse(
        productId=product.product_id,
        productName=product.product_name,
        category=product.category,
        materials=dpp.materials_json or [],
        origin_country=dpp.origin_country,
        carbon_footprint_kg=dpp.carbon_footprint_kg,
        certifications=dpp.certifications_json or [],
        recycling_instructions=dpp.recycling_instructions,
        brand_name=brand.name,
        materials_detailed=[MaterialDetail(**entry) for entry in (dpp.materials_detailed_json or [])],
        operator_type=dpp.operator_type,
        operator_address=dpp.operator_address,
        facility_id=dpp.facility_id,
        eori_number=dpp.eori_number,
        hazardous_substances=dpp.hazardous_substances_json or [],
        reach_compliant=dpp.reach_compliant,
        rohs_compliant=dpp.rohs_compliant,
        carbon_footprint_method=dpp.carbon_footprint_method,
        energy_consumption_kwh=dpp.energy_consumption_kwh,
        water_consumption_liters=dpp.water_consumption_liters,
        expected_lifetime_years=dpp.expected_lifetime_years,
        repair_score=dpp.repair_score,
        spare_parts_available=dpp.spare_parts_available,
        warranty_duration_months=dpp.warranty_duration_months,
        warranty_terms=dpp.warranty_terms,
        maintenance_instructions=dpp.maintenance_instructions,
        recyclability_percent=dpp.recyclability_percent,
        recycled_content_percent=dpp.recycled_content_percent,
        disassembly_instructions=dpp.disassembly_instructions,
        collection_points_url=dpp.collection_points_url,
        reuse_potential=dpp.reuse_potential,
        ce_marking=dpp.ce_marking,
        conformity_declaration_url=dpp.conformity_declaration_url,
        test_reports_urls=dpp.test_reports_urls_json or [],
        hs_code=dpp.hs_code,
        cn_code=dpp.cn_code,
        product_image_url=dpp.product_image_url,
        model_variant=dpp.model_variant,
        dpp_hash=dpp.dpp_hash,
        blockchain_tx=dpp.blockchain_tx_hash,
        ipfs_cid=dpp.ipfs_cid,
        created_at=dpp.created_at,
        version=dpp.version,
        verification_url=f"/proofmint/verify/{product.product_id}",
    )


def _resolve_viewing_scope(x_viewing_key: str | None, x_viewing_key_scope: str | None) -> str:
    scope_value = (x_viewing_key_scope or "").strip().lower()
    allow_scope_header = _env_flag("PROOFMINT_ALLOW_SCOPE_HEADER")
    if scope_value and allow_scope_header:
        if scope_value == "regulator":
            return "full_access"
        if scope_value == "recycler":
            return "tx_only"
        raise HTTPException(status_code=403, detail="Unsupported scope header value")

    if not x_viewing_key:
        raise HTTPException(status_code=401, detail="Missing viewing key")

    try:
        from routers.viewing_keys_v2 import _get_vk_manager
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail="Viewing key authentication module (routers.viewing_keys_v2) is not available",
        ) from exc

    manager = _get_vk_manager()
    info = manager.get_key_info(x_viewing_key)
    if not info:
        raise HTTPException(status_code=403, detail="Invalid viewing key")
    if info.get("status") != "active":
        raise HTTPException(status_code=403, detail="Inactive viewing key")
    return str(info.get("scope", "")).lower()


def _require_regulator_scope(x_viewing_key: str | None, x_viewing_key_scope: str | None) -> None:
    scope = _resolve_viewing_scope(x_viewing_key, x_viewing_key_scope)
    if scope != "full_access":
        raise HTTPException(status_code=403, detail="Regulator-level viewing key required")


def _require_recycler_scope(x_viewing_key: str | None, x_viewing_key_scope: str | None) -> None:
    scope = _resolve_viewing_scope(x_viewing_key, x_viewing_key_scope)
    if scope not in {"tx_only", "full_access"}:
        raise HTTPException(status_code=403, detail="Recycler-level viewing key required")


@router.post("/brands/register", status_code=201)
def register_brand(payload: BrandRegister, db: Session = Depends(get_db)):
    _ensure_tables(db)

    existing = db.query(Brand).filter(Brand.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Brand email already registered")

    api_key = secrets.token_urlsafe(32)
    brand = Brand(
        name=payload.name,
        email=payload.email,
        api_key=api_key,
        plan=DEFAULT_PLAN,
        operator_type=payload.operator_type,
        address=payload.address,
        country=payload.country,
        phone=payload.phone,
        website=payload.website,
        eori_number=payload.eori_number,
        facility_id=payload.facility_id,
    )
    db.add(brand)
    db.commit()
    db.refresh(brand)

    return {
        "brand_id": brand.id,
        "name": brand.name,
        "email": brand.email,
        "plan": brand.plan,
        "requested_plan": payload.plan if payload.plan != brand.plan else None,
        "products_limit": _plan_limit(brand.plan),
        "operator_type": brand.operator_type,
        "address": brand.address,
        "country": brand.country,
        "phone": brand.phone,
        "website": brand.website,
        "eori_number": brand.eori_number,
        "facility_id": brand.facility_id,
        "api_key": brand.api_key,
    }


@router.patch("/brands/{brand_id}/plan")
def set_brand_plan(
    brand_id: int,
    payload: BrandPlanUpdate,
    db: Session = Depends(get_db),
    admin: dict = Depends(ADMIN_ONLY),
):
    """Cambia il piano di un brand. Solo admin (es. dopo conferma del pagamento)."""
    _ensure_tables(db)
    plan = _normalize_plan(payload.plan)
    if plan not in PLAN_LIMITS:
        raise HTTPException(status_code=422, detail=f"Unknown plan. Allowed: {sorted(PLAN_LIMITS)}")
    brand = db.query(Brand).filter(Brand.id == brand_id).first()
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")
    previous = brand.plan
    brand.plan = plan
    db.commit()
    used = brand.products_count or 0
    logger.info("ProofMint: piano brand %s %r -> %r (admin %s)", brand.id, previous, plan, admin.get("user_id"))
    return {
        "brand_id": brand.id,
        "plan": brand.plan,
        "previous_plan": previous,
        "products_limit": _plan_limit(brand.plan),
        "products_count": used,
        "over_limit": used > _plan_limit(brand.plan),
    }


@router.post("/products", status_code=201)
def create_product(payload: ProductCreate, db: Session = Depends(get_db), api_key: str | None = Header(default=None, alias="X-API-Key")):
    _ensure_tables(db)
    brand = _get_brand_by_key(db, api_key)

    # 1) Duplicato prima del limite: un retry dello stesso SKU riceve 400, non 402.
    existing = db.query(Product).filter(Product.product_id == payload.product_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Product already exists")

    # 2) Incremento atomico con guardia: due richieste concorrenti non possono
    #    superare il limite (niente check-then-act su un valore letto in Python).
    limit = _plan_limit(brand.plan)
    reserved = (
        db.query(Brand)
        .filter(Brand.id == brand.id, func.coalesce(Brand.products_count, 0) < limit)
        .update(
            {Brand.products_count: func.coalesce(Brand.products_count, 0) + 1},
            synchronize_session=False,
        )
    )
    if reserved != 1:
        db.rollback()
        raise HTTPException(
            status_code=402,
            detail=f"Product limit reached for plan '{brand.plan}' ({limit}). Upgrade required.",
        )

    product = Product(
        product_id=payload.product_id,
        product_name=payload.product_name,
        category=payload.category,
        brand_id=brand.id,
    )
    db.add(product)
    try:
        db.commit()
    except IntegrityError:
        # SKU duplicato inserito in parallelo: annulla anche la prenotazione del contatore.
        db.rollback()
        raise HTTPException(status_code=400, detail="Product already exists")
    db.refresh(product)

    return {
        "id": product.id,
        "product_id": product.product_id,
        "product_name": product.product_name,
        "category": product.category,
        "brand_id": product.brand_id,
    }


@router.post("/dpp/create", response_model=DPPResponse, status_code=201)
def create_dpp(payload: DPPCreate, db: Session = Depends(get_db), api_key: str | None = Header(default=None, alias="X-API-Key")):
    _ensure_tables(db)
    brand = _get_brand_by_key(db, api_key)

    product = db.query(Product).filter(Product.product_id == payload.productId, Product.brand_id == brand.id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found for this brand")

    dpp_payload = payload.model_dump()
    dpp_hash = _dpp_hash(dpp_payload)
    ipfs_cid = upload_to_ipfs(dpp_payload)
    tx_hash = create_passport_onchain(product.product_id, dpp_hash, ipfs_cid)

    latest = (
        db.query(DigitalProductPassport)
        .filter(DigitalProductPassport.product_id == product.id)
        .order_by(desc(DigitalProductPassport.version))
        .first()
    )
    next_version = 1 if latest is None else latest.version + 1

    dpp = DigitalProductPassport(
        product_id=product.id,
        dpp_hash=dpp_hash,
        blockchain_tx_hash=tx_hash,
        ipfs_cid=ipfs_cid,
        version=next_version,
        materials_json=payload.materials,
        materials_detailed_json=_serialize_materials_detailed(payload),
        origin_country=payload.origin_country,
        carbon_footprint_kg=payload.carbon_footprint_kg,
        certifications_json=payload.certifications,
        recycling_instructions=payload.recycling_instructions,
        hazardous_substances_json=payload.hazardous_substances,
        reach_compliant=payload.reach_compliant,
        rohs_compliant=payload.rohs_compliant,
        carbon_footprint_method=payload.carbon_footprint_method,
        energy_consumption_kwh=payload.energy_consumption_kwh,
        water_consumption_liters=payload.water_consumption_liters,
        expected_lifetime_years=payload.expected_lifetime_years,
        repair_score=payload.repair_score,
        spare_parts_available=payload.spare_parts_available,
        warranty_duration_months=payload.warranty_duration_months,
        warranty_terms=payload.warranty_terms,
        maintenance_instructions=payload.maintenance_instructions,
        recyclability_percent=payload.recyclability_percent,
        recycled_content_percent=payload.recycled_content_percent,
        disassembly_instructions=payload.disassembly_instructions,
        collection_points_url=payload.collection_points_url,
        reuse_potential=payload.reuse_potential,
        ce_marking=payload.ce_marking,
        conformity_declaration_url=payload.conformity_declaration_url,
        test_reports_urls_json=payload.test_reports_urls,
        hs_code=payload.hs_code,
        cn_code=payload.cn_code,
        product_image_url=payload.product_image_url,
        model_variant=payload.model_variant,
        operator_type=payload.operator_type,
        operator_address=payload.operator_address,
        facility_id=payload.facility_id,
        eori_number=payload.eori_number,
        is_active=True,
    )
    db.add(dpp)
    db.commit()
    db.refresh(dpp)

    return _serialize_response(product, dpp, brand)


@router.get("/dpp/{dpp_id}")
def get_dpp(dpp_id: int, db: Session = Depends(get_db)):
    _ensure_tables(db)
    dpp = db.query(DigitalProductPassport).filter(DigitalProductPassport.id == dpp_id).first()
    if not dpp:
        raise HTTPException(status_code=404, detail="DPP not found")

    product = db.query(Product).filter(Product.id == dpp.product_id).first()
    brand = db.query(Brand).filter(Brand.id == product.brand_id).first()
    data = _serialize_response(product, dpp, brand).model_dump()
    data["is_active"] = dpp.is_active
    data["ipfs_payload"] = get_from_ipfs(dpp.ipfs_cid)
    return data


@router.get("/verify/{product_id}")
def verify_product_dpp(product_id: str, db: Session = Depends(get_db)):
    _ensure_tables(db)
    product = db.query(Product).filter(Product.product_id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    dpp = (
        db.query(DigitalProductPassport)
        .filter(DigitalProductPassport.product_id == product.id)
        .order_by(desc(DigitalProductPassport.version))
        .first()
    )
    if not dpp or not dpp.is_active:
        return {"is_valid": False, "passport_data": None}

    is_valid = verify_passport_onchain(dpp.id, dpp.dpp_hash)
    return {
        "is_valid": bool(is_valid),
        "passport_data": {
            "dpp_id": dpp.id,
            "product_id": product.product_id,
            "product_name": product.product_name,
            "category": product.category,
            "brand_name": product.brand.name if product.brand else None,
            "model_variant": dpp.model_variant,
            "materials": dpp.materials_json or [],
            "origin_country": dpp.origin_country,
            "carbon_footprint_kg": dpp.carbon_footprint_kg,
            "carbon_footprint_method": dpp.carbon_footprint_method,
            "certifications": dpp.certifications_json or [],
            "recycling_instructions": dpp.recycling_instructions,
            "recyclability_percent": dpp.recyclability_percent,
            "recycled_content_percent": dpp.recycled_content_percent,
            "ce_marking": dpp.ce_marking,
            "operator_type": dpp.operator_type,
            "product_image_url": dpp.product_image_url,
            "dpp_hash": dpp.dpp_hash,
            "version": dpp.version,
            "ipfs_cid": dpp.ipfs_cid,
        },
    }


@router.get("/verify/{product_id}/full")
def verify_product_dpp_full(
    product_id: str,
    db: Session = Depends(get_db),
    viewing_key: str | None = Header(default=None, alias="X-Viewing-Key"),
    viewing_key_scope: str | None = Header(default=None, alias="X-Viewing-Key-Scope"),
):
    _require_regulator_scope(viewing_key, viewing_key_scope)
    _ensure_tables(db)
    product = db.query(Product).filter(Product.product_id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    dpp = (
        db.query(DigitalProductPassport)
        .filter(DigitalProductPassport.product_id == product.id)
        .order_by(desc(DigitalProductPassport.version))
        .first()
    )
    if not dpp or not dpp.is_active:
        return {"is_valid": False, "passport_data": None}

    return {
        "is_valid": bool(verify_passport_onchain(dpp.id, dpp.dpp_hash)),
        "passport_data": _serialize_response(product, dpp, product.brand).model_dump(),
    }


@router.get("/verify/{product_id}/recycler")
def verify_product_dpp_recycler(
    product_id: str,
    db: Session = Depends(get_db),
    viewing_key: str | None = Header(default=None, alias="X-Viewing-Key"),
    viewing_key_scope: str | None = Header(default=None, alias="X-Viewing-Key-Scope"),
):
    _require_recycler_scope(viewing_key, viewing_key_scope)
    _ensure_tables(db)
    product = db.query(Product).filter(Product.product_id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    dpp = (
        db.query(DigitalProductPassport)
        .filter(DigitalProductPassport.product_id == product.id)
        .order_by(desc(DigitalProductPassport.version))
        .first()
    )
    if not dpp or not dpp.is_active:
        return {"is_valid": False, "passport_data": None}

    return {
        "is_valid": bool(verify_passport_onchain(dpp.id, dpp.dpp_hash)),
        "passport_data": {
            "dpp_id": dpp.id,
            "product_id": product.product_id,
            "product_name": product.product_name,
            "category": product.category,
            "materials": dpp.materials_json or [],
            "materials_detailed": dpp.materials_detailed_json or [],
            "hazardous_substances": dpp.hazardous_substances_json or [],
            "disassembly_instructions": dpp.disassembly_instructions,
            "recycling_instructions": dpp.recycling_instructions,
            "recyclability_percent": dpp.recyclability_percent,
            "recycled_content_percent": dpp.recycled_content_percent,
            "version": dpp.version,
            "dpp_hash": dpp.dpp_hash,
        },
    }


@router.put("/dpp/{dpp_id}", response_model=DPPResponse)
def update_dpp(dpp_id: int, payload: DPPCreate, db: Session = Depends(get_db), api_key: str | None = Header(default=None, alias="X-API-Key")):
    _ensure_tables(db)
    brand = _get_brand_by_key(db, api_key)

    dpp = db.query(DigitalProductPassport).filter(DigitalProductPassport.id == dpp_id).first()
    if not dpp:
        raise HTTPException(status_code=404, detail="DPP not found")

    product = db.query(Product).filter(Product.id == dpp.product_id).first()
    if not product or product.brand_id != brand.id:
        raise HTTPException(status_code=403, detail="Not allowed")

    new_payload = payload.model_dump()
    new_hash = _dpp_hash(new_payload)
    new_cid = upload_to_ipfs(new_payload)
    tx_hash = update_passport_onchain(dpp.id, new_hash, new_cid)

    dpp.dpp_hash = new_hash
    dpp.ipfs_cid = new_cid
    dpp.blockchain_tx_hash = tx_hash
    dpp.version += 1
    dpp.materials_json = payload.materials
    dpp.materials_detailed_json = _serialize_materials_detailed(payload)
    dpp.origin_country = payload.origin_country
    dpp.carbon_footprint_kg = payload.carbon_footprint_kg
    dpp.certifications_json = payload.certifications
    dpp.recycling_instructions = payload.recycling_instructions
    dpp.hazardous_substances_json = payload.hazardous_substances
    dpp.reach_compliant = payload.reach_compliant
    dpp.rohs_compliant = payload.rohs_compliant
    dpp.carbon_footprint_method = payload.carbon_footprint_method
    dpp.energy_consumption_kwh = payload.energy_consumption_kwh
    dpp.water_consumption_liters = payload.water_consumption_liters
    dpp.expected_lifetime_years = payload.expected_lifetime_years
    dpp.repair_score = payload.repair_score
    dpp.spare_parts_available = payload.spare_parts_available
    dpp.warranty_duration_months = payload.warranty_duration_months
    dpp.warranty_terms = payload.warranty_terms
    dpp.maintenance_instructions = payload.maintenance_instructions
    dpp.recyclability_percent = payload.recyclability_percent
    dpp.recycled_content_percent = payload.recycled_content_percent
    dpp.disassembly_instructions = payload.disassembly_instructions
    dpp.collection_points_url = payload.collection_points_url
    dpp.reuse_potential = payload.reuse_potential
    dpp.ce_marking = payload.ce_marking
    dpp.conformity_declaration_url = payload.conformity_declaration_url
    dpp.test_reports_urls_json = payload.test_reports_urls
    dpp.hs_code = payload.hs_code
    dpp.cn_code = payload.cn_code
    dpp.product_image_url = payload.product_image_url
    dpp.model_variant = payload.model_variant
    dpp.operator_type = payload.operator_type
    dpp.operator_address = payload.operator_address
    dpp.facility_id = payload.facility_id
    dpp.eori_number = payload.eori_number
    dpp.updated_at = datetime.now(timezone.utc)

    product.product_name = payload.productName
    product.category = payload.category

    db.commit()
    db.refresh(dpp)

    return _serialize_response(product, dpp, brand)


@router.delete("/dpp/{dpp_id}")
def revoke_dpp(dpp_id: int, db: Session = Depends(get_db), api_key: str | None = Header(default=None, alias="X-API-Key")):
    _ensure_tables(db)
    brand = _get_brand_by_key(db, api_key)

    dpp = db.query(DigitalProductPassport).filter(DigitalProductPassport.id == dpp_id).first()
    if not dpp:
        raise HTTPException(status_code=404, detail="DPP not found")

    product = db.query(Product).filter(Product.id == dpp.product_id).first()
    if not product or product.brand_id != brand.id:
        raise HTTPException(status_code=403, detail="Not allowed")

    dpp.is_active = False
    dpp.updated_at = datetime.now(timezone.utc)
    db.commit()

    return {"status": "revoked", "dpp_id": dpp_id}


@router.get("/brands/{brand_id}/products")
def list_brand_products(brand_id: int, db: Session = Depends(get_db), api_key: str | None = Header(default=None, alias="X-API-Key")):
    _ensure_tables(db)
    brand = _get_brand_by_key(db, api_key)
    if brand.id != brand_id:
        raise HTTPException(status_code=403, detail="Not allowed")

    products = db.query(Product).filter(Product.brand_id == brand_id).all()
    return [
        {
            "id": p.id,
            "product_id": p.product_id,
            "product_name": p.product_name,
            "category": p.category,
            "created_at": p.created_at,
        }
        for p in products
    ]


@router.get("/brands/{brand_id}/stats")
def brand_stats(brand_id: int, db: Session = Depends(get_db), api_key: str | None = Header(default=None, alias="X-API-Key")):
    _ensure_tables(db)
    brand = _get_brand_by_key(db, api_key)
    if brand.id != brand_id:
        raise HTTPException(status_code=403, detail="Not allowed")

    products = db.query(Product).filter(Product.brand_id == brand_id).all()
    product_ids = [p.id for p in products]

    total_products = len(products)
    dpps = db.query(DigitalProductPassport).filter(DigitalProductPassport.product_id.in_(product_ids)).all() if product_ids else []
    active_dpps = [d for d in dpps if d.is_active]

    compliant = 0
    for dpp in active_dpps:
        product = next((p for p in products if p.id == dpp.product_id), None)
        check = validate_compliance(
            {
                "productId": product.product_id if product else "",
                "productName": product.product_name if product else "",
                "category": product.category if product else "",
                "materials": dpp.materials_json or [],
                "origin_country": dpp.origin_country,
                "brand_name": brand.name,
                "model_variant": dpp.model_variant,
                "operator_type": dpp.operator_type,
                "carbon_footprint_kg": dpp.carbon_footprint_kg,
                "recycling_instructions": dpp.recycling_instructions,
                "recyclability_percent": dpp.recyclability_percent,
                "certifications": dpp.certifications_json or [],
            }
        )
        if check["is_compliant"]:
            compliant += 1

    compliance_pct = round((compliant / total_products) * 100, 2) if total_products else 0.0

    return {
        "brand_id": brand_id,
        "total_products": total_products,
        "total_scans": 0,
        "compliance_percent": compliance_pct,
    }
