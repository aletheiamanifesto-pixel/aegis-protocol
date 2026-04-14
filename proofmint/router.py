import hashlib
import json
import secrets
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import desc
from sqlalchemy.orm import Session

from db import Base, get_db
from proofmint.ai_engine import validate_compliance
from proofmint.blockchain_service import (
    create_passport_onchain,
    update_passport_onchain,
    verify_passport_onchain,
)
from proofmint.models import Brand, DigitalProductPassport, Product
from proofmint.schemas import (
    BrandRegister,
    DPPCreate,
    DPPResponse,
    ProductCreate,
)
from proofmint.storage_service import get_from_ipfs, upload_to_ipfs

router = APIRouter(prefix="/proofmint", tags=["proofmint"])

_tables_ready = False


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
        dpp_hash=dpp.dpp_hash,
        blockchain_tx=dpp.blockchain_tx_hash,
        ipfs_cid=dpp.ipfs_cid,
        created_at=dpp.created_at,
        version=dpp.version,
        verification_url=f"/proofmint/verify/{product.product_id}",
    )


@router.post("/brands/register", status_code=201)
def register_brand(payload: BrandRegister, db: Session = Depends(get_db)):
    _ensure_tables(db)

    existing = db.query(Brand).filter(Brand.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Brand email already registered")

    api_key = secrets.token_urlsafe(32)
    brand = Brand(name=payload.name, email=payload.email, api_key=api_key, plan=payload.plan)
    db.add(brand)
    db.commit()
    db.refresh(brand)

    return {
        "brand_id": brand.id,
        "name": brand.name,
        "email": brand.email,
        "plan": brand.plan,
        "api_key": brand.api_key,
    }


@router.post("/products", status_code=201)
def create_product(payload: ProductCreate, db: Session = Depends(get_db), x_api_key: str | None = Header(default=None)):
    _ensure_tables(db)
    brand = _get_brand_by_key(db, x_api_key)

    existing = db.query(Product).filter(Product.product_id == payload.product_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Product already exists")

    product = Product(
        product_id=payload.product_id,
        product_name=payload.product_name,
        category=payload.category,
        brand_id=brand.id,
    )
    brand.products_count += 1
    db.add(product)
    db.commit()
    db.refresh(product)

    return {
        "id": product.id,
        "product_id": product.product_id,
        "product_name": product.product_name,
        "category": product.category,
        "brand_id": product.brand_id,
    }


@router.post("/dpp/create", response_model=DPPResponse, status_code=201)
def create_dpp(payload: DPPCreate, db: Session = Depends(get_db), x_api_key: str | None = Header(default=None)):
    _ensure_tables(db)
    brand = _get_brand_by_key(db, x_api_key)

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
        origin_country=payload.origin_country,
        carbon_footprint_kg=payload.carbon_footprint_kg,
        certifications_json=payload.certifications,
        recycling_instructions=payload.recycling_instructions,
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
            "dpp_hash": dpp.dpp_hash,
            "version": dpp.version,
            "ipfs_cid": dpp.ipfs_cid,
        },
    }


@router.put("/dpp/{dpp_id}", response_model=DPPResponse)
def update_dpp(dpp_id: int, payload: DPPCreate, db: Session = Depends(get_db), x_api_key: str | None = Header(default=None)):
    _ensure_tables(db)
    brand = _get_brand_by_key(db, x_api_key)

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
    dpp.origin_country = payload.origin_country
    dpp.carbon_footprint_kg = payload.carbon_footprint_kg
    dpp.certifications_json = payload.certifications
    dpp.recycling_instructions = payload.recycling_instructions
    dpp.updated_at = datetime.utcnow()

    product.product_name = payload.productName
    product.category = payload.category

    db.commit()
    db.refresh(dpp)

    return _serialize_response(product, dpp, brand)


@router.delete("/dpp/{dpp_id}")
def revoke_dpp(dpp_id: int, db: Session = Depends(get_db), x_api_key: str | None = Header(default=None)):
    _ensure_tables(db)
    brand = _get_brand_by_key(db, x_api_key)

    dpp = db.query(DigitalProductPassport).filter(DigitalProductPassport.id == dpp_id).first()
    if not dpp:
        raise HTTPException(status_code=404, detail="DPP not found")

    product = db.query(Product).filter(Product.id == dpp.product_id).first()
    if not product or product.brand_id != brand.id:
        raise HTTPException(status_code=403, detail="Not allowed")

    dpp.is_active = False
    dpp.updated_at = datetime.utcnow()
    db.commit()

    return {"status": "revoked", "dpp_id": dpp_id}


@router.get("/brands/{brand_id}/products")
def list_brand_products(brand_id: int, db: Session = Depends(get_db), x_api_key: str | None = Header(default=None)):
    _ensure_tables(db)
    brand = _get_brand_by_key(db, x_api_key)
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
def brand_stats(brand_id: int, db: Session = Depends(get_db), x_api_key: str | None = Header(default=None)):
    _ensure_tables(db)
    brand = _get_brand_by_key(db, x_api_key)
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
