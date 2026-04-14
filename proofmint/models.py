from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from db import Base


def _utcnow():
    return datetime.now(timezone.utc)


class Brand(Base):
    __tablename__ = "proofmint_brands"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    api_key = Column(String(128), unique=True, nullable=False, index=True)
    plan = Column(String(20), nullable=False, default="free")
    operator_type = Column(String(50), nullable=False, default="manufacturer")
    address = Column(Text, nullable=True)
    country = Column(String(10), nullable=True)
    phone = Column(String(50), nullable=True)
    website = Column(String(500), nullable=True)
    eori_number = Column(String(50), nullable=True)
    facility_id = Column(String(120), nullable=True)
    products_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=_utcnow)

    products = relationship("Product", back_populates="brand", cascade="all, delete-orphan")


class Product(Base):
    __tablename__ = "proofmint_products"

    id = Column(Integer, primary_key=True, index=True)
    product_id = Column(String(120), unique=True, nullable=False, index=True)
    product_name = Column(String(255), nullable=False)
    category = Column(String(80), nullable=False)
    brand_id = Column(Integer, ForeignKey("proofmint_brands.id"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=_utcnow)

    brand = relationship("Brand", back_populates="products")
    passports = relationship("DigitalProductPassport", back_populates="product", cascade="all, delete-orphan")


class DigitalProductPassport(Base):
    __tablename__ = "proofmint_digital_product_passports"

    id = Column(Integer, primary_key=True, index=True)
    product_id = Column(Integer, ForeignKey("proofmint_products.id"), nullable=False, index=True)
    dpp_hash = Column(String(66), nullable=False, index=True)
    blockchain_tx_hash = Column(String(90), nullable=False)
    ipfs_cid = Column(String(255), nullable=False)
    version = Column(Integer, nullable=False, default=1)
    materials_json = Column(JSON, nullable=False, default=list)
    materials_detailed_json = Column(JSON, nullable=True)
    origin_country = Column(String(80), nullable=False)
    carbon_footprint_kg = Column(Float, nullable=True)
    certifications_json = Column(JSON, nullable=False, default=list)
    recycling_instructions = Column(Text, nullable=True)
    hazardous_substances_json = Column(JSON, nullable=False, default=list)
    reach_compliant = Column(Boolean, nullable=True)
    rohs_compliant = Column(Boolean, nullable=True)
    carbon_footprint_method = Column(String(50), nullable=True)
    energy_consumption_kwh = Column(Float, nullable=True)
    water_consumption_liters = Column(Float, nullable=True)
    expected_lifetime_years = Column(Float, nullable=True)
    repair_score = Column(Float, nullable=True)
    spare_parts_available = Column(Boolean, nullable=True)
    warranty_duration_months = Column(Integer, nullable=True)
    warranty_terms = Column(Text, nullable=True)
    maintenance_instructions = Column(Text, nullable=True)
    recyclability_percent = Column(Float, nullable=True)
    recycled_content_percent = Column(Float, nullable=True)
    disassembly_instructions = Column(Text, nullable=True)
    collection_points_url = Column(String(500), nullable=True)
    reuse_potential = Column(String(20), nullable=True)
    ce_marking = Column(Boolean, nullable=True)
    conformity_declaration_url = Column(String(500), nullable=True)
    test_reports_urls_json = Column(JSON, nullable=False, default=list)
    hs_code = Column(String(20), nullable=True)
    cn_code = Column(String(20), nullable=True)
    product_image_url = Column(String(500), nullable=True)
    model_variant = Column(String(255), nullable=True)
    operator_type = Column(String(50), nullable=True)
    operator_address = Column(Text, nullable=True)
    facility_id = Column(String(120), nullable=True)
    eori_number = Column(String(50), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=_utcnow)
    updated_at = Column(DateTime, nullable=False, default=_utcnow, onupdate=_utcnow)

    product = relationship("Product", back_populates="passports")
