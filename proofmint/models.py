from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from db import Base


class Brand(Base):
    __tablename__ = "proofmint_brands"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    api_key = Column(String(128), unique=True, nullable=False, index=True)
    plan = Column(String(20), nullable=False, default="free")
    products_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    products = relationship("Product", back_populates="brand", cascade="all, delete-orphan")


class Product(Base):
    __tablename__ = "proofmint_products"

    id = Column(Integer, primary_key=True, index=True)
    product_id = Column(String(120), unique=True, nullable=False, index=True)
    product_name = Column(String(255), nullable=False)
    category = Column(String(80), nullable=False)
    brand_id = Column(Integer, ForeignKey("proofmint_brands.id"), nullable=False, index=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

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
    origin_country = Column(String(80), nullable=False)
    carbon_footprint_kg = Column(Float, nullable=True)
    certifications_json = Column(JSON, nullable=False, default=list)
    recycling_instructions = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    product = relationship("Product", back_populates="passports")
