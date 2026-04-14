from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DPPCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    productId: str
    productName: str
    category: str
    materials: list[str]
    origin_country: str
    carbon_footprint_kg: float | None = None
    certifications: list[str] = Field(default_factory=list)
    recycling_instructions: str | None = None
    brand_name: str


class DPPResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    productId: str
    productName: str
    category: str
    materials: list[str]
    origin_country: str
    carbon_footprint_kg: float | None = None
    certifications: list[str]
    recycling_instructions: str | None = None
    brand_name: str
    dpp_hash: str
    blockchain_tx: str
    ipfs_cid: str
    created_at: datetime
    version: int
    verification_url: str


class DPPVerify(BaseModel):
    model_config = ConfigDict(extra="ignore")

    dpp_id: int
    dpp_hash: str


class DPPVerifyResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    is_valid: bool
    passport_data: dict[str, Any] | None = None


class BrandRegister(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    email: str
    plan: str = "free"


class ProductCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    product_id: str
    product_name: str
    category: str
