from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class MaterialDetail(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: str
    weight_percent: float | None = None
    recycled_content_percent: float | None = None
    origin_country: str | None = None


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
    materials_detailed: list[MaterialDetail] = Field(default_factory=list)
    operator_type: str | None = None
    operator_address: str | None = None
    facility_id: str | None = None
    eori_number: str | None = None
    hazardous_substances: list[str] = Field(default_factory=list)
    reach_compliant: bool | None = None
    rohs_compliant: bool | None = None
    carbon_footprint_method: str | None = None
    energy_consumption_kwh: float | None = None
    water_consumption_liters: float | None = None
    expected_lifetime_years: float | None = None
    repair_score: float | None = None
    spare_parts_available: bool | None = None
    warranty_duration_months: int | None = None
    warranty_terms: str | None = None
    maintenance_instructions: str | None = None
    recyclability_percent: float | None = None
    recycled_content_percent: float | None = None
    disassembly_instructions: str | None = None
    collection_points_url: str | None = None
    reuse_potential: str | None = None
    ce_marking: bool | None = None
    conformity_declaration_url: str | None = None
    test_reports_urls: list[str] = Field(default_factory=list)
    hs_code: str | None = None
    cn_code: str | None = None
    product_image_url: str | None = None
    model_variant: str | None = None


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
    materials_detailed: list[MaterialDetail] = Field(default_factory=list)
    operator_type: str | None = None
    operator_address: str | None = None
    facility_id: str | None = None
    eori_number: str | None = None
    hazardous_substances: list[str] = Field(default_factory=list)
    reach_compliant: bool | None = None
    rohs_compliant: bool | None = None
    carbon_footprint_method: str | None = None
    energy_consumption_kwh: float | None = None
    water_consumption_liters: float | None = None
    expected_lifetime_years: float | None = None
    repair_score: float | None = None
    spare_parts_available: bool | None = None
    warranty_duration_months: int | None = None
    warranty_terms: str | None = None
    maintenance_instructions: str | None = None
    recyclability_percent: float | None = None
    recycled_content_percent: float | None = None
    disassembly_instructions: str | None = None
    collection_points_url: str | None = None
    reuse_potential: str | None = None
    ce_marking: bool | None = None
    conformity_declaration_url: str | None = None
    test_reports_urls: list[str] = Field(default_factory=list)
    hs_code: str | None = None
    cn_code: str | None = None
    product_image_url: str | None = None
    model_variant: str | None = None
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
    operator_type: str = "manufacturer"
    address: str | None = None
    country: str | None = None
    phone: str | None = None
    website: str | None = None
    eori_number: str | None = None
    facility_id: str | None = None


class ProductCreate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    product_id: str
    product_name: str
    category: str
