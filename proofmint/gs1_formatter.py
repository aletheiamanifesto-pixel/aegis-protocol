from datetime import datetime, timezone
from io import BytesIO

import qrcode


def format_as_epcis(dpp_data: dict) -> dict:
    identity = {
        "productId": dpp_data.get("productId"),
        "productName": dpp_data.get("productName"),
        "category": dpp_data.get("category"),
        "model_variant": dpp_data.get("model_variant"),
        "product_image_url": dpp_data.get("product_image_url"),
        "hs_code": dpp_data.get("hs_code"),
        "cn_code": dpp_data.get("cn_code"),
    }
    operator = {
        "brand_name": dpp_data.get("brand_name"),
        "operator_type": dpp_data.get("operator_type"),
        "operator_address": dpp_data.get("operator_address"),
        "facility_id": dpp_data.get("facility_id"),
        "eori_number": dpp_data.get("eori_number"),
    }
    materials = {
        "materials": dpp_data.get("materials", []),
        "materials_detailed": dpp_data.get("materials_detailed", []),
        "hazardous_substances": dpp_data.get("hazardous_substances", []),
        "reach_compliant": dpp_data.get("reach_compliant"),
        "rohs_compliant": dpp_data.get("rohs_compliant"),
    }
    environmental = {
        "origin_country": dpp_data.get("origin_country"),
        "carbon_footprint_kg": dpp_data.get("carbon_footprint_kg"),
        "carbon_footprint_method": dpp_data.get("carbon_footprint_method"),
        "energy_consumption_kwh": dpp_data.get("energy_consumption_kwh"),
        "water_consumption_liters": dpp_data.get("water_consumption_liters"),
    }
    durability = {
        "expected_lifetime_years": dpp_data.get("expected_lifetime_years"),
        "repair_score": dpp_data.get("repair_score"),
        "spare_parts_available": dpp_data.get("spare_parts_available"),
        "warranty_duration_months": dpp_data.get("warranty_duration_months"),
        "warranty_terms": dpp_data.get("warranty_terms"),
        "maintenance_instructions": dpp_data.get("maintenance_instructions"),
    }
    circularity = {
        "recycling_instructions": dpp_data.get("recycling_instructions"),
        "recyclability_percent": dpp_data.get("recyclability_percent"),
        "recycled_content_percent": dpp_data.get("recycled_content_percent"),
        "disassembly_instructions": dpp_data.get("disassembly_instructions"),
        "collection_points_url": dpp_data.get("collection_points_url"),
        "reuse_potential": dpp_data.get("reuse_potential"),
    }
    conformity = {
        "certifications": dpp_data.get("certifications", []),
        "ce_marking": dpp_data.get("ce_marking"),
        "conformity_declaration_url": dpp_data.get("conformity_declaration_url"),
        "test_reports_urls": dpp_data.get("test_reports_urls", []),
    }

    return {
        "@context": [
            "https://ref.gs1.org/standards/epcis/2.0.0/epcis-context.jsonld",
            {"proofmint": "https://proofmint.io/ns#"},
        ],
        "type": "EPCISDocument",
        "schemaVersion": "2.0",
        "creationDate": datetime.now(timezone.utc).isoformat(),
        "epcisBody": {
            "eventList": [
                {
                    "type": "ObjectEvent",
                    "action": "OBSERVE",
                    "bizStep": "urn:epcglobal:cbv:bizstep:commissioning",
                    "disposition": "urn:epcglobal:cbv:disp:active",
                    "readPoint": {"id": dpp_data.get("facility_id") or dpp_data.get("origin_country")},
                    "bizLocation": {"id": dpp_data.get("operator_address") or dpp_data.get("origin_country")},
                    "proofmint:dpp": {
                        "identity": identity,
                        "operator": operator,
                        "materials": materials,
                        "environmental": environmental,
                        "durability": durability,
                        "circularity": circularity,
                        "conformity": conformity,
                    },
                }
            ]
        },
    }


def generate_qr_code(verification_url: str) -> bytes:
    image = qrcode.make(verification_url)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()
