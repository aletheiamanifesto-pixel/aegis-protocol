import json
import logging
import os

import httpx


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
logger = logging.getLogger(__name__)
REQUIRED_FIELDS_WEIGHT_PERCENT = 85
RECOMMENDED_FIELDS_WEIGHT_PERCENT = 15

ESPR_REQUIRED_FIELDS = {
    "identity": ["productId", "productName", "category", "model_variant"],
    "operator": ["brand_name", "operator_type"],
    "materials": ["materials"],
    "environmental": ["carbon_footprint_kg"],
    "circularity": ["recycling_instructions", "recyclability_percent"],
    "conformity": ["certifications"],
    "origin": ["origin_country"],
}

ESPR_RECOMMENDED_FIELDS = {
    "identity": ["product_image_url", "hs_code"],
    "operator": ["operator_address", "facility_id"],
    "materials": ["materials_detailed", "hazardous_substances"],
    "environmental": ["carbon_footprint_method", "energy_consumption_kwh"],
    "durability": ["expected_lifetime_years", "warranty_duration_months", "repair_score"],
    "circularity": ["recycled_content_percent", "disassembly_instructions", "reuse_potential"],
    "conformity": ["ce_marking", "reach_compliant", "conformity_declaration_url"],
}


def auto_fill_dpp(document_text: str) -> dict:
    if not document_text.strip() or not OPENAI_API_KEY:
        return {}

    prompt = (
        "Extract Digital Product Passport fields as JSON with keys: "
        "productId, productName, category, materials (array), materials_detailed (array of objects with name, weight_percent, recycled_content_percent, origin_country), "
        "origin_country, brand_name, model_variant, product_image_url, operator_type, operator_address, facility_id, eori_number, "
        "hazardous_substances (array), reach_compliant, rohs_compliant, carbon_footprint_kg, carbon_footprint_method, energy_consumption_kwh, "
        "water_consumption_liters, expected_lifetime_years, repair_score, spare_parts_available, warranty_duration_months, warranty_terms, maintenance_instructions, "
        "recyclability_percent, recycled_content_percent, disassembly_instructions, collection_points_url, reuse_potential, "
        "certifications (array), ce_marking, conformity_declaration_url, test_reports_urls (array), hs_code, cn_code, recycling_instructions. "
        "If unknown, use null or empty arrays. Return JSON only."
    )

    try:
        resp = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
            json={
                "model": OPENAI_MODEL,
                "messages": [
                    {"role": "system", "content": "You return strict JSON only."},
                    {"role": "user", "content": f"{prompt}\n\nDocument:\n{document_text}"},
                ],
                "temperature": 0,
            },
            timeout=20,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"]
        start = content.find("{")
        end = content.rfind("}")
        if start == -1 or end == -1:
            return {}
        return json.loads(content[start:end + 1])
    except Exception:
        logger.exception("OpenAI auto-fill request failed")
        return {}


def estimate_carbon_footprint(materials: list, origin: str, weight_kg: float, materials_detailed: list | None = None) -> float:
    material_factors = {
        "cotton": 5.0,
        "polyester": 9.5,
        "leather": 17.0,
        "glass": 1.5,
        "aluminum": 8.0,
        "plastic": 6.0,
    }
    avg_factor = 4.0
    detailed = materials_detailed or []
    weighted_sum = 0.0
    weight_total = 0.0
    for material in detailed:
        if isinstance(material, dict):
            name = str(material.get("name", "")).lower()
            weight_percent = material.get("weight_percent")
        else:
            name = str(getattr(material, "name", "")).lower()
            weight_percent = getattr(material, "weight_percent", None)
        factor = material_factors.get(name, avg_factor)
        if isinstance(weight_percent, (int, float)) and weight_percent > 0:
            weighted_sum += factor * float(weight_percent)
            weight_total += float(weight_percent)

    if weight_total > 0:
        avg_factor = weighted_sum / weight_total
    elif materials:
        factors = [material_factors.get(str(m).lower(), avg_factor) for m in materials]
        avg_factor = sum(factors) / len(factors)

    transport_multiplier = 1.0 if origin.upper() in {"IT", "EU", "ITALY"} else 1.2
    footprint = max(weight_kg, 0.0) * avg_factor * transport_multiplier
    return round(footprint, 3)


def validate_compliance(dpp_data: dict) -> dict:
    def _is_missing(value) -> bool:
        return value is None or value == "" or value == []

    def _clamp_score(raw_score: float) -> int:
        return int(round(max(0.0, min(100.0, raw_score))))

    def _weighted_score(req_present: int, req_total: int, rec_present: int, rec_total: int) -> int:
        required_weight = REQUIRED_FIELDS_WEIGHT_PERCENT if req_total else 0
        recommended_weight = RECOMMENDED_FIELDS_WEIGHT_PERCENT if rec_total else 0
        total_weight = required_weight + recommended_weight
        if total_weight == 0:
            return 0
        weighted = 0.0
        if req_total:
            weighted += (req_present / req_total) * required_weight
        if rec_total:
            weighted += (rec_present / rec_total) * recommended_weight
        return _clamp_score((weighted / total_weight) * 100)

    required_missing = []
    recommended_missing = []
    categories: dict[str, dict] = {}

    all_categories = list(dict.fromkeys(list(ESPR_REQUIRED_FIELDS.keys()) + list(ESPR_RECOMMENDED_FIELDS.keys())))
    for category in all_categories:
        req_fields = ESPR_REQUIRED_FIELDS.get(category, [])
        rec_fields = ESPR_RECOMMENDED_FIELDS.get(category, [])

        category_missing = []
        for field in req_fields:
            if _is_missing(dpp_data.get(field)):
                required_missing.append(field)
                category_missing.append(field)
        for field in rec_fields:
            if _is_missing(dpp_data.get(field)):
                recommended_missing.append(field)
                category_missing.append(field)

        present_req = len(req_fields) - sum(1 for f in req_fields if _is_missing(dpp_data.get(f)))
        present_rec = len(rec_fields) - sum(1 for f in rec_fields if _is_missing(dpp_data.get(f)))
        cat_score = _weighted_score(present_req, len(req_fields), present_rec, len(rec_fields))
        categories[category] = {"score": cat_score, "missing": category_missing}

    total_required = sum(len(v) for v in ESPR_REQUIRED_FIELDS.values())
    total_recommended = sum(len(v) for v in ESPR_RECOMMENDED_FIELDS.values())
    present_required = total_required - len(required_missing)
    present_recommended = total_recommended - len(recommended_missing)

    score = _weighted_score(present_required, total_required, present_recommended, total_recommended)

    if score < 50:
        compliance_level = "critical"
    elif score < 70:
        compliance_level = "low"
    elif score < 85:
        compliance_level = "medium"
    elif score < 95:
        compliance_level = "high"
    else:
        compliance_level = "full"

    return {
        "compliance_score": score,
        "compliance_level": compliance_level,
        "missing_fields": required_missing,
        "required_missing": required_missing,
        "recommended_missing": recommended_missing,
        "categories": categories,
        "is_compliant": len(required_missing) == 0,
    }
