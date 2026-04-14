import json
import os

import httpx


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")


def auto_fill_dpp(document_text: str) -> dict:
    if not document_text.strip() or not OPENAI_API_KEY:
        return {}

    prompt = (
        "Extract Digital Product Passport fields as JSON with keys: "
        "productName, category, materials (array), origin_country, "
        "carbon_footprint_kg, certifications (array), recycling_instructions, brand_name. "
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
        return {}


def estimate_carbon_footprint(materials: list, origin: str, weight_kg: float) -> float:
    material_factors = {
        "cotton": 5.0,
        "polyester": 9.5,
        "leather": 17.0,
        "glass": 1.5,
        "aluminum": 8.0,
        "plastic": 6.0,
    }
    avg_factor = 4.0
    if materials:
        factors = [material_factors.get(str(m).lower(), avg_factor) for m in materials]
        avg_factor = sum(factors) / len(factors)

    transport_multiplier = 1.0 if origin.upper() in {"IT", "EU", "ITALY"} else 1.2
    footprint = max(weight_kg, 0.0) * avg_factor * transport_multiplier
    return round(footprint, 3)


def validate_compliance(dpp_data: dict) -> dict:
    required_fields = [
        "productId",
        "productName",
        "category",
        "materials",
        "origin_country",
        "brand_name",
    ]

    missing_fields = []
    for field in required_fields:
        value = dpp_data.get(field)
        if value is None or value == "" or value == []:
            missing_fields.append(field)

    score = int(((len(required_fields) - len(missing_fields)) / len(required_fields)) * 100)

    return {
        "compliance_score": score,
        "missing_fields": missing_fields,
        "is_compliant": len(missing_fields) == 0,
    }
