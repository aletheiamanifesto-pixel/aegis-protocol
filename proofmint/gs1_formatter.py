from datetime import datetime, timezone
from io import BytesIO

import qrcode


def format_as_epcis(dpp_data: dict) -> dict:
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
                    "proofmint:dpp": dpp_data,
                }
            ]
        },
    }


def generate_qr_code(verification_url: str) -> bytes:
    image = qrcode.make(verification_url)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()
