#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
routers/oracle.py - Oracle endpoints for AEGIS Protocol.
"""

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException

from routers.auth import _get_current_user

try:
    from oracle import ChainlinkPriceFeed, OracleConfig
    _oracle_available = True
except ImportError:
    _oracle_available = False

router = APIRouter(tags=["oracle"])


@router.get("/api/v1/oracle/eur-usd")
def oracle_eur_usd(current_user: Dict = Depends(_get_current_user)):
    """Get the current EUR/USD price from the Chainlink price feed."""
    if not _oracle_available:
        raise HTTPException(status_code=503, detail="Oracle service not available")
    feed = ChainlinkPriceFeed()
    data = feed.get_eur_usd_price()
    return {
        "price": data.price,
        "decimals": data.decimals,
        "updated_at": data.updated_at,
        "round_id": data.round_id,
        "is_stale": data.is_stale,
    }
