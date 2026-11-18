#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
viewing_keys/disclosure_policy.py - Deterministic engine for graduated disclosure.

It decides WHAT may be disclosed, TO WHOM, with WHICH legal basis and HOW MANY approvals
from the committee holding the threshold keys (see docs/DISCLOSURE_GRADUATA.md).

Levels (each one includes the previous):
  L0 PUBLIC          nullifiers and commitments: what anyone sees on-chain.
  L1 COMPLIANCE      "this pseudonym passed KYC/tier/jurisdiction": already proven by
                     every proof, no key needed.
  L2 TAX             TAX ciphertexts: who pays and how much (no counterparties).
  L3 AML             AML ciphertexts: full detail of the transactions in scope.
  L4 IDENTITY        the KYC issuer reveals the real person behind the pseudonym.

The AI (disclosure_ai) may ONLY propose a `DisclosureRequest` by reading the
authority's document: the final decision is always this function, which is
deterministic, testable and auditable. Decryption then requires the
committee's threshold signatures: no single actor (nor the AI) holds the keys.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple


class Level(IntEnum):
    PUBLIC = 0
    COMPLIANCE = 1
    TAX = 2
    AML = 3
    IDENTITY = 4


class Decision(str):
    APPROVE = "approve"
    DENY = "deny"
    HUMAN_REVIEW = "human_review"


SECONDS_PER_DAY = 86_400

# (requester_type, legal_basis) → maximum level, maximum time window (days), notify the user?
# Notification: for AML/judicial requests the law forbids informing the customer
# (no "tipping off", art. 39 D.lgs. 231/2007): notification is suppressed.
POLICY: Dict[Tuple[str, str], Tuple[Level, int, bool]] = {
    # Tax authority: tax inquiries / CASP reporting (DAC8).
    ("tax_authority", "dpr_600_1973_art32"): (Level.TAX, 366, True),
    ("tax_authority", "dac8_reporting"): (Level.TAX, 366, True),
    # Financial Intelligence Unit / Guardia di Finanza: AML investigations.
    ("uif", "dlgs_231_2007"): (Level.AML, 366, False),
    ("guardia_finanza", "dlgs_231_2007"): (Level.AML, 366, False),
    # Judicial authority: the only one that reaches identity.
    ("judicial_authority", "court_order"): (Level.IDENTITY, 3 * 366, False),
    # The user themselves, voluntarily (e.g. for a bank or an accountant).
    ("user_consent", "user_consent"): (Level.AML, 10 * 366, True),
}

# Approvals required from the committee for each level (t-of-n of the threshold keys).
# "independent" = custodian independent of the operator (e.g. a notary / law firm).
REQUIRED_APPROVALS: Dict[Level, Dict[str, int]] = {
    Level.TAX: {"threshold": 2, "of": 3, "independent": 0},
    Level.AML: {"threshold": 2, "of": 3, "independent": 1},
    Level.IDENTITY: {"threshold": 3, "of": 3, "independent": 1},
}


@dataclass
class DisclosureRequest:
    requester_type: str
    legal_basis: str
    reference: str  # protocol/case number of the request
    authenticated: bool  # verified signature of the authority (PEC / qualified e-signature) upstream
    subject_pseudonyms: List[str]  # owner_pubkey (hex) involved
    requested_level: Level
    window_start: int  # unix seconds
    window_end: int
    justification: str = ""


@dataclass
class TxRecord:
    """Entry of the operator's off-chain register (pseudonym → transactions).

    The regulated operator (CASP/EMI) relays its customers' transactions, so it
    knows which `leaf_index` belongs to which pseudonym WITHOUT decrypting anything: it is the
    record keeping that the AML rules already require. That way the committee decrypts
    ONLY the transactions in scope, never those of other users.
    """

    leaf_index: int  # index of the Disclosure event in ShieldedPool
    owner: str  # pseudonym (owner_pubkey hex)
    timestamp: int


@dataclass
class DisclosureDecision:
    decision: str
    granted_level: Level
    reasons: List[str] = field(default_factory=list)
    window_start: Optional[int] = None
    window_end: Optional[int] = None
    tx_indices: List[int] = field(default_factory=list)
    approvals: Dict[str, int] = field(default_factory=dict)
    notify_user: bool = False


def evaluate(request: DisclosureRequest, index: List[TxRecord], now: int) -> DisclosureDecision:
    """Apply the policy to the request. Pure function: same input, same output."""
    reasons: List[str] = []

    if not request.authenticated:
        return DisclosureDecision(Decision.DENY, Level.PUBLIC, ["request not authenticated"])
    if not request.reference.strip():
        return DisclosureDecision(Decision.DENY, Level.PUBLIC, ["missing case reference"])
    rule = POLICY.get((request.requester_type, request.legal_basis))
    if rule is None:
        return DisclosureDecision(
            Decision.HUMAN_REVIEW, Level.PUBLIC,
            [f"no rule for ({request.requester_type}, {request.legal_basis}): legal review"],
        )
    if not request.subject_pseudonyms:
        return DisclosureDecision(Decision.DENY, Level.PUBLIC, ["no subject: bulk requests not allowed"])
    if request.window_end <= request.window_start or request.window_end > now:
        return DisclosureDecision(Decision.DENY, Level.PUBLIC, ["invalid time window"])

    max_level, max_days, notify = rule
    granted = min(request.requested_level, max_level)
    if granted < request.requested_level:
        reasons.append(f"level reduced from {request.requested_level.name} to {granted.name} by policy")

    start = request.window_start
    if request.window_end - start > max_days * SECONDS_PER_DAY:
        start = request.window_end - max_days * SECONDS_PER_DAY
        reasons.append(f"window limited to {max_days} days")

    if granted <= Level.COMPLIANCE:
        # L0/L1 are already public or provable: nothing to decrypt.
        return DisclosureDecision(Decision.APPROVE, granted, reasons + ["no decryption needed"],
                                  start, request.window_end, [], {}, notify)

    subjects = set(request.subject_pseudonyms)
    txs = sorted(t.leaf_index for t in index if t.owner in subjects and start <= t.timestamp <= request.window_end)
    if not txs:
        reasons.append("no transactions in scope")

    return DisclosureDecision(
        decision=Decision.APPROVE,
        granted_level=granted,
        reasons=reasons,
        window_start=start,
        window_end=request.window_end,
        tx_indices=txs,
        approvals=dict(REQUIRED_APPROVALS[granted]),
        notify_user=notify,
    )
