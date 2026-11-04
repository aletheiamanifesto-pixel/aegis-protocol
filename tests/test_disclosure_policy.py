"""Tests for the deterministic graduated-disclosure engine."""

from viewing_keys.disclosure_policy import (
    Decision,
    DisclosureRequest,
    Level,
    TxRecord,
    evaluate,
)

DAY = 86_400
NOW = 1_800_000_000
ALICE, BOB = "0xa11ce", "0xb0b"
INDEX = [
    TxRecord(0, ALICE, NOW - 400 * DAY),
    TxRecord(2, ALICE, NOW - 30 * DAY),
    TxRecord(4, BOB, NOW - 20 * DAY),
    TxRecord(6, ALICE, NOW - 10 * DAY),
]


def req(**kw):
    base = dict(
        requester_type="tax_authority",
        legal_basis="dpr_600_1973_art32",
        reference="AE-2026-000123",
        authenticated=True,
        subject_pseudonyms=[ALICE],
        requested_level=Level.TAX,
        window_start=NOW - 60 * DAY,
        window_end=NOW - DAY,
    )
    base.update(kw)
    return DisclosureRequest(**base)


def test_tax_request_gets_only_subject_txs_in_window():
    d = evaluate(req(), INDEX, NOW)
    assert d.decision == Decision.APPROVE
    assert d.granted_level == Level.TAX
    assert d.tx_indices == [2, 6]  # not Bob's, not the one outside the window
    assert d.approvals["threshold"] == 2
    assert d.notify_user is True


def test_tax_authority_cannot_escalate_to_aml_or_identity():
    d = evaluate(req(requested_level=Level.IDENTITY), INDEX, NOW)
    assert d.granted_level == Level.TAX
    assert any("reduced" in r for r in d.reasons)


def test_aml_request_has_no_tipping_off_and_needs_independent_approval():
    d = evaluate(req(requester_type="uif", legal_basis="dlgs_231_2007", requested_level=Level.AML), INDEX, NOW)
    assert d.granted_level == Level.AML
    assert d.notify_user is False
    assert d.approvals["independent"] == 1


def test_identity_only_with_court_order_and_unanimity():
    d = evaluate(req(requester_type="judicial_authority", legal_basis="court_order", requested_level=Level.IDENTITY), INDEX, NOW)
    assert d.granted_level == Level.IDENTITY
    assert d.approvals == {"threshold": 3, "of": 3, "independent": 1}


def test_unauthenticated_or_unreferenced_requests_are_denied():
    assert evaluate(req(authenticated=False), INDEX, NOW).decision == Decision.DENY
    assert evaluate(req(reference="  "), INDEX, NOW).decision == Decision.DENY


def test_bulk_requests_without_subject_are_denied():
    assert evaluate(req(subject_pseudonyms=[]), INDEX, NOW).decision == Decision.DENY


def test_unknown_legal_basis_goes_to_human_review():
    d = evaluate(req(legal_basis="email_from_someone"), INDEX, NOW)
    assert d.decision == Decision.HUMAN_REVIEW
    assert d.tx_indices == []


def test_window_is_clipped_to_policy_maximum():
    d = evaluate(req(window_start=NOW - 1000 * DAY), INDEX, NOW)
    assert d.window_start == NOW - DAY - 366 * DAY
    assert 0 not in d.tx_indices or INDEX[0].timestamp >= d.window_start


def test_future_or_inverted_window_denied():
    assert evaluate(req(window_end=NOW + DAY), INDEX, NOW).decision == Decision.DENY
    assert evaluate(req(window_start=NOW - DAY, window_end=NOW - 2 * DAY), INDEX, NOW).decision == Decision.DENY


def test_compliance_level_needs_no_decryption():
    d = evaluate(req(requested_level=Level.COMPLIANCE), INDEX, NOW)
    assert d.decision == Decision.APPROVE and d.tx_indices == [] and d.approvals == {}
