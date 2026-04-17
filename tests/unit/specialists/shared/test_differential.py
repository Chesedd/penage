"""Tests for penage.specialists.shared.differential."""

from __future__ import annotations

from penage.specialists.shared.differential import (
    DifferentialSignal,
    ExtractedMarkers,
    ResponseComparison,
    compare_responses,
    extract_markers,
)


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------


def test_extract_emails_basic() -> None:
    body = "Contact alice@example.org and bob@test.io for details."
    markers = extract_markers(body)
    assert "alice@example.org" in markers.emails
    assert "bob@test.io" in markers.emails


def test_extract_emails_denylist_filters_generic() -> None:
    body = (
        "admin@example.com, user@example.com, noreply@mail.site,"
        " alice@real-company.org"
    )
    markers = extract_markers(body)
    assert markers.emails == ["alice@real-company.org"]


def test_extract_order_id_from_label() -> None:
    body = "Order ID: ORD-1234-5678 was shipped today."
    markers = extract_markers(body)
    assert "ORD-1234-5678" in markers.order_ids


def test_extract_order_id_multiple_formats() -> None:
    body = "invoice_number=ABC-99XY and reference #ORD-998877"
    markers = extract_markers(body)
    assert "ABC-99XY" in markers.order_ids
    assert "998877" in markers.order_ids


def test_extract_username_quoted_from_html() -> None:
    body = '<span class="username">alice42</span>'
    markers = extract_markers(body)
    assert "alice42" in markers.usernames_quoted


def test_extract_username_welcome_text() -> None:
    body = "<h1>Welcome, carol!</h1>"
    markers = extract_markers(body)
    assert "carol" in markers.usernames_quoted


def test_extract_csrf_token() -> None:
    body = 'csrf_token="abcdef1234567890ABCDEF987654"'
    markers = extract_markers(body)
    assert "abcdef1234567890ABCDEF987654" in markers.csrf_tokens


def test_extract_api_key() -> None:
    body = 'api_key="sk_live_abcdef1234567890XYZ"'
    markers = extract_markers(body)
    assert "sk_live_abcdef1234567890XYZ" in markers.api_keys


def test_extract_uuid_canonical() -> None:
    body = "account_id: 123e4567-e89b-12d3-a456-426614174000"
    markers = extract_markers(body)
    assert "123e4567-e89b-12d3-a456-426614174000" in markers.uuids


def test_extract_uuid_zeros_filtered() -> None:
    body = (
        "placeholder 00000000-0000-0000-0000-000000000000 and"
        " real 123e4567-e89b-12d3-a456-426614174000"
    )
    markers = extract_markers(body)
    assert "00000000-0000-0000-0000-000000000000" not in markers.uuids
    assert "123e4567-e89b-12d3-a456-426614174000" in markers.uuids


def test_extract_short_tokens_dropped() -> None:
    # Body has no marker-generating content at all; extraction must not
    # invent <3-char tokens.
    body = "hello world, nothing interesting here: a b c."
    markers = extract_markers(body)
    for tok in markers.all_tokens():
        assert len(tok) >= 3


def test_extract_deduplication_case_insensitive() -> None:
    body = "Welcome, Alice! The user alice is logged in."
    markers = extract_markers(body)
    # Two case-different mentions of Alice/alice — deduped (first wins).
    lowered = [u.lower() for u in markers.usernames_quoted]
    assert lowered.count("alice") == 1


def test_extract_caps_at_max_per_kind() -> None:
    emails = " ".join(f"user{i}@domain{i}.org" for i in range(30))
    markers = extract_markers(emails, max_per_kind=16)
    assert len(markers.emails) == 16


def test_extract_empty_body_returns_empty() -> None:
    markers = extract_markers("")
    assert markers.is_empty()
    assert markers == ExtractedMarkers()


def test_markers_all_tokens_combines_all_categories() -> None:
    body = (
        'username="dave" email: dave@shop.io Order ID: ORD-ABCDE-7777'
        ' csrf_token="XxYy1122AaBb3344CcDd5566"'
        ' id=123e4567-e89b-12d3-a456-426614174000'
    )
    markers = extract_markers(body)
    tokens = markers.all_tokens()
    assert "dave" in tokens
    assert "dave@shop.io" in tokens
    assert "ORD-ABCDE-7777" in tokens
    assert "XxYy1122AaBb3344CcDd5566" in tokens
    assert "123e4567-e89b-12d3-a456-426614174000" in tokens


# ---------------------------------------------------------------------------
# Comparison — strong signals
# ---------------------------------------------------------------------------


def test_identical_body_both_200_leak() -> None:
    body = "Account holder dashboard. " * 10  # well over 32 chars
    result = compare_responses(
        a_body=body, a_status=200, b_body=body, b_status=200
    )
    assert result.signal is DifferentialSignal.LEAK_IDENTICAL_BODY
    assert result.a_body_hash == result.b_body_hash
    assert result.a_body_hash != ""


def test_identical_body_too_short_downgraded_to_no_signal() -> None:
    body = "tiny"
    result = compare_responses(
        a_body=body, a_status=200, b_body=body, b_status=200
    )
    assert result.signal is DifferentialSignal.NO_SIGNAL
    assert any("too short" in n for n in result.notes)


def test_shared_markers_emails() -> None:
    a_body = (
        "<html><body><p>Your profile</p>"
        "<p>Email: alice@real-domain.org</p></body></html>"
    )
    b_body = (
        "<html><body><p>Viewer profile</p>"
        "<p>Shared alice@real-domain.org info</p></body></html>"
    )
    result = compare_responses(
        a_body=a_body, a_status=200, b_body=b_body, b_status=200
    )
    assert result.signal is DifferentialSignal.LEAK_SHARED_MARKERS
    assert "alice@real-domain.org" in result.shared_markers


def test_shared_markers_order_id() -> None:
    a_body = "<div>Order ID: ORD-ZZZZ-4242 total $50</div>"
    b_body = "<div>Viewer sees Order ID: ORD-ZZZZ-4242 in logs</div>"
    result = compare_responses(
        a_body=a_body, a_status=200, b_body=b_body, b_status=200
    )
    assert result.signal is DifferentialSignal.LEAK_SHARED_MARKERS
    assert "ORD-ZZZZ-4242" in result.shared_markers


def test_shared_markers_multiple_kinds() -> None:
    a_body = (
        '<span class="username">frank</span>'
        " Contact: frank@corp-site.net"
    )
    b_body = (
        '<div>Profile: Welcome, frank! Email frank@corp-site.net</div>'
    )
    result = compare_responses(
        a_body=a_body, a_status=200, b_body=b_body, b_status=200
    )
    assert result.signal is DifferentialSignal.LEAK_SHARED_MARKERS
    assert "frank" in result.shared_markers
    assert "frank@corp-site.net" in result.shared_markers


def test_no_shared_markers_but_both_200_no_signal() -> None:
    a_body = "<p>alice@real-alpha.org</p>" + "x" * 200
    b_body = "<p>bob@real-beta.org</p>" + "y" * 200
    result = compare_responses(
        a_body=a_body, a_status=200, b_body=b_body, b_status=200
    )
    assert result.signal is DifferentialSignal.NO_SIGNAL


# ---------------------------------------------------------------------------
# Comparison — weak / none
# ---------------------------------------------------------------------------


def test_both_denied_403_returns_both_denied() -> None:
    result = compare_responses(
        a_body="forbidden", a_status=403, b_body="forbidden", b_status=403
    )
    assert result.signal is DifferentialSignal.BOTH_DENIED


def test_both_denied_404_returns_both_denied() -> None:
    result = compare_responses(
        a_body="missing", a_status=404, b_body="missing", b_status=404
    )
    assert result.signal is DifferentialSignal.BOTH_DENIED


def test_status_differential_length_ratio_low() -> None:
    a_body = "X" * 1000
    b_body = "Y" * 50
    result = compare_responses(
        a_body=a_body, a_status=200, b_body=b_body, b_status=200
    )
    assert result.signal is DifferentialSignal.STATUS_DIFFERENTIAL
    assert any("ratio" in n for n in result.notes)


def test_status_differential_a_200_b_500() -> None:
    a_body = "owner dashboard with data" * 10
    b_body = "Internal server error"
    result = compare_responses(
        a_body=a_body, a_status=200, b_body=b_body, b_status=500
    )
    assert result.signal is DifferentialSignal.STATUS_DIFFERENTIAL
    assert any("5xx" in n for n in result.notes)


def test_status_differential_not_triggered_when_lengths_similar() -> None:
    a_body = "A" * 500
    b_body = "B" * 490
    result = compare_responses(
        a_body=a_body, a_status=200, b_body=b_body, b_status=200
    )
    assert result.signal is DifferentialSignal.NO_SIGNAL


def test_no_signal_a_500_b_200() -> None:
    # Owner failed, other viewer saw 200 — not an IDOR signal.
    result = compare_responses(
        a_body="error", a_status=500, b_body="content" * 50, b_status=200
    )
    assert result.signal is DifferentialSignal.NO_SIGNAL


def test_none_status_handled_gracefully() -> None:
    result = compare_responses(
        a_body="body", a_status=None, b_body="body", b_status=200
    )
    assert result.signal is DifferentialSignal.NO_SIGNAL


# ---------------------------------------------------------------------------
# Edge
# ---------------------------------------------------------------------------


def test_empty_both_bodies_no_signal() -> None:
    result = compare_responses(
        a_body="", a_status=200, b_body="", b_status=200
    )
    assert result.signal is DifferentialSignal.NO_SIGNAL


def test_hash_stable_across_calls() -> None:
    body = "stable body content " * 10
    r1 = compare_responses(a_body=body, a_status=200, b_body=body, b_status=200)
    r2 = compare_responses(a_body=body, a_status=200, b_body=body, b_status=200)
    assert r1.a_body_hash == r2.a_body_hash
    assert r1.b_body_hash == r2.b_body_hash
    assert r1.a_body_hash == r1.b_body_hash


def test_notes_populated_on_downgrade() -> None:
    # Short identical body should leave a breadcrumb in notes.
    result = compare_responses(
        a_body="x" * 10, a_status=200, b_body="x" * 10, b_status=200
    )
    assert result.signal is DifferentialSignal.NO_SIGNAL
    assert result.notes  # non-empty
    assert any("downgraded" in n for n in result.notes)


def test_result_returns_response_comparison_dataclass() -> None:
    result = compare_responses(
        a_body="x", a_status=200, b_body="x", b_status=200
    )
    assert isinstance(result, ResponseComparison)
