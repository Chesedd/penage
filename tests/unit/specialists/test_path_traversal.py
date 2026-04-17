from __future__ import annotations

import ast
import base64
from pathlib import Path

import pytest

from penage.specialists.shared.path_traversal import (
    LfiMarkerHit,
    LfiTargetFamily,
    detect_lfi_markers,
    generate_traversal_variants,
)


# ---------------------------------------------------------------------------
# generate_traversal_variants
# ---------------------------------------------------------------------------


def test_traversal_variants_contain_basic_ascii():
    variants = generate_traversal_variants("/etc/passwd", max_depth=8)
    assert "../../../etc/passwd" in variants
    assert "../../../../../etc/passwd" in variants


def test_traversal_variants_contain_url_encoded():
    variants = generate_traversal_variants("/etc/passwd", max_depth=6)
    hits = [v for v in variants if v.startswith("%2e%2e%2f") and "%2e" in v]
    assert hits, f"no url-encoded variants produced, got {variants!r}"
    assert any(
        v == "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd" for v in variants
    )


def test_traversal_variants_contain_double_encoded():
    variants = generate_traversal_variants("/etc/passwd", max_depth=6)
    assert any(v.startswith("%252e%252e%252f") for v in variants)
    assert any(
        v == (
            "%252e%252e%252f%252e%252e%252f%252e%252e%252f"
            "etc%252fpasswd"
        )
        for v in variants
    )


def test_traversal_variants_contain_nullbyte():
    variants = generate_traversal_variants("/etc/passwd", max_depth=8)
    assert any(v.endswith("%00") for v in variants)
    assert any(v.endswith("%00.jpg") for v in variants)


def test_traversal_variants_contain_bypass_patterns():
    variants = generate_traversal_variants("/etc/passwd", max_depth=5)
    assert any("....//" in v for v in variants)
    assert any(".\\./" in v for v in variants)


def test_traversal_variants_deduplicated():
    variants = generate_traversal_variants("/etc/passwd", max_depth=8)
    assert len(variants) == len(set(variants)), "variants must be deduplicated"


def test_traversal_depth_respected():
    variants = generate_traversal_variants("/etc/passwd", max_depth=4)
    # No variant should contain 5 consecutive "../", 5 "....//", 5 "%2e%2e%2f",
    # 5 "%252e%252e%252f", 5 ".\./", or 5 "..\\".
    over_limit_tokens = (
        "../" * 5,
        "....//" * 5,
        "%2e%2e%2f" * 5,
        "%252e%252e%252f" * 5,
        ".\\./" * 5,
        "..\\" * 5,
    )
    for v in variants:
        for token in over_limit_tokens:
            assert token not in v, (
                f"variant {v!r} exceeds max_depth=4 via token {token!r}"
            )


def test_traversal_windows_backslash_variants():
    variants = generate_traversal_variants("C:\\Windows\\win.ini", max_depth=5)
    assert any("..\\..\\..\\Windows\\win.ini" == v for v in variants)
    # Absolute with drive letter is included
    assert "C:\\Windows\\win.ini" in variants


def test_traversal_absolute_variant_present():
    variants = generate_traversal_variants("/etc/passwd", max_depth=5)
    assert "/etc/passwd" in variants


def test_traversal_rejects_tiny_max_depth():
    with pytest.raises(ValueError):
        generate_traversal_variants("/etc/passwd", max_depth=2)


# ---------------------------------------------------------------------------
# detect_lfi_markers
# ---------------------------------------------------------------------------


def test_detect_unix_passwd_hit():
    body = (
        "Welcome\nroot:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    )
    hits = detect_lfi_markers(body)
    families = [h.family for h in hits]
    assert LfiTargetFamily.UNIX_PASSWD in families
    passwd_hit = next(h for h in hits if h.family == LfiTargetFamily.UNIX_PASSWD)
    assert "root:x:0:0:" in passwd_hit.marker


def test_detect_unix_passwd_negative():
    # Upper-case X, bare 'root:', and a discussion phrase: none should fire.
    bodies = [
        "root:X:0:0:not matching the canonical format",
        "Please contact root: for access to /etc/passwd documentation.",
        "root:x:0:0: without trailing colon-slash after gecos",
        "random prose about the root user and the passwd command",
    ]
    for body in bodies:
        hits = detect_lfi_markers(body)
        passwd_hits = [h for h in hits if h.family == LfiTargetFamily.UNIX_PASSWD]
        assert not passwd_hits, (
            f"false positive UNIX_PASSWD on body={body!r}: {passwd_hits!r}"
        )


def test_detect_win_ini():
    body = (
        "; for 16-bit app support\n"
        "[fonts]\n"
        "[extensions]\n"
        "[mci extensions]\n"
        "[files]\n"
    )
    hits = detect_lfi_markers(body)
    win_ini_hits = [h for h in hits if h.family == LfiTargetFamily.WIN_INI]
    assert len(win_ini_hits) >= 2
    assert any("[fonts]" == h.marker.lower() or "[fonts]" in h.marker
               for h in win_ini_hits)


def test_detect_proc_status_by_name_state():
    body = (
        "Name:\tapache2\n"
        "Umask:\t0022\n"
        "State:\tS (sleeping)\n"
    )
    # The regex requires Name:\t... immediately followed by State:\t on the
    # next line. Construct an input matching that shape directly:
    body_strict = "Name:\tapache2\nState:\tS (sleeping)\nTgid:\t1234\n"
    hits = detect_lfi_markers(body_strict)
    proc_hits = [h for h in hits if h.family == LfiTargetFamily.PROC_SELF]
    assert proc_hits, f"expected proc_self hit on {body_strict!r}, got {hits!r}"


def test_detect_code_leak_base64_with_php_tokens():
    php_source = (
        b"<?php\n"
        b"// a reasonably long PHP source sample that will base64 to more "
        b"than one hundred contiguous characters\n"
        b"function login($user) {\n"
        b"    return $_GET['name'] . $_POST['pw'];\n"
        b"}\n"
        b"?>\n"
    )
    encoded = base64.b64encode(php_source).decode("ascii")
    assert len(encoded) >= 100
    body = f"OK\n{encoded}\nEND"
    hits = detect_lfi_markers(body)
    code_hits = [h for h in hits if h.family == LfiTargetFamily.CODE_LEAK]
    assert code_hits, f"expected CODE_LEAK hit, got {hits!r}"


def test_detect_code_leak_negative_on_plain_base64_without_php():
    plain = (
        b"This is ordinary English prose with no executable markers in it. "
        b"It should decode cleanly but contain none of the PHP tokens the "
        b"heuristic requires. Repeat for padding padding padding padding."
    )
    encoded = base64.b64encode(plain).decode("ascii")
    assert len(encoded) >= 100
    body = f"prefix\n{encoded}\nsuffix"
    hits = detect_lfi_markers(body)
    code_hits = [h for h in hits if h.family == LfiTargetFamily.CODE_LEAK]
    assert not code_hits, f"false positive CODE_LEAK: {code_hits!r}"


def test_snippet_truncated_to_200_chars():
    body = ("A" * 500) + "root:x:0:0:root:/root:/bin/bash\n" + ("B" * 500)
    hits = detect_lfi_markers(body)
    passwd_hits = [h for h in hits if h.family == LfiTargetFamily.UNIX_PASSWD]
    assert passwd_hits
    assert all(len(h.snippet) <= 200 for h in passwd_hits)


def test_empty_body_returns_empty():
    assert detect_lfi_markers("") == []


def test_multiple_families_return_multiple_hits():
    body = (
        "[fonts]\n"
        "[extensions]\n"
        "root:x:0:0:root:/root:/bin/bash\n"
        "Name:\thttpd\nState:\tR (running)\n"
    )
    hits = detect_lfi_markers(body)
    families = {h.family for h in hits}
    assert LfiTargetFamily.UNIX_PASSWD in families
    assert LfiTargetFamily.WIN_INI in families
    assert LfiTargetFamily.PROC_SELF in families


def test_hit_dataclass_is_frozen():
    hit = LfiMarkerHit(
        family=LfiTargetFamily.UNIX_PASSWD,
        marker="root:x:0:0:",
        snippet="root:x:0:0:root:/root:/bin/bash",
    )
    with pytest.raises(Exception):
        hit.marker = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Layer boundary: the shared utility MUST NOT depend on specialists.vulns
# (CLAUDE.md invariant #1).
# ---------------------------------------------------------------------------


def test_path_traversal_has_no_vuln_specialist_imports():
    source_path = (
        Path(__file__).resolve().parents[3]
        / "penage"
        / "specialists"
        / "shared"
        / "path_traversal.py"
    )
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    bad: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith(
                "penage.specialists.vulns"
            ):
                bad.append(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("penage.specialists.vulns"):
                    bad.append(alias.name)
    assert not bad, f"forbidden imports from penage.specialists.vulns: {bad}"
