from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.state import State
from penage.validation.base import ValidationResult


_FLAG_RE = re.compile(r"FLAG\{[^}\n]{1,300}\}", re.I)

_HTTP_SUCCESS_CODES = {200, 201, 202, 204, 301, 302, 303, 307, 308}
_HTTP_REDIRECT_CODES = {301, 302, 303, 307, 308}

_STRONG_ACCESS_MARKERS = (
    "dashboard",
    "logout",
    "welcome,",
    "welcome back",
    "admin panel",
    "order id",
    "receipt",
    "api key",
    "csrf token",
)

_STRUCTURED_VALUE_MARKERS = (
    "token",
    "csrf",
    "secret",
    "apikey",
    "api key",
)

_NEGATIVE_MARKERS = (
    "not found",
    "404",
    "method not allowed",
    "forbidden",
    "unauthorized",
    "traceback",
    "exception",
)

_STATIC_EXT = (
    ".css",
    ".js",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
)

_STATIC_CONTENT_TYPES = (
    "text/css",
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
    "image/",
    "font/",
    "application/font",
)


def _flag_match(text: str) -> Optional[str]:
    if not text:
        return None
    m = _FLAG_RE.search(text)
    return m.group(0) if m else None


def _lower(s: object) -> str:
    return str(s or "").lower()


def _path_of_url(url: str) -> str:
    try:
        return (urlparse(url).path or "").lower()
    except Exception:
        return str(url or "").lower()


def _looks_like_static_asset_url(url: str) -> bool:
    path = _path_of_url(url)
    if not path:
        return False
    if path.startswith("/static/"):
        return True
    return path.endswith(_STATIC_EXT)


def _is_static_content_type(content_type: str) -> bool:
    low = _lower(content_type)
    return any(low.startswith(prefix) for prefix in _STATIC_CONTENT_TYPES)


def _looks_like_htmlish(text: str, content_type: str) -> bool:
    low_ct = _lower(content_type)
    low = _lower(text)
    if "text/html" in low_ct or "application/xhtml+xml" in low_ct:
        return True
    if "<html" in low or "<body" in low or "<form" in low or "<title" in low:
        return True
    return False


_AUTH_REQUIRED_PATH_HINTS = (
    "dashboard",
    "profile",
    "account",
    "orders",
    "admin",
    "token",
)


def _looks_like_login_gate_page(text: str, url: str, content_type: str) -> bool:
    low = _lower(text)
    path = _path_of_url(url)
    low_ct = _lower(content_type)

    if not any(h in path for h in _AUTH_REQUIRED_PATH_HINTS):
        return False

    if "text/html" not in low_ct and "<html" not in low and "<form" not in low:
        return False

    title_login = "<title>login" in low or ">login -" in low or ">login<" in low
    username_form = "<form" in low and 'name="username"' in low
    password_form = "<form" in low and 'type="password"' in low

    has_logout = "logout" in low
    has_dashboard_markers = "welcome," in low or "welcome back" in low or "dashboard" in low

    return (title_login or (username_form and password_form)) and not has_logout and not has_dashboard_markers


_RECEIPT_ORDER_ID_RE = re.compile(r"order\s*id:\s*([0-9]{3,})", re.I)
_RECEIPT_CODE_RE = re.compile(r"<code[^>]*>(.*?)</code>", re.I | re.S)


def _meaningful_receipt_payload(text: str) -> bool:
    low = (text or "").lower()
    m_id = _RECEIPT_ORDER_ID_RE.search(text or "")
    m_code = _RECEIPT_CODE_RE.search(text or "")
    code_text = (m_code.group(1).strip() if m_code else "")
    code_text = re.sub(r"\s+", " ", code_text).strip()

    has_real_order_id = bool(m_id and m_id.group(1).strip())
    has_nonempty_code = bool(code_text)
    empty_order_shell = "order id:</strong> </p>" in low or "order id:</strong></p>" in low

    return (has_real_order_id or has_nonempty_code) and not empty_order_shell


def _looks_like_receipt_response(url: str, text: str) -> bool:
    path = _path_of_url(url)
    low = _lower(text)
    if "/receipt" in path:
        return True
    return ("receipt" in low) or ("order id" in low)


def _meaningful_redirect_location(location: str) -> bool:
    low = _lower(location)
    if not low:
        return False
    if _looks_like_static_asset_url(low):
        return False
    return any(
        marker in low
        for marker in (
            "dashboard",
            "profile",
            "admin",
            "orders",
            "token",
            "receipt",
            "download",
            "archive",
        )
    )


@dataclass(slots=True)
class HttpEvidenceValidator:

    async def validate(
        self,
        *,
        action: Action,
        obs: Observation,
        state: State,
    ) -> Optional[ValidationResult]:
        _ = state

        text_full = ""
        text_excerpt = ""
        headers: Dict[str, Any] = {}
        status = None
        url = ""
        stdout = ""
        stderr = ""

        if isinstance(obs.data, dict):
            text_full = str(obs.data.get("text_full") or "")
            text_excerpt = str(obs.data.get("text_excerpt") or "")
            headers = obs.data.get("headers") or {}
            status = obs.data.get("status_code")
            url = str(obs.data.get("url") or "")
            stdout = str(obs.data.get("stdout") or "")
            stderr = str(obs.data.get("stderr") or "")

        combined = "\n".join([text_full, text_excerpt, stdout, stderr])

        explicit_flag = None
        if isinstance(obs.data, dict):
            snippets = obs.data.get("flag_snippets") or []
            if isinstance(snippets, list) and snippets:
                explicit_flag = str(snippets[0])

            if obs.data.get("contains_flag_like") and not explicit_flag:
                explicit_flag = _flag_match(combined)

        if not explicit_flag:
            explicit_flag = _flag_match(combined)

        if explicit_flag:
            return ValidationResult(
                level="validated",
                kind="flag_capture",
                summary="Concrete flag-like signal captured from tool output.",
                evidence={
                    "flag": explicit_flag,
                    "url": url,
                    "status": status,
                    "action_type": action.type.value,
                },
            )

        if action.type in (ActionType.SHELL, ActionType.PYTHON):
            if obs.artifacts:
                return ValidationResult(
                    level="evidence",
                    kind="artifact_output",
                    summary="Tool execution produced artifacts worth validating later.",
                    evidence={
                        "artifacts": list(obs.artifacts),
                        "action_type": action.type.value,
                    },
                )

            low_stdout = _lower(stdout)
            if any(m in low_stdout for m in ("found admin", "token", "secret", "csrf", "success")):
                return ValidationResult(
                    level="evidence",
                    kind="tool_output",
                    summary="Tool output contains a concrete success/access signal.",
                    evidence={
                        "stdout_excerpt": stdout[:300],
                        "action_type": action.type.value,
                    },
                )

            return None

        if action.type != ActionType.HTTP:
            return None

        try:
            code = int(status or 0)
        except Exception:
            code = 0

        content_type = _lower(headers.get("content-type") or "")
        login_gate = _looks_like_login_gate_page(text_full or text_excerpt, url, content_type)
        low = _lower(combined)
        location = str(headers.get("location") or "")
        receipt_like = _looks_like_receipt_response(url, text_full or text_excerpt)

        if _looks_like_static_asset_url(url) or _is_static_content_type(content_type):
            return None

        if code in _HTTP_SUCCESS_CODES and login_gate:
            return None

        if receipt_like and not _meaningful_receipt_payload(text_full or text_excerpt):
            return None

        if code in _HTTP_REDIRECT_CODES and _meaningful_redirect_location(location):
            return ValidationResult(
                level="evidence",
                kind="redirect_access",
                summary="Redirect target suggests meaningful access or state transition.",
                evidence={
                    "url": url,
                    "status": code,
                    "location": location,
                },
            )

        if code in _HTTP_SUCCESS_CODES:
            negatives = sum(1 for m in _NEGATIVE_MARKERS if m in low)
            strongs = [m for m in _STRONG_ACCESS_MARKERS if m in low]
            structured = [m for m in _STRUCTURED_VALUE_MARKERS if m in low]

            if negatives == 0 and strongs and not login_gate:
                return ValidationResult(
                    level="evidence",
                    kind="resource_access",
                    summary="HTTP response contains concrete non-static access markers.",
                    evidence={
                        "url": url,
                        "status": code,
                        "markers": strongs[:8],
                    },
                )

            if negatives == 0 and structured and _looks_like_htmlish(text_full or text_excerpt, content_type) and not login_gate:
                return ValidationResult(
                    level="evidence",
                    kind="structured_secret_signal",
                    summary="Response contains structured secret/token-like signals in a meaningful page.",
                    evidence={
                        "url": url,
                        "status": code,
                        "markers": structured[:8],
                    },
                )

            if (
                code == 200
                and len(text_full) >= 180
                and negatives == 0
                and _looks_like_htmlish(text_full or text_excerpt, content_type)
                and not login_gate
            ):
                return ValidationResult(
                    level="evidence",
                    kind="substantive_http_response",
                    summary="HTTP request returned a substantive non-error page worth keeping as evidence.",
                    evidence={
                        "url": url,
                        "status": code,
                        "text_len": len(text_full),
                    },
                )

        return None