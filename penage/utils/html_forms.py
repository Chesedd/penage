from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_INPUT_RE = re.compile(r"<input\b([^>]*)>", re.IGNORECASE | re.DOTALL)

_ATTR_RE = re.compile(
    r'(\w+)\s*=\s*"([^"]*)"|(\w+)\s*=\s*\'([^\']*)\'|(\w+)\s*=\s*([^\s>]+)',
    re.IGNORECASE,
)

_BOOL_ATTR_RE = re.compile(r"\b(required|hidden|disabled|checked|readonly)\b", re.IGNORECASE)


def _parse_attrs(attr_text: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for m in _ATTR_RE.finditer(attr_text):
        if m.group(1) and m.group(2):
            attrs[m.group(1).lower()] = m.group(2)
        elif m.group(3) and m.group(4):
            attrs[m.group(3).lower()] = m.group(4)
        elif m.group(5) and m.group(6):
            attrs[m.group(5).lower()] = m.group(6)

    for bm in _BOOL_ATTR_RE.finditer(attr_text):
        attrs[bm.group(1).lower()] = "true"

    return attrs


@dataclass(frozen=True, slots=True)
class HtmlInput:
    name: str
    type: str = "text"
    value: Optional[str] = None
    required: bool = False
    hidden: bool = False


@dataclass(frozen=True, slots=True)
class HtmlForm:
    method: str
    action: str
    inputs: List[HtmlInput]


def extract_forms(html: str) -> List[HtmlForm]:
    out: List[HtmlForm] = []
    if not html:
        return out

    for fm in _FORM_RE.finditer(html):
        form_attrs = _parse_attrs(fm.group(1) or "")
        inner = fm.group(2) or ""

        method = (form_attrs.get("method") or "GET").upper()
        action = form_attrs.get("action") or ""  # empty => current path

        inputs: List[HtmlInput] = []
        for im in _INPUT_RE.finditer(inner):
            raw = im.group(1) or ""
            attrs = _parse_attrs(raw)

            name = attrs.get("name")
            if not name:
                continue

            itype = (attrs.get("type") or "text").lower()
            value = attrs.get("value")

            required = attrs.get("required", "").lower() == "true"
            hidden = itype == "hidden" or (attrs.get("hidden", "").lower() == "true")

            inputs.append(HtmlInput(name=name, type=itype, value=value, required=required, hidden=hidden))

        out.append(HtmlForm(method=method, action=action, inputs=inputs))

    return out