from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

from penage.core.actions import Action, ActionType


DEFAULT_BLOCKED_EXT = (
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


@dataclass(slots=True)
class UrlGuard:
    block_static_assets: bool = True

    def filter(self, actions: Iterable[Action]) -> list[Action]:
        out: list[Action] = []
        for a in actions:
            if a.type != ActionType.HTTP:
                out.append(a)
                continue

            url = str((a.params or {}).get("url") or "")
            if self.block_static_assets and self._looks_like_asset(url):
                continue

            out.append(a)
        return out

    def _looks_like_asset(self, url: str) -> bool:
        try:
            path = (urlparse(url).path or "").lower()
        except Exception:
            return False

        if path.startswith("/static/"):
            return True
        return path.endswith(DEFAULT_BLOCKED_EXT)