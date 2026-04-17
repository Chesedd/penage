from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


class BrowserError(Exception):
    """Raised when a browser operation cannot complete.

    Covers navigation, DOM/JS evaluation and teardown failures. Validators
    using :class:`Browser` catch this to degrade quietly instead of crashing
    the validation cascade.
    """


@runtime_checkable
class Browser(Protocol):
    """Async browser abstraction for evidence validation.

    Implementations must be usable inside an episode lifetime (lazy create,
    guaranteed ``aclose`` via ``try/finally`` — see invariant #11 in
    ``CLAUDE.md``). A single instance is expected to be reused across
    navigations within an episode; ``aclose`` must be idempotent.
    """

    async def navigate(self, url: str) -> None:
        ...

    async def get_dom(self) -> str:
        ...

    async def eval_js(self, expr: str) -> Any:
        ...

    async def aclose(self) -> None:
        ...
