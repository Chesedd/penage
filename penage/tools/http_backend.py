from __future__ import annotations

from typing import Protocol

from penage.core.actions import Action
from penage.core.observations import Observation


class HttpBackend(Protocol):
    async def run(self, action: Action) -> Observation:
        ...

    async def aclose(self) -> None:
        ...