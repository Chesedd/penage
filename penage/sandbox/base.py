from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Protocol


@dataclass(frozen=True, slots=True)
class SandboxResult:
    ok: bool
    exit_code: int
    stdout: str
    stderr: str
    elapsed_ms: int
    error: Optional[str] = None


class Sandbox(Protocol):
    name: str

    async def run_shell(
        self,
        *,
        cmd: str,
        timeout_s: float,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        ...

    async def run_python(
        self,
        *,
        code: str,
        timeout_s: float,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        ...