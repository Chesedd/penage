from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from penage.sandbox.base import SandboxResult


@dataclass(slots=True)
class NullSandbox:
    name: str = "null"

    async def run_shell(
        self,
        *,
        cmd: str,
        timeout_s: float,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        _ = (cmd, timeout_s, cwd, env)
        return SandboxResult(
            ok=False,
            exit_code=127,
            stdout="",
            stderr="sandbox disabled",
            elapsed_ms=0,
            error="sandbox disabled",
        )

    async def run_python(
        self,
        *,
        code: str,
        timeout_s: float,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        _ = (code, timeout_s, cwd, env)
        return SandboxResult(
            ok=False,
            exit_code=127,
            stdout="",
            stderr="sandbox disabled",
            elapsed_ms=0,
            error="sandbox disabled",
        )