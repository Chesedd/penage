from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from penage.sandbox.base import Sandbox, SandboxResult


@dataclass(slots=True)
class SandboxExecutor:
    sandbox: Sandbox
    max_output_chars: int = 30_000

    def _clip(self, s: str) -> str:
        if s is None:
            return ""
        if len(s) <= self.max_output_chars:
            return s
        return s[: self.max_output_chars] + "\n<...truncated...>\n"

    async def run_shell(
        self,
        *,
        cmd: str,
        timeout_s: float = 60.0,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        res = await self.sandbox.run_shell(cmd=cmd, timeout_s=timeout_s, cwd=cwd, env=env)
        return SandboxResult(
            ok=res.ok,
            exit_code=res.exit_code,
            stdout=self._clip(res.stdout),
            stderr=self._clip(res.stderr),
            elapsed_ms=res.elapsed_ms,
            error=res.error,
        )

    async def run_python(
        self,
        *,
        code: str,
        timeout_s: float = 60.0,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        res = await self.sandbox.run_python(code=code, timeout_s=timeout_s, cwd=cwd, env=env)
        return SandboxResult(
            ok=res.ok,
            exit_code=res.exit_code,
            stdout=self._clip(res.stdout),
            stderr=self._clip(res.stderr),
            elapsed_ms=res.elapsed_ms,
            error=res.error,
        )