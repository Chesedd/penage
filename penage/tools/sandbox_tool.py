from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.sandbox.base import Sandbox


@dataclass(slots=True)
class SandboxTool:
    sandbox: Sandbox

    async def aclose(self) -> None:
        aclose = getattr(self.sandbox, "aclose", None)
        if callable(aclose):
            await aclose()

    async def run(self, action: Action) -> Observation:
        params = action.params or {}

        timeout_s = action.timeout_s
        if timeout_s is None:
            timeout_s = float(params.get("timeout_s", 30.0))

        if action.type == ActionType.SHELL:
            cmd = params.get("command")
            if not cmd or not isinstance(cmd, str):
                return Observation(ok=False, error="SHELL action missing 'command' (string)")

            res = await self.sandbox.run_shell(cmd=cmd, timeout_s=float(timeout_s))
            return Observation(
                ok=res.ok,
                elapsed_ms=res.elapsed_ms,
                data={"exit_code": res.exit_code, "stdout": res.stdout, "stderr": res.stderr},
                error=res.error,
            )

        if action.type == ActionType.PYTHON:
            code = params.get("code")
            if not code or not isinstance(code, str):
                return Observation(ok=False, error="PYTHON action missing 'code' (string)")

            res = await self.sandbox.run_python(code=code, timeout_s=float(timeout_s))
            return Observation(
                ok=res.ok,
                elapsed_ms=res.elapsed_ms,
                data={"exit_code": res.exit_code, "stdout": res.stdout, "stderr": res.stderr},
                error=res.error,
            )

        return Observation(ok=False, error=f"SandboxTool unsupported action type: {action.type}")