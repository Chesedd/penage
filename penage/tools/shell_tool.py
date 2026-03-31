from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from penage.core.actions import Action
from penage.core.observations import Observation


@dataclass(slots=True)
class ShellTool:
    async def run(self, action: Action) -> Observation:
        params = action.params or {}
        cmd = params.get("command")
        if not cmd or not isinstance(cmd, str):
            return Observation(ok=False, error="SHELL action missing 'command' (string)")

        timeout_s = action.timeout_s if action.timeout_s is not None else params.get("timeout_s", 30.0)

        start = time.perf_counter()
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
            except asyncio.TimeoutError:
                proc.kill()
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                return Observation(ok=False, elapsed_ms=elapsed_ms, error=f"SHELL timeout after {timeout_s}s")

            elapsed_ms = int((time.perf_counter() - start) * 1000)
            stdout = (stdout_b or b"").decode("utf-8", errors="replace")
            stderr = (stderr_b or b"").decode("utf-8", errors="replace")

            return Observation(
                ok=(proc.returncode == 0),
                elapsed_ms=elapsed_ms,
                data={
                    "returncode": proc.returncode,
                    "stdout": stdout,
                    "stderr": stderr,
                },
                error=None if proc.returncode == 0 else f"SHELL non-zero exit: {proc.returncode}",
            )
        except Exception as e:
            elapsed_ms = int((time.perf_counter() - start) * 1000)
            return Observation(ok=False, elapsed_ms=elapsed_ms, error=f"SHELL failed: {e}")