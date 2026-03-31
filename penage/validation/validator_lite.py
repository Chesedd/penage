from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Sequence, TypedDict

from penage.sandbox.base import SandboxResult
from penage.sandbox.executor import SandboxExecutor


StepType = Literal["shell", "python"]


class ValidationStep(TypedDict, total=False):
    type: StepType
    cmd: str          # for shell
    code: str         # for python
    timeout_s: float
    note: str


@dataclass(frozen=True, slots=True)
class ValidationResult:
    verdict: Literal["pass", "fail", "unknown"]
    summary: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class ValidatorLite:
    executor: SandboxExecutor

    async def validate(
        self,
        *,
        steps: Sequence[ValidationStep],
        stop_on_fail: bool = True,
        require_all_ok: bool = True,
    ) -> ValidationResult:
        evidence: List[Dict[str, Any]] = []
        any_fail = False

        for idx, step in enumerate(steps):
            stype = step.get("type")
            timeout_s = float(step.get("timeout_s", 60.0))
            note = step.get("note", "")

            if stype == "shell":
                cmd = step.get("cmd") or ""
                res = await self.executor.run_shell(cmd=cmd, timeout_s=timeout_s)
                evidence.append(_ev(idx, "shell", note, cmd=cmd, res=res))
                if not res.ok:
                    any_fail = True
                    if stop_on_fail:
                        break

            elif stype == "python":
                code = step.get("code") or ""
                res = await self.executor.run_python(code=code, timeout_s=timeout_s)
                evidence.append(_ev(idx, "python", note, code=code, res=res))
                if not res.ok:
                    any_fail = True
                    if stop_on_fail:
                        break

            else:
                evidence.append({"step": idx, "type": "unknown", "note": note, "error": f"unknown step type: {stype!r}"})
                any_fail = True
                if stop_on_fail:
                    break

        if require_all_ok:
            if any_fail:
                return ValidationResult(verdict="fail", summary="one or more validation steps failed", evidence=evidence)
            return ValidationResult(verdict="pass", summary="all validation steps succeeded", evidence=evidence)

        return ValidationResult(verdict="unknown", summary="validation completed (non-strict mode)", evidence=evidence)


def _ev(idx: int, typ: str, note: str, *, cmd: str = "", code: str = "", res: SandboxResult) -> Dict[str, Any]:
    return {
        "step": idx,
        "type": typ,
        "note": note,
        "cmd": cmd,
        "code": code,
        "ok": res.ok,
        "exit_code": res.exit_code,
        "elapsed_ms": res.elapsed_ms,
        "stdout": res.stdout,
        "stderr": res.stderr,
        "error": res.error,
    }