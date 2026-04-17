from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from penage.core.errors import SandboxError
from penage.sandbox.base import SandboxResult


@dataclass(slots=True)
class DockerSandbox:
    name: str = "docker"
    image: str = "python:3.12-slim"
    network_mode: str = "none"
    max_output_chars: int = 50_000

    # NEW
    persistent: bool = False

    # Hardening/resource limits (override if needed later)
    cpus: str = "1"
    memory: str = "512m"
    pids_limit: int = 256
    run_as_user: str = "1000:1000"

    tmpfs_tmp: str = "/tmp:rw,noexec,nosuid,size=64m"
    tmpfs_workspace: str = "/workspace:rw,nosuid,size=128m"

    # Hardening (new in 3.6)
    memory_swap: Optional[str] = None  # default: равен memory (disable swap)
    hostname: str = "penage-sandbox"
    use_init: bool = True
    log_driver: str = "none"

    # ulimits: имя → (soft, hard). Значения в байтах/количестве.
    ulimit_fsize: int = 67_108_864   # 64 MiB — max file size
    ulimit_nofile: int = 256         # max open files
    ulimit_nproc: int = 256          # max processes (вместе с pids-limit — двойная защита)

    # NEW: runtime state
    _container_id: Optional[str] = None
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def aclose(self) -> None:
        if not self.persistent:
            return

        async with self._lock:
            cid = self._container_id
            self._container_id = None

        if not cid:
            return

        try:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "rm",
                "-f",
                cid,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.communicate()
        except Exception:  # LEGACY: best-effort cleanup
            pass

    async def run_shell(
        self,
        *,
        cmd: str,
        timeout_s: float,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        if self.persistent:
            return await self._exec_in_persistent(["sh", "-lc", cmd], timeout_s=timeout_s, cwd=cwd, env=env)
        return await self._run_in_container(["sh", "-lc", cmd], timeout_s=timeout_s, cwd=cwd, env=env)

    async def run_python(
        self,
        *,
        code: str,
        timeout_s: float,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> SandboxResult:
        if self.persistent:
            return await self._exec_in_persistent(["python", "-c", code], timeout_s=timeout_s, cwd=cwd, env=env)
        return await self._run_in_container(["python", "-c", code], timeout_s=timeout_s, cwd=cwd, env=env)

    def _base_docker_run_args(self, *, cwd: Optional[str], env: Optional[Dict[str, str]]) -> list[str]:
        mem_swap = self.memory_swap if self.memory_swap is not None else self.memory

        docker_cmd: list[str] = [
            "docker",
            "run",
            # network
            "--network",
            self.network_mode,
            # hardening
            "--read-only",
            "--tmpfs",
            self.tmpfs_tmp,
            "--tmpfs",
            self.tmpfs_workspace,
            "--workdir",
            cwd or "/workspace",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(self.pids_limit),
            "--memory",
            self.memory,
            "--memory-swap",
            mem_swap,
            "--cpus",
            self.cpus,
            "--user",
            self.run_as_user,
            "--hostname",
            self.hostname,
            "--log-driver",
            self.log_driver,
            "--ulimit",
            f"fsize={self.ulimit_fsize}:{self.ulimit_fsize}",
            "--ulimit",
            f"nofile={self.ulimit_nofile}:{self.ulimit_nofile}",
            "--ulimit",
            f"nproc={self.ulimit_nproc}:{self.ulimit_nproc}",
        ]

        if self.use_init:
            docker_cmd += ["--init"]

        if "HOME" not in (env or {}):
            docker_cmd += ["-e", "HOME=/workspace"]
        if env:
            for k, v in env.items():
                docker_cmd += ["-e", f"{k}={v}"]
        return docker_cmd

    async def _ensure_persistent_container(self, *, cwd: Optional[str], env: Optional[Dict[str, str]]) -> Optional[str]:
        if self._container_id:
            return self._container_id

        # Start a daemon container
        docker_cmd = self._base_docker_run_args(cwd=cwd, env=env)
        docker_cmd += [
            "-d",
            "--rm",  # auto-remove when stopped
            self.image,
            "sh",
            "-lc",
            # keep alive
            "trap : TERM INT; sleep infinity & wait",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_b, stderr_b = await proc.communicate()
        except FileNotFoundError:
            return None
        except OSError as e:
            raise SandboxError("failed to start docker daemon container", cause=e) from e

        if int(proc.returncode or 0) != 0:
            _ = stderr_b
            return None

        cid = (stdout_b or b"").decode(errors="replace").strip()
        if not cid:
            return None

        self._container_id = cid
        return cid

    async def _exec_in_persistent(
        self,
        cmd: list[str],
        *,
        timeout_s: float,
        cwd: Optional[str],
        env: Optional[Dict[str, str]],
    ) -> SandboxResult:
        t0 = time.perf_counter()

        async with self._lock:
            cid = await self._ensure_persistent_container(cwd=cwd, env=None)  # env handled per-exec
            if not cid:
                return SandboxResult(
                    ok=False,
                    exit_code=127,
                    stdout="",
                    stderr="failed to start persistent docker container",
                    elapsed_ms=int((time.perf_counter() - t0) * 1000),
                    error="docker_start_failed",
                )

            docker_cmd: list[str] = ["docker", "exec"]

            if env:
                for k, v in env.items():
                    docker_cmd += ["-e", f"{k}={v}"]

            if cwd:
                docker_cmd += ["-w", cwd]

            docker_cmd += [cid]
            docker_cmd += cmd

            try:
                proc = await asyncio.create_subprocess_exec(
                    *docker_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                return SandboxResult(
                    ok=False,
                    exit_code=127,
                    stdout="",
                    stderr="docker not found",
                    elapsed_ms=int((time.perf_counter() - t0) * 1000),
                    error="docker not found",
                )
            except OSError as e:
                return SandboxResult(
                    ok=False,
                    exit_code=1,
                    stdout="",
                    stderr=str(e),
                    elapsed_ms=int((time.perf_counter() - t0) * 1000),
                    error=str(e),
                )

            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
            except asyncio.TimeoutError:
                proc.kill()
                try:
                    await proc.communicate()
                except Exception:  # LEGACY: best-effort after kill
                    pass
                return SandboxResult(
                    ok=False,
                    exit_code=124,
                    stdout="",
                    stderr=f"timeout after {timeout_s}s",
                    elapsed_ms=int((time.perf_counter() - t0) * 1000),
                    error="timeout",
                )

            stdout = (stdout_b or b"").decode(errors="replace")
            stderr = (stderr_b or b"").decode(errors="replace")

            if len(stdout) > self.max_output_chars:
                stdout = stdout[: self.max_output_chars] + "\n<...truncated...>\n"
            if len(stderr) > self.max_output_chars:
                stderr = stderr[: self.max_output_chars] + "\n<...truncated...>\n"

            exit_code = int(proc.returncode or 0)
            ok = exit_code == 0
            return SandboxResult(
                ok=ok,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                elapsed_ms=int((time.perf_counter() - t0) * 1000),
                error=None if ok else "nonzero exit",
            )

    async def _run_in_container(
        self,
        cmd: list[str],
        *,
        timeout_s: float,
        cwd: Optional[str],
        env: Optional[Dict[str, str]],
    ) -> SandboxResult:
        t0 = time.perf_counter()

        docker_cmd = self._base_docker_run_args(cwd=cwd, env=env)
        docker_cmd += ["--rm", self.image]
        docker_cmd += cmd

        try:
            proc = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            return SandboxResult(
                ok=False,
                exit_code=127,
                stdout="",
                stderr="docker not found",
                elapsed_ms=int((time.perf_counter() - t0) * 1000),
                error="docker not found",
            )
        except OSError as e:
            return SandboxResult(
                ok=False,
                exit_code=1,
                stdout="",
                stderr=str(e),
                elapsed_ms=int((time.perf_counter() - t0) * 1000),
                error=str(e),
            )

        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
        except asyncio.TimeoutError:
            proc.kill()
            try:
                await proc.communicate()
            except Exception:  # LEGACY: best-effort after kill
                pass
            return SandboxResult(
                ok=False,
                exit_code=124,
                stdout="",
                stderr=f"timeout after {timeout_s}s",
                elapsed_ms=int((time.perf_counter() - t0) * 1000),
                error="timeout",
            )

        stdout = (stdout_b or b"").decode(errors="replace")
        stderr = (stderr_b or b"").decode(errors="replace")

        if len(stdout) > self.max_output_chars:
            stdout = stdout[: self.max_output_chars] + "\n<...truncated...>\n"
        if len(stderr) > self.max_output_chars:
            stderr = stderr[: self.max_output_chars] + "\n<...truncated...>\n"

        exit_code = int(proc.returncode or 0)
        ok = exit_code == 0
        return SandboxResult(
            ok=ok,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            elapsed_ms=int((time.perf_counter() - t0) * 1000),
            error=None if ok else "nonzero exit",
        )