from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class AuthState:
    """Auth confusion specialist results and session tracking."""

    confusion_runs: int = 0
    confusion_last_step: int = 0
    confusion_last_hits_preview: list[dict[str, object]] = field(default_factory=list)
    confusion_winning_ids: list[str] = field(default_factory=list)
    confusion_bad_form_actions: list[str] = field(default_factory=list)
    confusion_last_stats: dict[str, object] = field(default_factory=dict)
    confusion_last_fp: str = ""
    confusion_followup_last_fp: str = ""
    session_established: bool = False


@dataclass(slots=True)
class RoleSession:
    """Single named session (cookies + metadata) for one logical role.

    Supports multi-role penetration tests (e.g. IDOR differential probes):
    role-A is a regular user who owns some resource; role-B is another
    regular user used to check whether role-A's resource is accessible
    under B's cookies.

    SECURITY: cookies are in-memory only; no persistence to disk. Use
    AuthRoleRegistry to look up per-role sessions during a single episode.
    """

    role_name: str
    username: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    established: bool = False
    last_login_ts: float = 0.0
    login_error: str = ""   # non-empty iff last attempt failed


@dataclass(slots=True)
class AuthRoleRegistry:
    """Registry of named role sessions for multi-role specialists.

    Populated by specialists (e.g. IdorSpecialist) via login utilities.
    Reads via .get() or direct .roles access. Not thread-safe — writes
    must be serialised by the orchestrator.

    login_url is optional and may be auto-discovered from state.forms_by_url
    by the login utility; CLI may also pre-configure it.
    """

    roles: dict[str, RoleSession] = field(default_factory=dict)
    login_url: str = ""

    def get(self, role_name: str) -> RoleSession | None:
        return self.roles.get(role_name)

    def upsert(self, session: RoleSession) -> None:
        self.roles[session.role_name] = session

    def has_established(self, role_name: str) -> bool:
        sess = self.roles.get(role_name)
        return sess is not None and sess.established

    def established_roles(self) -> list[str]:
        return [name for name, s in self.roles.items() if s.established]


@dataclass(slots=True)
class MacroState:
    """Macro execution results."""

    last_name: str = ""
    last_result: dict[str, object] = field(default_factory=dict)
    auth_followup_hits_preview: list[dict[str, object]] = field(default_factory=list)
    followup_hits_preview: list[dict[str, object]] = field(default_factory=list)
    followup_recommended_next: list[object] = field(default_factory=list)
    family_hits_preview: list[dict[str, object]] = field(default_factory=list)
    family_recommended_next: list[object] = field(default_factory=list)


@dataclass(slots=True)
class CurlReconTracking:
    """Curl recon specialist cooldown and dedup tracking."""

    runs: int = 0
    last_step: int = 0
    last_target_url: str = ""
    useless_streak: int = 0


@dataclass(slots=True)
class ResearchTracking:
    """Research specialist tracking state."""

    det_last_step: int = 0
    det_preview: list[dict[str, object]] = field(default_factory=list)
    fuzz_runs: int = 0
    last_fuzz_step: int = 0
    last_fuzz_fp: str = ""
    last_result: dict[str, object] = field(default_factory=dict)
    candidates_preview: list[dict[str, object]] = field(default_factory=list)


@dataclass(slots=True)
class SpecialistTracking:
    """Specialist management telemetry."""

    candidates_count: int = 0
    candidates_preview: list[dict[str, object]] = field(default_factory=list)
    errors_preview: list[dict[str, object]] = field(default_factory=list)
    source_counts_preview: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class FilterModel:
    """Inferred input-filter behaviour for a single parameter/channel.

    Populated by :class:`penage.specialists.shared.filter_inferrer.FilterInferrer`.
    Each probe falls into exactly one of three buckets:

    - ``allowed_tags`` / ``allowed_events`` — echoed verbatim.
    - ``blocked_tags`` / ``blocked_events`` — removed from the response.
    - ``transformed_chars`` — character-level rewrites (``{char: transform}``).
      Example: ``{'<': '&lt;'}`` means ``<`` was HTML-entity encoded.
    """

    parameter: str = ""
    channel: str = ""
    allowed_tags: list[str] = field(default_factory=list)
    blocked_tags: list[str] = field(default_factory=list)
    allowed_events: list[str] = field(default_factory=list)
    blocked_events: list[str] = field(default_factory=list)
    transformed_chars: dict[str, str] = field(default_factory=dict)
