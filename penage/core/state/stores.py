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
