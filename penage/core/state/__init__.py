from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from penage.core.state.stores import (
    AuthRoleRegistry,
    AuthState,
    CurlReconTracking,
    FilterModel,
    MacroState,
    ResearchTracking,
    RoleSession,
    SpecialistTracking,
)

__all__ = [
    "State",
    "AuthRoleRegistry",
    "AuthState",
    "CurlReconTracking",
    "FilterModel",
    "MacroState",
    "ResearchTracking",
    "RoleSession",
    "SpecialistTracking",
]


@dataclass(slots=True)
class State:
    facts: Dict[str, Any] = field(default_factory=dict)
    visited_actions_fingerprint: Set[str] = field(default_factory=set)
    notes: List[str] = field(default_factory=list)

    # --- orchestration ---
    orch_step: int = 0
    base_url: str = ""

    # --- last HTTP response ---
    last_http_status: Optional[int] = None
    last_http_url: Optional[str] = None
    last_http_excerpt: Optional[str] = None
    last_http_text_full: Optional[str] = None

    last_forms: List[dict[str, object]] = field(default_factory=list)
    known_paths: Set[str] = field(default_factory=set)
    # Mapping from URL to list of form descriptors; each form has shape:
    #   {
    #     "method": str,           # HTTP method ("get"/"post"), as extracted
    #     "action": str,           # resolved absolute URL (via urljoin with base_url)
    #     "inputs": list[dict],    # one entry per <input>/<textarea>/<select>
    #   }
    # Each ``inputs`` entry has shape:
    #   {
    #     "name": str,       # input element name; "" for nameless — should be skipped
    #     "type": str,       # lowercased (e.g. "text", "hidden", "submit", "password")
    #     "value": str,      # default or pre-filled value; "" if absent
    #     "required": bool,  # from HTML ``required`` attribute
    #     "hidden": bool,    # type == "hidden" OR inferred style display:none
    #   }
    # Note: submit-type inputs are excluded from SQLi target discovery
    # (_SKIP_INPUT_TYPES in penage/specialists/vulns/sqli.py) but remain as
    # sibling fields in other targets' baseline_params so the form submit
    # trigger still fires.
    forms_by_url: Dict[str, List[dict[str, object]]] = field(default_factory=dict)

    http_requests_used: int = 0
    total_text_len_seen: int = 0

    llm_calls: int = 0
    tool_calls_total: int = 0
    tool_calls_http: int = 0
    tool_calls_sandbox: int = 0
    tool_elapsed_ms_total: int = 0

    known_paths_count_prev: int = 0
    no_new_paths_streak: int = 0

    best_http_score: float = 0.0
    best_http_url: Optional[str] = None
    best_http_text_full: Optional[str] = None
    best_http_ids: List[str] = field(default_factory=list)
    best_http_paths: List[str] = field(default_factory=list)

    recent_http_memory: List[Dict[str, object]] = field(default_factory=list)
    recent_http_memory_limit: int = 4

    research_summary: str = ""
    research_hypotheses: List[Dict[str, object]] = field(default_factory=list)
    research_fuzz_paths: List[str] = field(default_factory=list)
    research_negatives: List[str] = field(default_factory=list)
    research_negative_families: List[str] = field(default_factory=list)
    recent_failures: List[Dict[str, object]] = field(default_factory=list)
    recent_failures_limit: int = 8

    research_llm_last_step: int = 0

    last_action_family: Optional[str] = None
    same_action_family_streak: int = 0
    action_family_counts: Dict[str, int] = field(default_factory=dict)

    policy_source_counts: Dict[str, int] = field(default_factory=dict)
    last_policy_source: Optional[str] = None
    same_policy_source_streak: int = 0

    # --- policy tracking ---
    policy_name: str = ""
    policy_chosen_source: str = ""

    # Ring of recent validation outcomes. Despite the name, this is
    # ``list[dict[str, Any]]``, NOT ``list[ValidationResult]`` — there is no
    # ``ValidationResult`` dataclass in the core state tree. Each entry has
    # the following keys:
    #   - ``kind``: str  (e.g. "xss_finding", "sqli_finding", "evidence_note")
    #   - ``level``: str — one of ``"validated"`` | ``"evidence"`` | ``"rejected"``
    #   - ``url``: str
    #   - ``parameter``: str
    #   - ``payload``: str
    #   - ``details``: dict — validator-specific nested payload
    # Access pattern: ``r.get("level")`` (dict lookup, NOT attribute access).
    # Early test code that tried attribute access failed silently — if you
    # are tempted to write ``r.level`` here, stop.
    # Populated by :class:`penage.validation.gate.ValidationGate` (for HTTP
    # actions routed through the gate) and by specialist-direct NOTE findings
    # for SQLi (which bypasses the gate to emit findings inline).
    validation_results: List[Dict[str, object]] = field(default_factory=list)
    validation_results_limit: int = 10
    validation_evidence_count: int = 0
    validation_validated_count: int = 0
    last_validation: Optional[Dict[str, object]] = None

    # summary / telemetry counters used by run_one.py
    http_status_counts: Dict[str, int] = field(default_factory=dict)
    novel_http_responses: int = 0
    useful_http_responses: int = 0
    failure_http_responses: int = 0
    form_pages_seen: int = 0

    promoted_pivot_ids: List[str] = field(default_factory=list)
    promoted_pivot_targets: List[str] = field(default_factory=list)
    promoted_pivot_source: Optional[str] = None
    promoted_pivot_reason: str = ""
    promoted_pivot_active_until_step: int = 0

    # --- page extraction ---
    page_ids: List[str] = field(default_factory=list)

    # --- typed sub-stores ---
    auth: AuthState = field(default_factory=AuthState)
    auth_roles: AuthRoleRegistry = field(default_factory=AuthRoleRegistry)
    macro: MacroState = field(default_factory=MacroState)
    curl_recon: CurlReconTracking = field(default_factory=CurlReconTracking)
    research_tracking: ResearchTracking = field(default_factory=ResearchTracking)
    specialist: SpecialistTracking = field(default_factory=SpecialistTracking)
