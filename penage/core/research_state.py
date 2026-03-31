from __future__ import annotations

from dataclasses import dataclass

from penage.core.state import State
from penage.core.state_helpers import (
    clip_text,
    dedup_keep_order,
    path_only,
    truncate_forms,
)


@dataclass(slots=True)
class ResearchStateSyncer:
    def store_specialist_previews(self, st: State, specialist_candidates: list) -> None:
        st.facts["specialist_candidates_count"] = len(specialist_candidates)

        preview = []
        research_preview = []
        for c in specialist_candidates[:20]:
            item = {
                "source": c.source,
                "score": c.score,
                "type": getattr(c.action.type, "value", str(c.action.type)),
                "url": (c.action.params or {}).get("url"),
                "method": (c.action.params or {}).get("method"),
                "reason": c.reason,
            }
            preview.append(item)

            if str(c.source) in ("research_llm", "research"):
                research_preview.append(
                    {
                        **item,
                        "reason": (c.reason or "")[:240],
                        "tags": list(getattr(c.action, "tags", []) or [])[:12],
                    }
                )

        st.facts["specialist_candidates_preview"] = preview
        if research_preview:
            st.facts["research_candidates_preview"] = research_preview[:12]

    def sync_research_memory_from_facts(self, st: State) -> None:
        rr = st.facts.get("research_last_result")
        if not isinstance(rr, dict):
            return

        st.research_summary = str(rr.get("notes") or "")[:800]

        hyps = rr.get("hypotheses")
        if isinstance(hyps, list):
            cleaned: list[dict[str, object]] = []
            for h in hyps[:10]:
                if not isinstance(h, dict):
                    continue
                cleaned.append(
                    {
                        "method": str(h.get("method") or "GET").upper(),
                        "path": str(h.get("path") or "")[:240],
                        "why": str(h.get("why") or "")[:240],
                        "confidence": float(h.get("confidence") or 0.0),
                    }
                )
            st.research_hypotheses = cleaned

        fuzz_paths = rr.get("fuzz_paths")
        if isinstance(fuzz_paths, list):
            st.research_fuzz_paths = dedup_keep_order([str(x) for x in fuzz_paths], limit=24)

    def record_recent_http_memory(
        self,
        st: State,
        *,
        url: str,
        status: int | None,
        excerpt: str,
        paths_preview: list[str],
        forms_preview: list[dict[str, object]],
    ) -> None:
        if not url:
            return
        item = {
            "url": url,
            "status": status,
            "excerpt": clip_text(excerpt or "", 1200),
            "paths": paths_preview[:20],
            "forms": truncate_forms(forms_preview),
        }
        st.recent_http_memory.append(item)
        if len(st.recent_http_memory) > st.recent_http_memory_limit:
            st.recent_http_memory = st.recent_http_memory[-st.recent_http_memory_limit :]
        st.facts["recent_http_memory_preview"] = st.recent_http_memory[-st.recent_http_memory_limit :]

    def record_negative_http_result(
        self,
        st: State,
        *,
        url: str,
        status: int | None,
        action_family: str,
        excerpt: str,
        had_new_paths: bool,
        had_forms: bool,
    ) -> None:
        code = int(status or 0)
        if code not in (404, 405, 410):
            return
        if had_new_paths or had_forms:
            return

        path = path_only(url)
        if not path:
            return

        st.research_negatives = dedup_keep_order(st.research_negatives + [path], limit=40)
        st.research_negative_families = dedup_keep_order(
            st.research_negative_families + [action_family],
            limit=20,
        )

        st.recent_failures.append(
            {
                "url": url,
                "path": path,
                "status": code,
                "family": action_family,
                "excerpt": clip_text(excerpt or "", 600),
            }
        )
        if len(st.recent_failures) > st.recent_failures_limit:
            st.recent_failures = st.recent_failures[-st.recent_failures_limit :]

        st.facts["research_negatives_preview"] = st.research_negatives[-20:]
        st.facts["research_negative_families_preview"] = st.research_negative_families[-12:]
        st.facts["recent_failures_preview"] = st.recent_failures[-st.recent_failures_limit :]

    def promote_confirmed_pivot(
        self,
        st: State,
        *,
        ids: list[str],
        targets: list[str],
        source: str,
        reason: str,
        ttl_steps: int = 6,
    ) -> None:
        curr_step = int(st.facts.get("orch_step") or 0)

        merged_ids = dedup_keep_order((ids or []) + list(st.promoted_pivot_ids or []), limit=8)
        merged_targets = dedup_keep_order((targets or []) + list(st.promoted_pivot_targets or []), limit=8)

        st.promoted_pivot_ids = merged_ids
        st.promoted_pivot_targets = merged_targets
        st.promoted_pivot_source = str(source or "")
        st.promoted_pivot_reason = str(reason or "")
        st.promoted_pivot_active_until_step = curr_step + max(1, int(ttl_steps))

        st.facts["promoted_pivot_ids"] = merged_ids
        st.facts["promoted_pivot_targets"] = merged_targets
        st.facts["promoted_pivot_source"] = st.promoted_pivot_source
        st.facts["promoted_pivot_reason"] = st.promoted_pivot_reason
        st.facts["promoted_pivot_active_until_step"] = st.promoted_pivot_active_until_step