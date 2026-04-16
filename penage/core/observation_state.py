from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.parse import urljoin

from penage.core.action_tracking import ActionStateRecorder
from penage.core.actions import Action, ActionType
from penage.core.observations import Observation
from penage.core.research_state import ResearchStateSyncer
from penage.core.state import State
from penage.core.state_helpers import (
    STATIC_CONTENT_TYPE_PREFIXES,
    extract_numeric_ids,
    looks_like_login_gate_http_page,
    looks_like_static_http_url,
    promoted_ids_from_auth_hits,
    promoted_path_candidates_from_auth_hits,
)
from penage.utils.html_forms import extract_forms
from penage.utils.html_paths import extract_paths


@dataclass(slots=True)
class ObservationStateProjector:
    action_recorder: ActionStateRecorder
    research_state: ResearchStateSyncer

    def project(self, st: State, action: Action, obs: Observation) -> None:
        action_family = self.action_recorder.record(st, action)

        if action.type in (ActionType.SHELL, ActionType.PYTHON) and obs.ok and isinstance(obs.data, dict):
            self._project_sandbox_json(st, action, obs)
            return

        if action.type == ActionType.MACRO and isinstance(obs.data, dict):
            self._project_macro_result(st, obs)
            return

        if action.type == ActionType.HTTP and obs.data:
            self._project_http_result(st, action_family=action_family, obs=obs)

    def _project_sandbox_json(self, st: State, action: Action, obs: Observation) -> None:
        stdout = obs.data.get("stdout")
        if not isinstance(stdout, str):
            return
        s = stdout.strip()
        if not (s.startswith("{") and s.endswith("}")):
            return

        try:
            obj = json.loads(s)
        except Exception:
            return
        if not isinstance(obj, dict):
            return

        auth_hits = obj.get("auth_hits")
        if isinstance(auth_hits, list):
            self._project_auth_confusion_hits(st, auth_hits)
            stats = obj.get("stats")
            if isinstance(stats, dict):
                st.auth.confusion_last_stats = stats

        before = len(st.known_paths)

        paths = obj.get("paths")
        if isinstance(paths, list):
            st.known_paths |= {p for p in paths if isinstance(p, str) and p}
        after = len(st.known_paths)

        ids = obj.get("ids")
        if isinstance(ids, list):
            page_ids = [x for x in ids if isinstance(x, str)][:40]
            st.page_ids = page_ids
            if page_ids:
                from penage.core.state_helpers import dedup_keep_order

                st.best_http_ids = dedup_keep_order(st.best_http_ids + page_ids, limit=40)

        tags = list(getattr(action, "tags", None) or [])
        if "curl" in tags and "recon" in tags:
            self._project_curl_recon(st, action=action, obj=obj, before=before, after=after)
        if "research" in tags and "fuzz" in tags:
            self._project_research_fuzz(st, action=action)

    def _project_auth_confusion_hits(self, st: State, auth_hits: list[dict[str, object]]) -> None:
        st.auth.confusion_runs += 1
        st.auth.confusion_last_step = st.orch_step
        st.auth.confusion_last_hits_preview = auth_hits[:10]

        winning_ids = promoted_ids_from_auth_hits(auth_hits)
        winning_targets = promoted_path_candidates_from_auth_hits(auth_hits)

        if winning_ids:
            st.auth.confusion_winning_ids = winning_ids[:8]

        if winning_ids or winning_targets:
            self.research_state.promote_confirmed_pivot(
                st,
                ids=winning_ids,
                targets=winning_targets,
                source="auth_confusion",
                reason="confirmed differential state transition from replayed auth/session pivot",
                ttl_steps=6,
            )

        bad_form_actions = list(st.auth.confusion_bad_form_actions)
        bad_seen = set(str(x) for x in bad_form_actions)

        for hit in auth_hits:
            if not isinstance(hit, dict):
                continue
            form_action = str(hit.get("form_action") or "").strip()
            post_location = str(hit.get("post_location") or "").strip().lower()
            set_cookie = bool(hit.get("set_cookie"))
            improved = hit.get("improved_targets") or []

            weak_error_redirect = (
                post_location.startswith("/?error=")
                or "user+not+found" in post_location
                or "incorrect+password" in post_location
            )
            if form_action and weak_error_redirect and not set_cookie and not improved:
                if form_action not in bad_seen:
                    bad_seen.add(form_action)
                    bad_form_actions.append(form_action)

        if bad_form_actions:
            st.auth.confusion_bad_form_actions = bad_form_actions[:16]

    def _project_curl_recon(self, st: State, *, action: Action, obj: dict, before: int, after: int) -> None:
        st.curl_recon.runs += 1
        st.curl_recon.last_step = st.orch_step

        stats = obj.get("stats") if isinstance(obj.get("stats"), dict) else {}
        asset_like = int(stats.get("asset_like") or 0) if isinstance(stats, dict) else 0
        paths_total = int(stats.get("paths_total") or 0) if isinstance(stats, dict) else 0

        new_paths_added = max(0, after - before)
        only_assets = paths_total > 0 and asset_like >= paths_total
        if new_paths_added <= 0 or only_assets:
            st.curl_recon.useless_streak += 1
        else:
            st.curl_recon.useless_streak = 0

    def _project_research_fuzz(self, st: State, *, action: Action) -> None:
        st.research_tracking.fuzz_runs += 1
        st.research_tracking.last_fuzz_step = st.orch_step
        cmd = (action.params or {}).get("command")
        if isinstance(cmd, str) and cmd:
            st.research_tracking.last_fuzz_fp = str(hash(cmd))

    def _project_macro_result(self, st: State, obs: Observation) -> None:
        st.macro.last_result = obs.data

        paths = obs.data.get("paths") or []
        if isinstance(paths, list):
            for p in paths:
                if isinstance(p, str) and p:
                    st.known_paths.add(p)

        macro_name = str(obs.data.get("macro_name") or "")
        if macro_name:
            st.macro.last_name = macro_name

        if macro_name == "replay_auth_session":
            if bool(obs.data.get("session_established")):
                st.auth.session_established = True

            hits = obs.data.get("meaningful_hits") or []
            if isinstance(hits, list):
                st.macro.auth_followup_hits_preview = hits[:8]

        if macro_name == "follow_authenticated_branch":
            hits = obs.data.get("hits") or []
            if isinstance(hits, list):
                st.macro.followup_hits_preview = hits[:8]

            rec = obs.data.get("recommended_next") or []
            if isinstance(rec, list):
                st.macro.followup_recommended_next = rec[:8]

        if macro_name == "probe_resource_family":
            hits = obs.data.get("hits") or []
            if isinstance(hits, list):
                st.macro.family_hits_preview = hits[:8]

            rec = obs.data.get("recommended_next") or []
            if isinstance(rec, list):
                st.macro.family_recommended_next = rec[:8]

    def _project_http_result(self, st: State, *, action_family: str, obs: Observation) -> None:
        st.last_http_status = obs.data.get("status_code")
        st.last_http_url = obs.data.get("url")
        st.last_http_excerpt = obs.data.get("text_excerpt")
        full = obs.data.get("text_full")
        full_s = full if isinstance(full, str) else ""

        headers = obs.data.get("headers") or {}
        content_type = str(headers.get("content-type") or "").lower()
        is_login_gate_http = looks_like_login_gate_http_page(
            full_s or (st.last_http_excerpt or ""),
            str(st.last_http_url or ""),
            content_type,
        )
        is_static_http = looks_like_static_http_url(str(st.last_http_url or "")) or content_type.startswith(
            STATIC_CONTENT_TYPE_PREFIXES
        )

        st.last_http_text_full = full_s

        html_for_extraction = full_s or (st.last_http_excerpt or "")
        before = len(st.known_paths)

        st.known_paths |= extract_paths(html_for_extraction)
        paths = obs.data.get("paths")
        if isinstance(paths, list):
            st.known_paths |= {p for p in paths if isinstance(p, str) and p}

        after = len(st.known_paths)
        st.known_paths_count_prev = before

        base = st.base_url or st.last_http_url or ""
        forms = extract_forms(html_for_extraction)
        st.last_forms = []

        for f in forms:
            action_url = f.action
            if base:
                action_url = urljoin(base, f.action) if f.action else (st.last_http_url or base)

            st.last_forms.append(
                {
                    "method": f.method,
                    "action": action_url,
                    "inputs": [
                        {
                            "name": i.name,
                            "type": i.type,
                            "value": i.value,
                            "required": i.required,
                            "hidden": i.hidden,
                        }
                        for i in f.inputs
                    ],
                }
            )

        if st.last_http_url:
            st.forms_by_url[st.last_http_url] = st.last_forms
        st.http_requests_used += 1
        text_len = obs.data.get("text_len")
        if isinstance(text_len, int):
            st.total_text_len_seen += text_len
        elif full_s:
            st.total_text_len_seen += len(full_s)

        if after <= before:
            st.no_new_paths_streak += 1
        else:
            st.no_new_paths_streak = 0
        status = int(st.last_http_status or 0)
        score = self._http_score(full_s=full_s, status=status, is_login_gate_http=is_login_gate_http, is_static_http=is_static_http)

        ids_u = [] if (is_static_http or is_login_gate_http) else extract_numeric_ids(full_s, limit=40)

        if (not is_static_http) and (not is_login_gate_http) and score >= float(getattr(st, "best_http_score", 0.0) or 0.0) + 0.25:
            st.best_http_score = score
            st.best_http_url = st.last_http_url
            st.best_http_text_full = full_s[:120000]
            st.best_http_ids = ids_u
            st.best_http_paths = sorted(list(st.known_paths))[:200]

        if (not is_static_http) and (not is_login_gate_http) and ids_u and not st.best_http_ids:
            st.best_http_ids = ids_u[:40]

        self.research_state.record_recent_http_memory(
            st,
            url=str(st.last_http_url or ""),
            status=st.last_http_status,
            excerpt=st.last_http_excerpt or full_s,
            paths_preview=sorted(list(st.known_paths))[:20],
            forms_preview=st.last_forms,
        )

        self.research_state.record_negative_http_result(
            st,
            url=str(st.last_http_url or ""),
            status=st.last_http_status,
            action_family=action_family,
            excerpt=st.last_http_excerpt or full_s,
            had_new_paths=(after > before),
            had_forms=bool(st.last_forms),
        )

    def _http_score(self, *, full_s: str, status: int, is_login_gate_http: bool, is_static_http: bool) -> float:
        score = 0.0
        if status == 200:
            score += 10.0
        elif status in (301, 302, 303, 307, 308):
            score += 6.0
        elif status in (401, 403):
            score += 3.0
        else:
            score += 0.5

        score += min(8.0, len(full_s) / 1200.0)

        low = full_s.lower()
        for kw in ("data-order-id", "/order/", "/receipt", "flag{", "flag", "admin", "debug", "xss"):
            if kw in low:
                score += 2.5
        if is_login_gate_http:
            score -= 8.0
        if is_static_http:
            score -= 12.0
        return score