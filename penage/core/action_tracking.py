from __future__ import annotations

from dataclasses import dataclass

from penage.core.actions import Action
from penage.core.state import State
from penage.core.state_helpers import action_family
from penage.utils.fingerprint import action_fingerprint


@dataclass(slots=True)
class ActionStateRecorder:
    def record(self, st: State, action: Action) -> str:
        fp = action_fingerprint(action)
        st.visited_actions_fingerprint.add(fp)

        fam = action_family(action)
        prev = st.last_action_family
        if fam == prev:
            st.same_action_family_streak += 1
        else:
            st.same_action_family_streak = 1
        st.last_action_family = fam
        st.action_family_counts[fam] = int(st.action_family_counts.get(fam) or 0) + 1
        return fam