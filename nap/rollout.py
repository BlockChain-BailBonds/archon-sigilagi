from dataclasses import dataclass
from enum import Enum
from typing import Callable

class RolloutResult(str, Enum):
    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"

@dataclass(frozen=True)
class Stage:
    percent: int
    observation_seconds: int

DEFAULT_STAGES = (Stage(1, 900), Stage(5, 900), Stage(20, 1800), Stage(50, 1800), Stage(100, 3600))

def execute_progressive_rollout(apply_stage: Callable[[int], None], evaluate_stage: Callable[[int, int], tuple[bool, str]], rollback: Callable[[], None], audit: Callable[[str, dict], None], stages=DEFAULT_STAGES) -> RolloutResult:
    completed = 0
    try:
        for stage in stages:
            audit("rollout_stage_started", {"target_percent": stage.percent, "previous_percent": completed})
            apply_stage(stage.percent)
            healthy, reason = evaluate_stage(stage.percent, stage.observation_seconds)
            audit("rollout_stage_evaluated", {"target_percent": stage.percent, "healthy": healthy, "reason": reason})
            if not healthy:
                rollback(); audit("rollout_rolled_back", {"failed_percent": stage.percent, "last_healthy_percent": completed, "reason": reason}); return RolloutResult.ROLLED_BACK
            completed = stage.percent
        audit("rollout_completed", {"final_percent": completed}); return RolloutResult.COMPLETED
    except Exception as exc:
        rollback(); audit("rollout_exception_rollback", {"last_healthy_percent": completed, "exception_type": type(exc).__name__}); return RolloutResult.ROLLED_BACK

