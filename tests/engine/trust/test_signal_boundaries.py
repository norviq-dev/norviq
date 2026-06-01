from datetime import datetime, timedelta, timezone

from norviq.engine.trust.models import TrustInput
from norviq.engine.trust.signals.chain_depth import ChainDepthSignal
from norviq.engine.trust.signals.param_entropy import ParamEntropySignal
from norviq.engine.trust.signals.scope_drift import ScopeDriftSignal
from norviq.engine.trust.signals.session_velocity import SessionVelocitySignal
from norviq.engine.trust.signals.time_decay import TimeDecaySignal
from norviq.engine.trust.signals.tool_novelty import ToolNoveltySignal
from norviq.engine.trust.signals.violation_rate import ViolationRateSignal


def _input(tool_name: str = "search_kb", depth: int = 0) -> TrustInput:
    return TrustInput("spiffe://a", "ns", "support", tool_name, {"q": "x"}, "s", depth, datetime.now(timezone.utc))


async def test_violation_rate_boundary_20_percent_is_low_bucket() -> None:
    signal = ViolationRateSignal()
    history = [{"decision": "block"}] * 2 + [{"decision": "allow"}] * 8
    assert await signal.compute(_input(), history, {}) == 0.2


async def test_tool_novelty_known_tool_high_bucket_boundary() -> None:
    signal = ToolNoveltySignal()
    history = [{"tool_name": "search_kb"}] * 9 + [{"tool_name": "new_tool"}]
    assert await signal.compute(_input("search_kb"), history, {"known_tools": ["search_kb"]}) == 1.0


async def test_scope_drift_allowed_tool_returns_one() -> None:
    signal = ScopeDriftSignal()
    assert await signal.compute(_input("search_kb"), [], {"allowed_tools": ["search_kb"], "blocked_tools": []}) == 1.0


async def test_param_entropy_zscore_two_boundary(monkeypatch) -> None:
    signal = ParamEntropySignal()
    monkeypatch.setattr(ParamEntropySignal, "entropy_of_params", staticmethod(lambda _: 4.0))
    score = await signal.compute(_input("search_kb"), [], {"param_entropy_baseline": {"search_kb": {"mean": 2.0, "std": 1.0}}})
    assert score == 0.7


async def test_time_decay_ten_minute_boundary() -> None:
    signal = TimeDecaySignal()
    ts = datetime.now(timezone.utc) - timedelta(minutes=10)
    assert await signal.compute(_input(), [{"decision": "block", "timestamp": ts.isoformat()}], {}) == 0.2


async def test_chain_depth_boundary_four() -> None:
    signal = ChainDepthSignal()
    assert await signal.compute(_input(depth=4), [], {}) == 0.2


async def test_session_velocity_ratio_two_boundary() -> None:
    signal = SessionVelocitySignal()
    now = datetime.now(timezone.utc)
    history = [{"timestamp": (now - timedelta(seconds=1)).isoformat()} for _ in range(19)]
    assert await signal.compute(_input(), history, {"baseline_rpm": 10.0}) == 0.8
