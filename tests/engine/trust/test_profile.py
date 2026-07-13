from norviq.engine.trust.profile import AgentProfileStore


class _PipelineStub:
    def __init__(self, responses):
        self._responses = responses
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        _ = exc_type, exc, tb
        return False

    async def hgetall(self, key: str) -> None:
        self.calls.append(key)

    async def execute(self):
        return self._responses


class _ClientStub:
    def __init__(self) -> None:
        self.script_load_calls = 0
        self.evalsha_calls = 0
        self.evalsha_values: list[tuple] = []

    def pipeline(self, transaction: bool = False):
        _ = transaction
        return _PipelineStub(
            [
                {"known_tools": '["search_kb"]', "baseline_rpm": "12.0"},
                {"allowed_tools": '["search_kb"]', "blocked_tools": '["danger"]'},
            ]
        )

    async def hgetall(self, key: str) -> dict[str, str]:
        _ = key
        return {}

    async def script_load(self, script: str) -> str:
        _ = script
        self.script_load_calls += 1
        return "sha-1" if self.script_load_calls == 1 else "sha-2"

    async def evalsha(self, sha: str, *args):
        self.evalsha_calls += 1
        self.evalsha_values.append((sha, args))
        if self.evalsha_calls == 1:
            raise RuntimeError("NOSCRIPT No matching script. Please use EVAL.")
        return 1


class _CacheStub:
    def __init__(self) -> None:
        self.client = _ClientStub()

    def _client(self) -> _ClientStub:
        return self.client


async def test_get_profile_uses_seven_day_window_and_single_pipeline() -> None:
    store = AgentProfileStore(_CacheStub())  # type: ignore[arg-type]
    profile = await store.get_profile("spiffe://a", "support")
    assert store.WINDOW_SECONDS == 604800
    assert profile["known_tools"] == ["search_kb"]
    assert profile["allowed_tools"] == ["search_kb"]
    assert profile["blocked_tools"] == ["danger"]


async def test_update_profile_recovers_from_noscript() -> None:
    cache = _CacheStub()
    store = AgentProfileStore(cache)  # type: ignore[arg-type]
    await store.update_profile("spiffe://a", "search_kb", 2.5, 16.0, "allow")
    assert cache.client.script_load_calls == 2
    assert cache.client.evalsha_calls == 2
