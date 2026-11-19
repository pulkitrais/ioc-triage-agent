import time

from triage_agent.executor import Executor, FailureInjector, ToolTimeout, call_with_timeout
from triage_agent.llm import LLMError, ScriptedLLM
from triage_agent.memory import Memory

import pytest


def test_call_with_timeout_gives_up_on_hung_call():
    started = time.time()
    with pytest.raises(ToolTimeout):
        call_with_timeout(lambda: time.sleep(5), {}, timeout=0.3)
    assert time.time() - started < 2


def test_simulated_timeout_triggers_llm_recovery(registry, trace):
    llm = ScriptedLLM([{"action": "use_tool", "tool": "web_search", "args": {"query": "1.2.3.4 abuse"},
                        "reason": "OTX is down, search for reports instead"}])
    ex = Executor(registry, trace, llm=llm, retries=1, backoff=0,
                  injector=FailureInjector("timeout", "otx_lookup"), timeout_override=0.2)
    mem = Memory(goal="is 1.2.3.4 bad")
    result = ex.run_step({"id": "s1", "tool": "otx_lookup", "args": {"indicator": "1.2.3.4"}}, mem)
    assert result.ok and result.tool == "web_search" and result.recovered_from == "s1"
    first = mem.get("s1")
    assert not first.ok and first.attempts == 2 and "timeout" in first.error


def test_bad_response_only_once_is_fixed_by_retry(registry, trace):
    ex = Executor(registry, trace, llm=None, retries=1, backoff=0,
                  injector=FailureInjector("bad_response", "otx_lookup", times=1))
    mem = Memory(goal="g")
    result = ex.run_step({"id": "s1", "tool": "otx_lookup", "args": {"indicator": "1.2.3.4"}}, mem)
    assert result.ok and result.attempts == 2
    assert len(mem.results) == 1


def test_static_fallback_when_llm_is_unavailable(registry, trace):
    llm = ScriptedLLM([LLMError("all models failed")])
    ex = Executor(registry, trace, llm=llm, retries=0, backoff=0)
    mem = Memory(goal="g")
    result = ex.run_step({"id": "s1", "tool": "broken_tool", "args": {"ip": "1.2.3.4"}}, mem)
    assert result.tool == "internetdb_lookup" and result.ok


def test_llm_can_choose_to_skip(registry, trace):
    llm = ScriptedLLM([{"action": "skip", "reason": "not needed"}])
    ex = Executor(registry, trace, llm=llm, retries=0, backoff=0)
    mem = Memory(goal="g")
    result = ex.run_step({"id": "s1", "tool": "broken_tool", "args": {"ip": "1.2.3.4"}}, mem)
    assert not result.ok and len(mem.results) == 1


def test_identical_retry_suggestion_is_not_accepted(registry, trace):
    # the LLM suggests the exact call that just failed; we should use the static fallback instead
    llm = ScriptedLLM([{"action": "retry_with", "args": {"ip": "1.2.3.4"}, "reason": "try again"}])
    ex = Executor(registry, trace, llm=llm, retries=0, backoff=0)
    result = ex.run_step({"id": "s1", "tool": "broken_tool", "args": {"ip": "1.2.3.4"}}, Memory(goal="g"))
    assert result.tool == "internetdb_lookup"


def test_recovery_that_duplicates_a_planned_step_is_replaced(registry, trace):
    # internetdb is already step s2 in the plan, so suggesting it as the recovery for s1 adds nothing
    llm = ScriptedLLM([{"action": "use_tool", "tool": "internetdb_lookup", "args": {"ip": "1.2.3.4"}, "reason": "x"}])
    ex = Executor(registry, trace, llm=llm, retries=0, backoff=0,
                  injector=FailureInjector("bad_response", "otx_lookup"))
    plan = [{"id": "s1", "tool": "otx_lookup", "args": {"indicator": "1.2.3.4"}},
            {"id": "s2", "tool": "internetdb_lookup", "args": {"ip": "1.2.3.4"}}]
    ex.remember(plan)
    result = ex.run_step(plan[0], Memory(goal="g"))
    assert result.tool == "web_search"  # the static fallback for otx_lookup


def test_search_results_that_ignore_the_indicator_trigger_recovery(registry, trace):
    # the fake search returns a page that never mentions 9.9.9.9, so the step should count as failed
    registry["web_search"].func = lambda **kw: {"results": [{"title": "Threat Intel Platform", "url": "https://vendor.example"}]}
    llm = ScriptedLLM([{"action": "skip", "reason": "nothing better"}])
    ex = Executor(registry, trace, llm=llm, retries=2, backoff=0)
    mem = Memory(goal="g")
    result = ex.run_step({"id": "s1", "tool": "web_search", "args": {"query": "9.9.9.9 threat intel"}}, mem)
    assert not result.ok and "unexpected result" in result.error
    assert result.attempts == 1  # no pointless retries of the same query
