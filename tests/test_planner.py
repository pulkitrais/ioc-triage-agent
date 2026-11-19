from triage_agent.llm import LLMError, ScriptedLLM
from triage_agent.planner import Planner, check_steps, fallback_plan


def test_check_steps_flags_unknown_tool_and_missing_args(registry):
    steps = [
        {"id": "s1", "tool": "otx_lookup", "args": {"indicator": "1.2.3.4", "junk": 1}},
        {"id": "s2", "tool": "virustotal", "args": {"x": 1}},
        {"id": "s3", "tool": "internetdb_lookup", "args": {}},
    ]
    good, problems = check_steps(steps, registry)
    assert [s["id"] for s in good] == ["s1"]
    assert "junk" not in good[0]["args"]  # unknown args are dropped
    assert len(problems) == 2


def test_planner_asks_llm_to_fix_a_bad_plan(registry, trace):
    bad = {"understanding": "u", "steps": [{"id": "s1", "tool": "made_up", "args": {}}]}
    good = {"understanding": "u", "steps": [{"id": "s1", "tool": "otx_lookup", "args": {"indicator": "1.2.3.4"}}]}
    llm = ScriptedLLM([bad, good])
    plan = Planner(llm, registry, trace).make_plan("is 1.2.3.4 bad?")
    assert [p for p, _ in llm.prompts] == ["plan", "plan-fix"]
    assert plan["steps"][0]["tool"] == "otx_lookup"
    assert plan["source"] == "llm"


def test_planner_uses_rule_based_plan_when_llm_is_down(registry, trace):
    llm = ScriptedLLM([LLMError("503")])
    plan = Planner(llm, registry, trace).make_plan("Investigate 45.9.148.10")
    assert plan["source"] == "fallback"
    assert any(s["tool"] == "otx_lookup" for s in plan["steps"])


def test_ambiguous_goal_returns_question_not_steps(registry, trace):
    llm = ScriptedLLM([{"clarification_needed": "Which IP or domain?", "steps": [{"tool": "web_search"}]}])
    plan = Planner(llm, registry, trace).make_plan("check that thing from earlier")
    assert plan["clarification_needed"] == "Which IP or domain?"
    assert plan["steps"] == []


def test_fallback_plan_for_news_goal():
    plan = fallback_plan("summarize the top security developments this week")
    assert plan["task_type"] == "news_summary"
    assert {s["tool"] for s in plan["steps"]} == {"kev_recent", "web_search"}


def test_reflect_skips_calls_that_already_succeeded(registry, trace):
    from triage_agent.memory import Memory, StepResult

    mem = Memory(goal="g")
    mem.add(StepResult("s1", "otx_lookup", {"indicator": "1.2.3.4"}, True, output={"pulse_count": 1}))
    reply = {"done": False, "reason": "need more", "new_steps": [
        {"id": "r1", "tool": "otx_lookup", "args": {"indicator": "1.2.3.4"}},
        {"id": "r2", "tool": "internetdb_lookup", "args": {"ip": "1.2.3.4"}},
    ]}
    new = Planner(ScriptedLLM([reply]), registry, trace).reflect("g", {}, mem, budget=3)
    assert [s["tool"] for s in new] == ["internetdb_lookup"]
