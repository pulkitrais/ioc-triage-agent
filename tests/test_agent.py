from triage_agent.agent import TriageAgent, save_outputs
from triage_agent.executor import FailureInjector
from triage_agent.llm import ScriptedLLM


def scripted(purpose, prompt):
    if purpose == "plan":
        return {"understanding": "check 1.2.3.4", "task_type": "ioc_investigation", "clarification_needed": None,
                "assumptions": [], "done_when": "verdict",
                "steps": [{"id": "s1", "tool": "otx_lookup", "args": {"indicator": "1.2.3.4"}, "why": "rep"},
                          {"id": "s2", "tool": "internetdb_lookup", "args": {"ip": "1.2.3.4"}, "why": "ports"}]}
    if purpose == "recover":
        return {"action": "use_tool", "tool": "web_search", "args": {"query": "1.2.3.4 malicious"}, "reason": "OTX down"}
    if purpose == "reflect":
        return {"done": True, "reason": "enough"}
    if purpose in ("report", "report-fix"):
        return {"verdict": "suspicious", "confidence": "medium", "summary": "Seen scanning.",
                "findings": [{"text": "web reports mention scanning", "evidence": ["s1b"]},
                             {"text": "ports 22 and 80 open", "evidence": ["s2"]}],
                "recommendations": ["block"], "gaps": ["OTX timed out"]}
    raise AssertionError(purpose)


def test_full_run_with_induced_timeout(registry, trace, tmp_path):
    agent = TriageAgent(ScriptedLLM(scripted), registry, trace,
                        injector=FailureInjector("timeout", "otx_lookup"), timeout_override=0.2)
    agent.executor.backoff = 0
    doc = agent.run("Is 1.2.3.4 malicious?")
    assert doc["status"] == "completed"
    assert [s["id"] for s in doc["steps"]] == ["s1", "s1b", "s2"]
    assert doc["self_check"]["recovered_steps"] == 1
    out = save_outputs(doc, trace, tmp_path / "run")
    assert (out / "report.md").exists() and (out / "run.jsonl").exists()
    kinds = {e["kind"] for e in trace.events}
    assert {"plan", "tool", "retry", "error", "recover", "selfcheck"} <= kinds


def test_ambiguous_goal_stops_without_calling_tools(registry, trace):
    llm = ScriptedLLM([{"clarification_needed": "Which indicator do you mean?", "steps": []}])
    doc = TriageAgent(llm, registry, trace).run("is it bad?")
    assert doc["status"] == "needs_clarification"
    assert doc["steps"] == []


def test_ambiguous_goal_in_interactive_mode_replans(registry, trace):
    llm = ScriptedLLM(lambda purpose, prompt: (
        {"clarification_needed": "Which IP?", "steps": []} if "Clarification" not in prompt and purpose == "plan"
        else scripted(purpose, prompt)))
    agent = TriageAgent(llm, registry, trace, ask_user=lambda q: "1.2.3.4")
    doc = agent.run("is it bad?")
    assert doc["status"] == "completed"
    assert "Clarification: 1.2.3.4" in doc["goal"]
