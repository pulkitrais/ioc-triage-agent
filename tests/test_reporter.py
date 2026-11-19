from triage_agent.llm import LLMError, ScriptedLLM
from triage_agent.memory import Memory, StepResult
from triage_agent.reporter import Reporter, self_check, to_markdown


def _memory():
    mem = Memory(goal="is 1.2.3.4 bad")
    mem.add(StepResult("s1", "otx_lookup", {"indicator": "1.2.3.4"}, False, error="timeout"))
    mem.add(StepResult("s1b", "web_search", {"query": "1.2.3.4"}, True,
                       output={"results": [{"url": "https://example.org/x"}]}, recovered_from="s1"))
    mem.add(StepResult("s2", "internetdb_lookup", {"ip": "1.2.3.4"}, True, output={"found": True}))
    return mem


def test_self_check_flags_findings_that_cite_failed_steps():
    report = {"verdict": "malicious", "confidence": "high", "findings": [
        {"text": "OTX lists it in 40 pulses", "evidence": ["s1"]},
        {"text": "Port 22 is open", "evidence": ["s2"]},
    ]}
    check = self_check(report, _memory())
    assert check["findings_supported"] == 1
    assert check["findings_unsupported"][0]["reason"] == "cites failed steps"
    assert check["recovered_steps"] == 1
    assert check["unrecovered_failures"] == 0  # s1 failed but s1b covered it
    assert report["confidence"] == "medium"  # lowered once for the unsupported finding
    assert not check["passed"]


def test_unrecovered_failures_lower_confidence():
    mem = Memory(goal="g")
    mem.add(StepResult("s1", "otx_lookup", {"indicator": "x"}, False, error="timeout"))
    mem.add(StepResult("s2", "internetdb_lookup", {"ip": "x"}, True, output={"found": True}))
    report = {"verdict": "suspicious", "confidence": "high", "findings": [{"text": "a", "evidence": ["s2"]}]}
    check = self_check(report, mem)
    assert report["confidence"] == "medium" and check["unrecovered_failures"] == 1


def test_reporter_falls_back_to_raw_results(trace):
    doc = Reporter(ScriptedLLM([LLMError("down")]), trace).build(_memory(), {"steps": []})
    assert doc["result"]["verdict"] == "unknown"
    assert doc["sources"] == ["https://example.org/x"]
    md = to_markdown(doc)
    assert "## What the agent did" in md and "recovery for s1" in md


def test_sources_prefer_urls_the_report_cites():
    from triage_agent.reporter import collect_sources

    mem = Memory(goal="g")
    mem.add(StepResult("s1", "web_search", {"query": "q"}, True, output={"results": [
        {"url": "https://news.example/a"}, {"url": "https://sports.example/nfl"}]}))
    assert collect_sources(mem, {"findings": [{"text": "see https://news.example/a"}]}) == ["https://news.example/a"]
    assert len(collect_sources(mem, {"findings": []})) == 2


def test_reporter_fixes_unsupported_findings_once(trace):
    draft = {"verdict": "suspicious", "confidence": "medium", "summary": "x",
             "findings": [{"text": "port 22 open", "evidence": ["s3"]}]}  # s3 doesn't exist
    fixed = {"verdict": "suspicious", "confidence": "medium", "summary": "x",
             "findings": [{"text": "port 22 open", "evidence": ["s2"]}]}
    llm = ScriptedLLM([draft, fixed])
    doc = Reporter(llm, trace).build(_memory(), {"steps": []})
    assert [p for p, _ in llm.prompts] == ["report", "report-fix"]
    assert doc["self_check"]["findings_unsupported"] == []
    assert "report revised once" in doc["self_check"]["notes"][0]
