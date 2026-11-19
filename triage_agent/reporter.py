"""Builds the final report and checks it against the evidence.

The LLM writes the summary and findings, and every finding has to cite the
step ids it is based on. After that I run a plain-Python self-check: a finding
that cites a failed or non-existent step is marked unsupported, and the
confidence is lowered when a lot of the evidence is missing. I added this
after seeing the model state things "according to OTX" in a run where the OTX
call had timed out.
"""

import json
from datetime import datetime

from .llm import LLMError

REPORT_PROMPT = """You are writing the final report for a SOC analyst. Today's date is {today}.

Goal: \"\"\"{goal}\"\"\"
What the plan set out to do: {understanding}
Assumptions: {assumptions}

Evidence collected (step id, tool, result). Failed steps are marked FAILED:
{evidence}

Write a short, factual report in plain language, the way an analyst writes a ticket note.
Rules:
- Only state things the evidence shows. Every finding must list the step ids it is based on in
  "evidence", using the exact ids shown above (like s2 or r1.3). Don't repeat the ids in the text.
- If a source failed, put that in gaps, not in findings, and don't guess what it would have said.
- Weigh context: shared infrastructure (cloud hosting, Tor, VPN) and old reports are not the same as current malicious use.
- verdict: "malicious", "suspicious", "benign" or "unknown" is only for indicators (IP, domain, hash).
  For CVE questions and news goals use "n/a" and put severity and exploitation status in the summary.
- For news goals, each finding is one development with its source URL in the text.

Reply with JSON only:
{{"verdict": "...", "confidence": "low | medium | high",
  "summary": "2-4 sentences",
  "findings": [{{"text": "...", "evidence": ["s1"]}}],
  "recommendations": ["..."],
  "gaps": ["what could not be checked and why"]}}
"""

CONFIDENCE_ORDER = ["low", "medium", "high"]


def self_check(report, memory):
    """Cross-check the report against what actually ran. Returns a dict and adjusts report in place."""
    ok_ids = {r.step_id for r in memory.succeeded()}
    all_ids = {r.step_id for r in memory.results}
    supported, unsupported = 0, []
    for f in report.get("findings", []):
        cited = [str(e) for e in f.get("evidence", [])]
        good = [c for c in cited if c in ok_ids]
        if good:
            supported += 1
            f["supported"] = True
        else:
            f["supported"] = False
            reason = "cites no evidence" if not cited else (
                "cites failed steps" if any(c in all_ids for c in cited) else "cites unknown steps")
            unsupported.append({"finding": f.get("text", "")[:100], "reason": reason})

    total = len(memory.results)
    failed = len(memory.failed())
    recovered = sum(1 for r in memory.results if r.recovered_from and r.ok)
    # a failure that a later step made up for isn't really missing evidence
    recovered_ids = {r.recovered_from for r in memory.results if r.recovered_from and r.ok}
    unrecovered = [r for r in memory.failed() if r.step_id not in recovered_ids and not r.recovered_from]
    notes = []
    conf = report.get("confidence", "low")
    if conf not in CONFIDENCE_ORDER:
        conf = "low"
    # lose one confidence level if a third or more of the planned steps failed with
    # no recovery, and another if any finding isn't backed by a successful step
    planned = [r for r in memory.results if not r.recovered_from]
    if planned and len(unrecovered) / len(planned) >= 1 / 3 and conf != "low":
        conf = CONFIDENCE_ORDER[CONFIDENCE_ORDER.index(conf) - 1]
        notes.append(f"confidence lowered: {len(unrecovered)} of {len(planned)} planned steps failed without a recovery")
    if unsupported and conf != "low":
        conf = CONFIDENCE_ORDER[CONFIDENCE_ORDER.index(conf) - 1]
        notes.append("confidence lowered: some findings are not backed by a successful step")
    if report.get("verdict") in ("malicious", "benign") and len(memory.succeeded()) < 2:
        notes.append("a firm verdict rests on fewer than two successful sources")
    report["confidence"] = conf

    return {
        "tool_calls": total,
        "failed_calls": failed,
        "unrecovered_failures": len(unrecovered),
        "recovered_steps": recovered,
        "findings_supported": supported,
        "findings_unsupported": unsupported,
        "notes": notes,
        # "passed" means every finding is backed by a successful step; notes are extra context
        "passed": not unsupported,
    }


def fallback_report(memory):
    """Plain report from raw results, used when the LLM can't write one."""
    findings = []
    for r in memory.succeeded():
        findings.append({"text": f"{r.tool}: {json.dumps(r.output, default=str)[:240]}", "evidence": [r.step_id]})
    return {
        "verdict": "unknown",
        "confidence": "low",
        "summary": "The LLM was unavailable for the write-up, so this report lists the raw results for a human to read.",
        "findings": findings,
        "recommendations": ["Review the raw results below manually."],
        "gaps": [f"{r.tool} failed: {r.error}" for r in memory.failed()],
    }


class Reporter:
    def __init__(self, llm, trace):
        self.llm = llm
        self.trace = trace

    def build(self, memory, plan, status="completed"):
        prompt = REPORT_PROMPT.format(
            today=datetime.now().date().isoformat(), goal=memory.goal,
            understanding=plan.get("understanding", ""), assumptions=json.dumps(plan.get("assumptions", [])),
            evidence=memory.evidence_for_llm(max_chars=2500),
        )
        try:
            report = self.llm.generate_json(prompt, purpose="report")
            if not isinstance(report, dict) or "summary" not in report:
                raise LLMError("report reply missing summary")
            report.setdefault("findings", [])
        except LLMError as e:
            self.trace.event("fallback", f"report LLM unavailable ({e}); writing a raw-results report")
            report = fallback_report(memory)
        check = self_check(report, memory)
        if check["findings_unsupported"]:
            report, check = self._repair(prompt, report, check, memory)
        self.trace.event("selfcheck",
                         f"{check['findings_supported']} supported / {len(check['findings_unsupported'])} unsupported findings, "
                         f"{check['failed_calls']} failed calls, {check['recovered_steps']} recovered"
                         + (f"; {'; '.join(check['notes'])}" if check["notes"] else ""), check=check)
        return assemble(memory, plan, report, check, status)


    def _repair(self, prompt, report, check, memory):
        """One round of self-correction: show the model its unsupported findings and ask for a fix."""
        ok_ids = ", ".join(r.step_id for r in memory.succeeded())
        problems = "\n".join(f"- \"{u['finding']}\": {u['reason']}" for u in check["findings_unsupported"])
        self.trace.event("check", f"{len(check['findings_unsupported'])} finding(s) not backed by a successful step, "
                                  "asking the model to fix the report", problems=check["findings_unsupported"])
        fix_prompt = (prompt + "\n\nYour draft report:\n" + json.dumps(report) +
                      f"\n\nThese findings are not backed by a successful step:\n{problems}\n"
                      f"Successful step ids are: {ok_ids}. Fix the evidence ids, or move the point to gaps "
                      "if no successful step supports it. Return the full corrected report as JSON.")
        try:
            fixed = self.llm.generate_json(fix_prompt, purpose="report-fix")
            if not isinstance(fixed, dict) or "summary" not in fixed:
                raise LLMError("fixed report missing summary")
        except LLMError as e:
            self.trace.event("check", f"report fix failed ({e}), keeping the draft with its warnings")
            return report, check
        fixed.setdefault("findings", [])
        new_check = self_check(fixed, memory)
        if len(new_check["findings_unsupported"]) < len(check["findings_unsupported"]):
            new_check["notes"].insert(0, f"report revised once: {len(check['findings_unsupported'])} unsupported "
                                         f"finding(s) before the fix, {len(new_check['findings_unsupported'])} after")
            return fixed, new_check
        return report, check


def assemble(memory, plan, report, check, status):
    return {
        "goal": memory.goal,
        "status": status,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "plan": {k: plan.get(k) for k in ("understanding", "task_type", "assumptions", "done_when", "source")}
        | {"steps": plan.get("steps", [])},
        "result": report,
        "self_check": check,
        "steps": [
            {"id": r.step_id, "tool": r.tool, "args": r.args, "ok": r.ok, "attempts": r.attempts,
             "seconds": r.seconds, "error": r.error, "recovered_from": r.recovered_from}
            for r in memory.results
        ],
        "sources": collect_sources(memory, report),
    }


def collect_sources(memory, report=None):
    """Search URLs, with the ones the report actually mentions first.

    News search returns some junk (one run pulled in an NFL page), so if the
    report cites URLs I only list those.
    """
    urls = []
    for r in memory.succeeded():
        if r.tool == "web_search":
            for row in r.output.get("results", []):
                if row.get("url") and row["url"] not in urls:
                    urls.append(row["url"])
    text = json.dumps(report or {})
    cited = [u for u in urls if u in text]
    return cited if cited else urls[:8]


def to_markdown(doc):
    res = doc["result"]
    lines = [f"# Triage report", "", f"**Goal:** {doc['goal']}", ""]
    if doc["status"] == "needs_clarification":
        lines += [f"**Status:** stopped, needs clarification", "", res.get("summary", ""), ""]
        return "\n".join(lines)
    lines += [
        f"**Verdict:** {res.get('verdict', 'unknown')} (confidence: {res.get('confidence', 'low')})  ",
        f"**Generated:** {doc['generated_at']}", "",
        "## Summary", "", res.get("summary", ""), "",
        "## Findings", "",
    ]
    for f in res.get("findings", []):
        mark = "" if f.get("supported", True) else " _(not backed by a successful step)_"
        lines.append(f"- {f.get('text', '')} [{', '.join(map(str, f.get('evidence', [])))}]{mark}")
    if res.get("recommendations"):
        lines += ["", "## Recommendations", ""] + [f"- {r}" for r in res["recommendations"]]
    if res.get("gaps"):
        lines += ["", "## Gaps", ""] + [f"- {g}" for g in res["gaps"]]

    lines += ["", "## What the agent did", "", "| step | tool | args | result | attempts | time |", "|---|---|---|---|---|---|"]
    for s in doc["steps"]:
        outcome = "ok" if s["ok"] else f"failed: {s['error']}"
        if s["recovered_from"]:
            outcome += f" (recovery for {s['recovered_from']})"
        args = json.dumps(s["args"]).replace("|", "/")
        lines.append(f"| {s['id']} | {s['tool']} | `{args}` | {outcome} | {s['attempts']} | {s['seconds']}s |")

    chk = doc["self_check"]
    lines += ["", "## Self-check", "",
              f"- tool calls: {chk['tool_calls']}, failed: {chk['failed_calls']}, recovered: {chk['recovered_steps']}, "
              f"failed with no recovery: {chk.get('unrecovered_failures', 0)}",
              f"- findings backed by evidence: {chk['findings_supported']}, not backed: {len(chk['findings_unsupported'])}"]
    lines += [f"- {n}" for n in chk["notes"]]
    lines.append(f"- result: {'passed' if chk['passed'] else 'see notes above'}")
    if doc["sources"]:
        lines += ["", "## Sources", ""] + [f"- {u}" for u in doc["sources"]]
    return "\n".join(lines) + "\n"
