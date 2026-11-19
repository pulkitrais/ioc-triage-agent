"""Turns a goal into a checked list of tool calls.

The LLM proposes the plan, but I don't trust it blindly: every step is checked
against the tool registry (does the tool exist, are the required args there)
before anything runs. If the plan is broken I send the problems back once and
ask for a fix. If the LLM is down altogether there is a rule-based plan built
from the indicators I can regex out of the goal, so the agent still does
something useful.
"""

import json

from .llm import LLMError
from .tools import describe_tools, extract_indicators

MAX_STEPS = 8

PLAN_PROMPT = """You are the planning part of a security triage agent used by a SOC analyst.
Today's date is {today}.

Goal from the analyst:
\"\"\"{goal}\"\"\"

Indicators a regex found in the goal (may be incomplete): {indicators}

Tools you can use:
{tools}

Write a short plan before anything runs. Rules:
- Use only the tools above, with the argument names shown. Max {max_steps} steps.
- Prefer several independent sources for a verdict (e.g. reputation + infrastructure + registration).
- Each step must be runnable on its own; don't reference outputs of other steps in args.
- If the goal is too vague to act on (no indicator and no clear topic), set clarification_needed
  to one short question and return no steps. Don't guess an indicator.
- Note any assumption you make (for example the time window for "recent").

Reply with JSON only:
{{"understanding": "one sentence, what the analyst wants",
  "task_type": "ioc_investigation | cve_research | news_summary | other",
  "clarification_needed": null,
  "assumptions": ["..."],
  "steps": [{{"id": "s1", "tool": "tool_name", "args": {{}}, "why": "what this tells us"}}],
  "done_when": "what a finished answer must contain"}}
"""

REFLECT_PROMPT = """You are checking the progress of a security triage agent. Today's date is {today}.

Goal: \"\"\"{goal}\"\"\"
Plan understanding: {understanding}
Done when: {done_when}

Results so far:
{evidence}

Tools:
{tools}

Decide if the evidence is enough to answer the goal well. If something important is missing,
or a result raised a new lead (e.g. a domain resolved to an IP worth checking, a CVE was mentioned,
a source failed and nothing replaced it), add up to {budget} new steps. If the goal asks which
CVEs to patch first, cve_lookup gives CVSS and EPSS for ranking. Use the calculator if a
number is needed for the answer (domain age, a score, a percentage). Don't repeat a call that
already succeeded.

Reply with JSON only:
{{"done": true or false, "reason": "short", "new_steps": [{{"id": "r1", "tool": "...", "args": {{}}, "why": "..."}}]}}
"""


def _today():
    from datetime import date

    return date.today().isoformat()


def check_steps(steps, registry):
    """Return (good_steps, problems). A step is good if its tool exists and required args are present."""
    good, problems = [], []
    if not isinstance(steps, list):
        return [], ["'steps' must be a list"]
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            problems.append(f"step {i + 1} is not an object")
            continue
        sid = str(step.get("id") or f"s{i + 1}")
        tool = registry.get(step.get("tool"))
        if tool is None:
            problems.append(f"{sid}: unknown tool {step.get('tool')!r}")
            continue
        args = step.get("args") or {}
        if not isinstance(args, dict):
            problems.append(f"{sid}: args must be an object")
            continue
        required = [k for k, desc in tool.args.items() if "optional" not in desc]
        missing = [k for k in required if k not in args or args[k] in ("", None)]
        unknown = [k for k in args if k not in tool.args]
        if missing:
            problems.append(f"{sid}: {tool.name} is missing required arg(s) {missing}")
            continue
        for k in unknown:  # drop extra args quietly instead of failing the step
            args.pop(k)
        good.append({"id": sid, "tool": tool.name, "args": args, "why": step.get("why", "")})
    return good, problems


def fallback_plan(goal):
    """Rule-based plan used when the LLM can't be reached."""
    ind = extract_indicators(goal)
    steps = []
    for ip in ind["ip"][:2]:
        steps += [
            {"tool": "otx_lookup", "args": {"indicator": ip}, "why": "community reputation"},
            {"tool": "internetdb_lookup", "args": {"ip": ip}, "why": "open ports and tags"},
            {"tool": "tor_exit_check", "args": {"ip": ip}, "why": "is it a Tor exit"},
            {"tool": "rdap_lookup", "args": {"target": ip}, "why": "who owns the range"},
        ]
    for d in ind["domain"][:2]:
        steps += [
            {"tool": "dns_lookup", "args": {"name": d}, "why": "does it resolve"},
            {"tool": "rdap_lookup", "args": {"target": d}, "why": "registration date"},
            {"tool": "otx_lookup", "args": {"indicator": d}, "why": "community reputation"},
        ]
    for h in ind["hash"][:2]:
        steps += [
            {"tool": "otx_lookup", "args": {"indicator": h}, "why": "known malware?"},
            {"tool": "web_search", "args": {"query": h}, "why": "public sandbox reports"},
        ]
    for c in ind["cve"][:2]:
        steps += [{"tool": "cve_lookup", "args": {"cve_id": c}, "why": "severity and exploitation"}]
    task_type = "ioc_investigation" if steps else "other"
    if not steps and any(w in goal.lower() for w in ("week", "news", "latest", "recent", "today", "developments")):
        task_type = "news_summary"
        steps = [
            {"tool": "kev_recent", "args": {"days": 7}, "why": "what is being exploited right now"},
            {"tool": "web_search", "args": {"query": "cybersecurity news this week", "mode": "news", "timelimit": "w"},
             "why": "headlines"},
        ]
    for i, s in enumerate(steps[:MAX_STEPS]):
        s["id"] = f"s{i + 1}"
    return {
        "understanding": goal,
        "task_type": task_type,
        "clarification_needed": None if steps else "Which indicator or topic should I look at?",
        "assumptions": ["Plan built by rules because the LLM was unavailable"],
        "steps": steps[:MAX_STEPS],
        "done_when": "each indicator has at least one reputation source",
        "source": "fallback",
    }


class Planner:
    def __init__(self, llm, registry, trace):
        self.llm = llm
        self.registry = registry
        self.trace = trace

    def make_plan(self, goal):
        indicators = {k: v for k, v in extract_indicators(goal).items() if v}
        prompt = PLAN_PROMPT.format(
            today=_today(), goal=goal, indicators=json.dumps(indicators) or "none",
            tools=describe_tools(self.registry), max_steps=MAX_STEPS,
        )
        try:
            plan = self.llm.generate_json(prompt, purpose="plan")
        except LLMError as e:
            self.trace.event("fallback", f"planner LLM unavailable ({e}); using rule-based plan")
            return fallback_plan(goal)

        if not isinstance(plan, dict):
            plan = {}
        if plan.get("clarification_needed"):
            plan["steps"] = []
            plan["source"] = "llm"
            return plan

        steps, problems = check_steps(plan.get("steps"), self.registry)
        if problems:
            self.trace.event("check", f"plan has problems: {'; '.join(problems)}. Asking for a fix.", problems=problems)
            fix_prompt = prompt + "\n\nYour last plan had these problems:\n- " + "\n- ".join(problems) + \
                "\nReturn the full corrected plan as JSON."
            try:
                fixed = self.llm.generate_json(fix_prompt, purpose="plan-fix")
                fixed_steps, still_bad = check_steps(fixed.get("steps"), self.registry)
                if fixed_steps:
                    plan, steps = fixed, fixed_steps
                if still_bad:
                    self.trace.event("check", f"dropping steps that are still invalid: {'; '.join(still_bad)}")
            except (LLMError, AttributeError):
                self.trace.event("check", "plan fix failed, keeping only the valid steps")

        if not steps:
            self.trace.event("fallback", "LLM plan had no usable steps; using rule-based plan")
            return fallback_plan(goal)

        plan["steps"] = steps[:MAX_STEPS]
        plan["source"] = "llm"
        plan.setdefault("assumptions", [])
        return plan

    def reflect(self, goal, plan, memory, budget):
        """Look at the evidence and maybe add follow-up steps. Returns a list of new steps."""
        if budget <= 0:
            return []
        prompt = REFLECT_PROMPT.format(
            today=_today(), goal=goal, understanding=plan.get("understanding", ""),
            done_when=plan.get("done_when", ""), evidence=memory.evidence_for_llm(),
            tools=describe_tools(self.registry), budget=budget,
        )
        try:
            reply = self.llm.generate_json(prompt, purpose="reflect")
        except LLMError as e:
            self.trace.event("fallback", f"reflection skipped, LLM unavailable ({e})")
            return []
        if not isinstance(reply, dict):
            return []
        self.trace.event("reflect", f"done={bool(reply.get('done'))}: {reply.get('reason', '')}", reply=reply)
        if reply.get("done"):
            return []
        steps, problems = check_steps(reply.get("new_steps", []), self.registry)
        if problems:
            self.trace.event("check", f"ignoring invalid follow-up steps: {'; '.join(problems)}")
        # don't re-run something that already worked
        done_calls = {(r.tool, json.dumps(r.args, sort_keys=True)) for r in memory.succeeded()}
        fresh = [s for s in steps if (s["tool"], json.dumps(s["args"], sort_keys=True)) not in done_calls]
        return fresh[:budget]
