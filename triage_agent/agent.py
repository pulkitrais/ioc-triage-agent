"""The loop that ties it together: plan -> execute -> reflect -> report."""

import json
from pathlib import Path

from .executor import Executor
from .memory import Memory
from .planner import MAX_STEPS, Planner
from .reporter import Reporter, assemble, to_markdown

MAX_TOTAL_STEPS = 12  # hard cap including follow-ups and recoveries
REFLECT_ROUNDS = 2


class TriageAgent:
    def __init__(self, llm, registry, trace, injector=None, ask_user=None, timeout_override=None):
        self.llm = llm
        self.registry = registry
        self.trace = trace
        self.planner = Planner(llm, registry, trace)
        self.executor = Executor(registry, trace, llm=llm, injector=injector, timeout_override=timeout_override)
        self.reporter = Reporter(llm, trace)
        self.ask_user = ask_user  # function(question) -> answer, or None for non-interactive runs

    def run(self, goal):
        memory = Memory(goal=goal)
        self.trace.section("PLAN")
        self.trace.event("goal", goal)
        plan = self.planner.make_plan(goal)

        if plan.get("clarification_needed"):
            question = plan["clarification_needed"]
            self.trace.event("clarify", f"goal is ambiguous: {question}")
            if self.ask_user:
                answer = self.ask_user(question)
                goal = f"{goal}\n(Clarification: {answer})"
                memory.goal = goal
                plan = self.planner.make_plan(goal)
            if plan.get("clarification_needed"):
                return self._stop_for_clarification(memory, plan)

        memory.plan = plan
        self._print_plan(plan)

        self.trace.section("EXECUTE")
        self.executor.remember(plan["steps"])
        for step in plan["steps"]:
            self.executor.run_step(step, memory)

        for round_no in range(1, REFLECT_ROUNDS + 1):
            budget = min(3, MAX_TOTAL_STEPS - len(memory.results))
            if budget <= 0:
                self.trace.event("check", "step budget used up, moving to the report")
                break
            self.trace.section(f"REFLECT (round {round_no})")
            new_steps = self.planner.reflect(goal, plan, memory, budget)
            if not new_steps:
                break
            for i, step in enumerate(new_steps, 1):
                step["id"] = f"r{round_no}.{i}"
                plan["steps"].append(step)
            self.executor.remember(new_steps)
            for step in new_steps:
                self.executor.run_step(step, memory)

        self.trace.section("REPORT")
        status = "completed" if memory.succeeded() else "failed"
        doc = self.reporter.build(memory, plan, status=status)
        return doc

    def _print_plan(self, plan):
        self.trace.event("plan", f"understanding: {plan.get('understanding', '')}", plan=plan)
        if plan.get("source") == "fallback":
            self.trace.event("plan", "(rule-based plan, LLM was unavailable)")
        for a in plan.get("assumptions", []):
            self.trace.event("plan", f"assumption: {a}")
        for s in plan["steps"]:
            self.trace.event("plan", f"{s['id']}. {s['tool']}({json.dumps(s['args'])}) - {s.get('why', '')}")
        if plan.get("done_when"):
            self.trace.event("plan", f"done when: {plan['done_when']}")

    def _stop_for_clarification(self, memory, plan):
        question = plan["clarification_needed"]
        self.trace.event("stop", "not guessing; returning the question to the user")
        report = {"verdict": "n/a", "confidence": "low",
                  "summary": f"I stopped before calling any tools because the goal is ambiguous. {question}",
                  "findings": [], "recommendations": [], "gaps": ["no tools were run"]}
        check = {"tool_calls": 0, "failed_calls": 0, "recovered_steps": 0, "findings_supported": 0,
                 "findings_unsupported": [], "notes": ["stopped for clarification"], "passed": True}
        plan.setdefault("steps", [])
        return assemble(memory, plan, report, check, status="needs_clarification")


def save_outputs(doc, trace, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    (out / "report.md").write_text(to_markdown(doc), encoding="utf-8")
    trace.save_jsonl(out / "run.jsonl")
    return out
