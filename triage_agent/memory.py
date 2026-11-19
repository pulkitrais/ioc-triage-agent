"""Run trace and working memory.

Everything the agent does goes through Trace.event(). That gives me one place
that both prints the readable console trace and keeps a machine-readable
JSONL log, so the sample transcripts and the logs always agree.
"""

import json
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class StepResult:
    step_id: str
    tool: str
    args: dict
    ok: bool
    output: object = None
    error: str | None = None
    attempts: int = 1
    seconds: float = 0.0
    recovered_from: str | None = None  # id of the step this one replaced, if any


class Trace:
    def __init__(self, verbose=True, printer=print):
        self.verbose = verbose
        self.printer = printer
        self.events = []
        self.started = time.time()

    def event(self, kind, message="", **data):
        record = {"t": round(time.time() - self.started, 2), "kind": kind, "message": message}
        record.update(data)
        self.events.append(record)
        if self.verbose and message:
            self.printer(f"[{record['t']:6.1f}s] {kind.upper():<9} {message}")
        return record

    def section(self, title):
        if self.verbose:
            self.printer("")
            self.printer(f"== {title} ==")

    def save_jsonl(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            for e in self.events:
                f.write(json.dumps(e, default=str) + "\n")


@dataclass
class Memory:
    """What the agent knows so far: the goal, the plan and every step result."""

    goal: str
    plan: dict | None = None
    results: list = field(default_factory=list)

    def add(self, result: StepResult):
        self.results.append(result)

    def get(self, step_id):
        for r in self.results:
            if r.step_id == step_id:
                return r
        return None

    def succeeded(self):
        return [r for r in self.results if r.ok]

    def failed(self):
        return [r for r in self.results if not r.ok]

    def evidence_for_llm(self, max_chars=1800):
        """Compact view of the results so prompts stay small (OTX alone can be 400 KB)."""
        lines = []
        for r in self.results:
            if r.ok:
                body = json.dumps(r.output, default=str)
                if len(body) > max_chars:
                    body = body[:max_chars] + " ...(truncated)"
                lines.append(f"[{r.step_id}] {r.tool}({json.dumps(r.args)}) OK: {body}")
            else:
                lines.append(f"[{r.step_id}] {r.tool}({json.dumps(r.args)}) FAILED: {r.error}")
        return "\n".join(lines) if lines else "(no results yet)"
