"""Draws docs/architecture.png. Run: python docs/make_diagram.py (needs matplotlib)."""

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

fig, ax = plt.subplots(figsize=(13.8, 8.2))
ax.set_xlim(0, 13.9)
ax.set_ylim(0, 8.2)
ax.axis("off")


def box(x, y, w, h, title, body="", color="#e8f0fe", edge="#3367d6"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.05,rounding_size=0.12",
                                fc=color, ec=edge, lw=1.6))
    ax.text(x + w / 2, y + h - 0.28, title, ha="center", va="top", fontsize=11, weight="bold")
    if body:
        ax.text(x + w / 2, y + h - 0.62, body, ha="center", va="top", fontsize=8.6, linespacing=1.35)


def arrow(x1, y1, x2, y2, label="", style="-|>", color="#333", rad=0.0, lx=0, ly=0):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=14, lw=1.4,
                                 color=color, connectionstyle=f"arc3,rad={rad}"))
    if label:
        ax.text((x1 + x2) / 2 + lx, (y1 + y2) / 2 + ly, label, fontsize=8.3, ha="center", color=color,
                bbox=dict(fc="white", ec="none", pad=0.5))


ax.text(6.85, 7.95, "IOC triage agent: components and control flow", ha="center", fontsize=14, weight="bold")

# columns: A 0.3-2.9, B 3.9-6.9, C 7.9-10.7, D 11.5-13.7
box(0.3, 6.0, 2.6, 1.3, "CLI  (__main__.py)", "goal in plain English\n--simulate-failure\n--interactive", "#f1f3f4", "#5f6368")
box(3.9, 5.7, 3.0, 1.6, "Planner", "LLM writes plan as JSON\ncheck_steps(): tool exists,\nargs present; one fix round\nrule-based plan if LLM down", "#e6f4ea", "#188038")
box(7.9, 5.7, 2.8, 1.6, "Clarify?", "goal too vague:\nask user (--interactive)\nor stop and return\nthe question", "#fef7e0", "#f9ab00")
box(11.5, 5.7, 2.2, 1.6, "Gemini (REST)", "retry + backoff\nmodel fallback chain\nskip a model after\nit keeps failing", "#fef7e0", "#f9ab00")
box(0.3, 3.0, 2.6, 2.0, "Reflect", "LLM reads evidence,\nadds follow-up steps\n(new leads, gaps,\ncalculator)\nmax 2 rounds, 12 steps", "#e6f4ea", "#188038")
box(3.9, 3.0, 3.0, 2.0, "Executor", "per step:\n1. call tool in thread w/ timeout\n2. validate result shape\n3. retry with backoff\n4. recover: LLM picks other args,\n    other tool, or skip\n    (static fallback if LLM down)", "#e8f0fe", "#3367d6")
box(7.9, 2.6, 2.8, 2.4, "Tools (live, no keys)", "web_search (ddgs)\ndns_lookup (DoH)\nrdap_lookup (WHOIS)\ninternetdb_lookup (Shodan)\notx_lookup (AlienVault)\ntor_exit_check\ncve_lookup + kev_recent\ncalculator (safe AST)", "#fce8e6", "#c5221f")
box(11.5, 3.0, 2.2, 2.0, "Failure injector", "timeout or\nbad_response\non any tool\n(first N calls\nor always)", "#fce8e6", "#c5221f")
box(0.3, 0.35, 2.6, 2.0, "Memory + Trace", "StepResult per call\nevidence_for_llm()\nevery event printed\nand logged as JSONL", "#f1f3f4", "#5f6368")
box(3.9, 0.35, 3.0, 2.0, "Reporter", "LLM writes verdict + findings,\neach citing step ids\nself_check(): unsupported\nfindings, unrecovered\nfailures lower confidence", "#f3e8fd", "#8430ce")
box(7.9, 0.6, 2.8, 1.5, "Outputs", "report.md, report.json\nrun.jsonl (every event)\ntranscript.txt", "#f1f3f4", "#5f6368")

arrow(2.95, 6.65, 3.85, 6.65, "goal", ly=0.2)
arrow(6.95, 6.65, 7.85, 6.65, "vague?", ly=0.2)
arrow(5.4, 5.65, 5.4, 5.05, "plan steps", lx=0.6)
arrow(6.95, 4.3, 7.85, 4.3, "call(args)", ly=0.2)
arrow(7.85, 3.5, 6.95, 3.5, "result/error", ly=0.2)
arrow(11.45, 4.0, 10.75, 4.0, "")
arrow(3.85, 4.3, 2.95, 4.3, "evidence", ly=0.2)
arrow(2.95, 3.5, 3.85, 3.5, "new steps", ly=0.2)
arrow(5.4, 2.95, 5.4, 2.4, "done", lx=0.4)
arrow(6.95, 1.35, 7.85, 1.35, "")
arrow(1.6, 2.95, 1.6, 2.4, "", style="<|-|>", color="#777")
ax.text(12.6, 7.55, "used by planner, reflect,\nrecover and reporter", fontsize=8, color="#666", ha="center")
ax.text(12.6, 2.85, "wraps one tool's\nfunction when the\nflag is set", fontsize=8, color="#c5221f", ha="center", va="top")

out = Path(__file__).with_name("architecture.png")
fig.savefig(out, dpi=150, bbox_inches="tight")
print(f"wrote {out}")
