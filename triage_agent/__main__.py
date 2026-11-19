"""Command line entry point: python -m triage_agent "your goal"."""

import argparse
import os
import re
import sys
from datetime import datetime
from pathlib import Path

from .agent import TriageAgent, save_outputs
from .executor import FailureInjector
from .llm import GeminiClient, LLMError
from .memory import Trace
from .reporter import to_markdown
from .tools import build_registry


def load_dotenv(path=".env"):
    """Tiny .env reader so I don't need python-dotenv for two lines of config."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def parse_failure(spec):
    """'timeout' or 'timeout:otx_lookup' or 'bad_response:web_search:1'."""
    parts = spec.split(":")
    kind = parts[0]
    tool = parts[1] if len(parts) > 1 and parts[1] else "otx_lookup"
    times = int(parts[2]) if len(parts) > 2 else 0
    return FailureInjector(kind, tool, times)


class Tee:
    """Print to the console and keep a copy for transcript.txt."""

    def __init__(self):
        self.lines = []

    def __call__(self, line):
        print(line, flush=True)
        self.lines.append(line)


def main(argv=None):
    ap = argparse.ArgumentParser(description="IOC triage agent: plans, checks live threat intel, writes a report.")
    ap.add_argument("goal", nargs="?", help="what you want investigated, in plain English")
    ap.add_argument("--simulate-failure", metavar="KIND[:TOOL[:TIMES]]",
                    help="break a tool on purpose: timeout or bad_response, default tool otx_lookup, TIMES=0 means always")
    ap.add_argument("--tool-timeout", type=float, help="override every tool's timeout (seconds)")
    ap.add_argument("--interactive", action="store_true", help="ask me a question if the goal is ambiguous")
    ap.add_argument("--out", help="output folder (default runs/<timestamp>-<slug>)")
    ap.add_argument("--quiet", action="store_true", help="only print the final report")
    args = ap.parse_args(argv)

    goal = args.goal or input("Goal: ").strip()
    if not goal:
        ap.error("a goal is required")

    load_dotenv()
    tee = Tee()
    trace = Trace(verbose=not args.quiet, printer=tee)
    try:
        llm = GeminiClient(trace=trace)
    except LLMError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    injector = parse_failure(args.simulate_failure) if args.simulate_failure else None
    if injector:
        trace.event("inject", f"simulating '{injector.kind}' on {injector.tool_name}"
                    + (f" for the first {injector.times} call(s)" if injector.times else " for every call"))

    ask = (lambda q: input(f"\nAgent asks: {q}\n> ")) if args.interactive else None
    agent = TriageAgent(llm, build_registry(), trace, injector=injector, ask_user=ask,
                        timeout_override=args.tool_timeout)
    doc = agent.run(goal)

    tee("")
    tee(to_markdown(doc))
    slug = re.sub(r"[^a-z0-9]+", "-", goal.lower())[:40].strip("-")
    out = Path(args.out or f"runs/{datetime.now():%Y%m%d-%H%M%S}-{slug}")
    save_outputs(doc, trace, out)
    trace.event("saved", f"report and logs written to {out}/ ({llm.calls} LLM calls)")
    (out / "transcript.txt").write_text("\n".join(tee.lines) + "\n", encoding="utf-8")
    return 0 if doc["status"] != "failed" else 1


if __name__ == "__main__":
    sys.exit(main())
