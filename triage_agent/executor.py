"""Runs plan steps one at a time and deals with failures.

For each step:
  1. call the tool in a thread with a hard timeout
  2. check the result has the shape the tool promises (required_keys)
  3. on a timeout or error, retry with a short backoff
  4. if it still fails, ask the LLM how to recover (retry with other args,
     swap to another tool, or skip). If the LLM can't answer either, use the
     tool's static fallback. Each step gets at most one recovery, so a broken
     source can't put the agent in a loop.
"""

import json
import threading
import time

from .llm import LLMError
from .memory import StepResult
from .tools import ToolError, describe_tools, extract_indicators


class ToolTimeout(Exception):
    pass


class UnexpectedResult(Exception):
    """The call worked but the answer is useless. Retrying the same call won't help."""


RECOVER_PROMPT = """A step in a security triage agent failed after retries.

Goal: \"\"\"{goal}\"\"\"
Failed step: {tool}({args}) because: {why}
Error: {error}

Results so far:
{evidence}

Calls already planned or done (don't suggest these again):
{known}

Tools:
{tools}

Choose one recovery:
- "retry_with": same tool, different args (only if the args were the problem)
- "use_tool": a different tool that can get similar information
- "skip": the information isn't needed or no tool can provide it; the report will mention the gap
Tip: web search works best with the indicator in quotes plus one or two words, e.g. "1.2.3.4" abuse.

Reply with JSON only: {{"action": "retry_with | use_tool | skip", "tool": "name or null", "args": {{}}, "reason": "short"}}
"""


def call_with_timeout(func, args, timeout):
    """Run func(**args) in a daemon thread so a hung HTTP call can't freeze the agent."""
    box = {}

    def target():
        try:
            box["value"] = func(**args)
        except BaseException as e:  # passed back to the main thread below
            box["error"] = e

    t = threading.Thread(target=target, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise ToolTimeout(f"no answer after {timeout:.0f}s")
    if "error" in box:
        raise box["error"]
    return box["value"]


def validate(tool, output):
    if not isinstance(output, dict):
        raise ToolError(f"unexpected response type {type(output).__name__}: {str(output)[:60]!r}")
    missing = [k for k in tool.required_keys if k not in output]
    if missing:
        raise ToolError(f"response missing expected field(s) {missing}")


def check_relevance(tool, args, output):
    """Catch answers that are well-formed but useless.

    The case I hit: a web search for an IP with a fancy OR query came back with
    vendor landing pages ("Threat Intelligence Platform") that never mention
    the IP. Shape validation passes, but the step taught us nothing.
    """
    if tool.name != "web_search":
        return
    query = str(args.get("query", ""))
    wanted = [i for kind in ("ip", "hash", "cve") for i in extract_indicators(query)[kind]]
    if not wanted:
        return  # topic searches can't be checked this simply
    blob = json.dumps(output.get("results", [])).lower()
    if not any(w.lower() in blob for w in wanted):
        raise UnexpectedResult(f"none of the {len(output.get('results', []))} results mention {', '.join(wanted)}")


class FailureInjector:
    """Deliberately breaks one tool so the recovery path can be shown on demand.

    kind is 'timeout' (tool hangs past its timeout) or 'bad_response'
    (tool returns an HTML error page instead of data, like crt.sh does when
    it is overloaded). times=0 means every call fails.
    """

    def __init__(self, kind, tool_name, times=0):
        if kind not in ("timeout", "bad_response"):
            raise ValueError("kind must be 'timeout' or 'bad_response'")
        self.kind, self.tool_name, self.times = kind, tool_name, times
        self.fired = 0

    def wrap(self, tool):
        if tool.name != self.tool_name:
            return tool.func
        real = tool.func

        def broken(**kwargs):
            if self.times and self.fired >= self.times:
                return real(**kwargs)
            self.fired += 1
            if self.kind == "timeout":
                time.sleep(tool.timeout + 30)  # longer than the executor will wait
                return real(**kwargs)
            return "<html><head><title>502 Bad Gateway</title></head><body>nginx</body></html>"

        return broken


class Executor:
    def __init__(self, registry, trace, llm=None, retries=1, backoff=1.5, injector=None, timeout_override=None):
        self.registry = registry
        self.trace = trace
        self.llm = llm
        self.retries = retries
        self.backoff = backoff
        self.injector = injector
        self.timeout_override = timeout_override
        self.known_calls = set()  # (tool, args) already planned or run, so a recovery doesn't duplicate them

    @staticmethod
    def call_key(tool, args):
        return tool, json.dumps(args, sort_keys=True)

    def remember(self, steps):
        for s in steps:
            self.known_calls.add(self.call_key(s["tool"], s["args"]))

    def _attempt(self, tool, args):
        func = self.injector.wrap(tool) if self.injector else tool.func
        timeout = self.timeout_override or tool.timeout
        output = call_with_timeout(func, args, timeout)
        validate(tool, output)
        check_relevance(tool, args, output)
        return output

    def _run_with_retries(self, step):
        tool = self.registry[step["tool"]]
        started = time.time()
        error = None
        attempts = 0
        for attempt in range(1, self.retries + 2):
            attempts = attempt
            try:
                output = self._attempt(tool, step["args"])
                return StepResult(step["id"], tool.name, step["args"], True, output=output,
                                  attempts=attempts, seconds=round(time.time() - started, 2))
            except ToolTimeout as e:
                error = f"timeout: {e}"
            except ToolError as e:
                error = str(e)
            except UnexpectedResult as e:
                error = f"unexpected result: {e}"
                break
            except TypeError as e:  # wrong arg names slipped through
                error = f"bad arguments: {e}"
                break
            except Exception as e:  # last line of defence, a tool bug shouldn't kill the run
                error = f"{type(e).__name__}: {e}"
            if attempt <= self.retries:
                self.trace.event("retry", f"{step['id']} {tool.name} failed ({error}); retry {attempt} in {self.backoff}s",
                                 step=step["id"], error=error)
                time.sleep(self.backoff)
        return StepResult(step["id"], tool.name, step["args"], False, error=error,
                          attempts=attempts, seconds=round(time.time() - started, 2))

    def run_step(self, step, memory):
        self.known_calls.add(self.call_key(step["tool"], step["args"]))
        self.trace.event("tool", f"{step['id']} {step['tool']}({json.dumps(step['args'])})  # {step.get('why', '')}",
                         step=step["id"], tool=step["tool"], args=step["args"])
        result = self._run_with_retries(step)
        if result.ok:
            self.trace.event("result", f"{step['id']} ok in {result.seconds}s: {_preview(result.output)}",
                             step=step["id"], output=result.output)
            memory.add(result)
            return result

        self.trace.event("error", f"{step['id']} {step['tool']} failed after {result.attempts} attempt(s): {result.error}",
                         step=step["id"], error=result.error)
        memory.add(result)
        recovery = self.plan_recovery(step, result.error, memory)
        if recovery is None:
            return result
        recovery["id"] = f"{step['id']}b"
        self.trace.event("recover", f"{step['id']} -> {recovery['tool']}({json.dumps(recovery['args'])}): {recovery['why']}",
                         step=step["id"], recovery=recovery)
        second = self._run_with_retries(recovery)
        second.recovered_from = step["id"]
        if second.ok:
            self.trace.event("result", f"{recovery['id']} ok in {second.seconds}s: {_preview(second.output)}",
                             step=recovery["id"], output=second.output)
        else:
            self.trace.event("error", f"{recovery['id']} also failed: {second.error}. Moving on, the report will flag the gap.",
                             step=recovery["id"], error=second.error)
        memory.add(second)
        return second

    def plan_recovery(self, step, error, memory):
        """Decide what to do about a failed step. Returns a new step dict or None to skip."""
        tool = self.registry[step["tool"]]
        choice = None
        if self.llm is not None:
            prompt = RECOVER_PROMPT.format(
                goal=memory.goal, tool=step["tool"], args=json.dumps(step["args"]), why=step.get("why", ""),
                error=error, evidence=memory.evidence_for_llm(max_chars=600), tools=describe_tools(self.registry),
                known="\n".join(f"- {t}({a})" for t, a in sorted(self.known_calls)),
            )
            try:
                choice = self.llm.generate_json(prompt, purpose="recover")
            except LLMError as e:
                self.trace.event("fallback", f"recovery LLM unavailable ({e}), using static fallback")

        if isinstance(choice, dict):
            action = choice.get("action")
            reason = choice.get("reason", "")
            if action == "skip":
                self.trace.event("recover", f"{step['id']}: skipping. {reason}", step=step["id"])
                return None
            name = step["tool"] if action == "retry_with" else choice.get("tool")
            args = choice.get("args") or {}
            if name in self.registry and isinstance(args, dict) and args:
                # never repeat the call that just failed, or one that is already in the plan
                if self.call_key(name, args) not in self.known_calls:
                    return {"tool": name, "args": args, "why": reason or "LLM-chosen recovery"}
                self.trace.event("check", f"recovery suggestion {name}({json.dumps(args)}) is already planned or "
                                          "just failed, using static fallback instead")
            else:
                self.trace.event("check", f"recovery suggestion unusable ({choice}), using static fallback")

        fallback = self._static_fallback(step, tool)
        if fallback and self.call_key(fallback["tool"], fallback["args"]) in self.known_calls:
            self.trace.event("recover", f"{step['id']}: static fallback is already planned, skipping", step=step["id"])
            return None
        return fallback

    def _static_fallback(self, step, tool):
        if not tool.fallback or tool.fallback not in self.registry:
            return None
        target = next(iter(step["args"].values()), "")
        if tool.fallback == "web_search":
            args = {"query": f'"{target}" malicious', "max_results": 5}
        else:
            first_arg = next(iter(self.registry[tool.fallback].args))
            args = {first_arg: target}
        return {"tool": tool.fallback, "args": args, "why": f"static fallback for {tool.name}"}


def _preview(output, limit=160):
    text = json.dumps(output, default=str)
    return text if len(text) <= limit else text[:limit] + "..."
