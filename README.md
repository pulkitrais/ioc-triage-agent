# IOC triage agent

A small agent that does the first 15 minutes of what I do when an alert lands in the SOC queue. You give it a goal in plain English ("is this IP malicious?", "what got exploited this week?"), it writes a plan, checks live threat-intel sources, recovers when a source breaks, and hands back a short report with a verdict, the evidence behind each finding, and what it couldn't check.

I built it for the Agentic AI Engineer Intern take-home. I work on SOC automation (Sentinel, Logic Apps, KQL), so I picked a problem I actually have instead of a generic research bot.

## What it does

1. **Plans first.** Gemini turns the goal into a JSON plan of tool calls. Before anything runs, I check every step against the tool list (tool exists, required args present). A broken plan goes back to the model once with the list of problems. If the LLM is down, a rule-based plan built from the indicators in the goal takes over.
2. **Runs the steps.** Each tool call runs in a thread with a hard timeout, and the result is checked for the fields that tool promises. Failures are retried with a short backoff.
3. **Recovers.** If a step still fails, the LLM chooses: retry with different args, switch to another tool, or skip and note the gap. If the LLM can't answer either, each tool has a static fallback (usually web search). One recovery per step, so it can't loop.
4. **Reflects.** After the plan, the model looks at the evidence and can add up to 3 follow-up steps (a new lead, a gap, a calculation). Max 2 rounds and 12 tool calls total.
5. **Reports and checks itself.** The model writes the verdict and findings, and every finding has to cite step ids. A plain-Python check then marks findings that cite failed or made-up steps, and lowers the confidence when evidence is missing.
6. **Asks instead of guessing.** If the goal is too vague ("is it malicious?"), it stops and returns a question, or asks you directly with `--interactive`.

Everything is logged: the console shows a readable trace, and `run.jsonl` has every event (plan, tool call, retry, recovery, LLM call, self-check).

## Tools

All live, free, and keyless:

| tool | source | used for |
|---|---|---|
| `web_search` | ddgs (DuckDuckGo-style metasearch) | text and news search |
| `dns_lookup` | dns.google DNS-over-HTTPS | does a domain resolve, to what |
| `rdap_lookup` | rdap.org | owner, country, registration date and domain age |
| `internetdb_lookup` | Shodan InternetDB | open ports, hostnames, tags like `tor`, known CVEs |
| `otx_lookup` | AlienVault OTX | community reputation: pulses, tags, malware families |
| `tor_exit_check` | Tor Project bulk exit list | is this IP a Tor exit right now |
| `cve_lookup` | MITRE CVE API + FIRST EPSS + CISA KEV | severity, exploit probability, known exploitation |
| `kev_recent` | CISA KEV feed | what CISA flagged as exploited in the last N days |
| `calculator` | local, AST-based (no `eval`) | arithmetic and `days_since('YYYY-MM-DD')` |

The LLM is Google Gemini over plain REST. It tries `gemini-flash-latest` first and falls back to the lite models. On the free tier the bigger model often returns 503 "high demand", so after a model fails all its retries it is skipped for the rest of the run.

## Setup

Needs Python 3.10+.

```bash
git clone https://github.com/pulkitrais/ioc-triage-agent.git ioc-triage-agent && cd ioc-triage-agent
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt    # requests, ddgs
cp .env.example .env               # then put your key in .env
```

Get a free key at https://aistudio.google.com/apikey. The key is read from the `GEMINI_API_KEY` environment variable (or `.env`), and `.env` is in `.gitignore`.

## Run

```bash
python -m triage_agent "Investigate 185.220.101.1 and tell me if it is malicious"
```

More examples:

```bash
# domain or hash, defanged input is fine
python -m triage_agent "Is login-micros0ft[.]com safe to allow through the proxy?"

# CVE research and weekly brief
python -m triage_agent "How bad is CVE-2024-3400 and is it being exploited?"
python -m triage_agent "Summarize the top 3 security developments this week"

# vague goal: it will ask a question
python -m triage_agent "is it malicious?" --interactive
```

Each run writes `runs/<timestamp>-<slug>/` with `report.md`, `report.json`, `run.jsonl` and `transcript.txt`. Use `--out DIR` to choose the folder and `--quiet` to only print the report.

### Breaking it on purpose

`--simulate-failure KIND[:TOOL[:TIMES]]` breaks one tool so you can watch the recovery:

```bash
# OTX hangs on every call; the executor times out, retries, then recovers with another tool
python -m triage_agent "Is 162.243.103.246 a C2 server?" --simulate-failure timeout:otx_lookup --tool-timeout 10

# web search returns an HTML error page once; validation catches it and the retry works
python -m triage_agent "Summarize this week's security news" --simulate-failure bad_response:web_search:1
```

`KIND` is `timeout` or `bad_response`, `TOOL` defaults to `otx_lookup`, and `TIMES=0` (default) means every call fails. The third failure type, an ambiguous goal, needs no flag: just give it a vague goal.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

The tests run offline. The LLM is replaced with a scripted fake and the tools with small fake functions, so they check the agent's logic (plan validation, retries, timeouts, recovery choices, self-check, the full loop) without network or API cost.

## Samples

Real runs from 19 Nov 2026, in `samples/`. Each folder has the console transcript (`transcript.txt`), the full event log (`run.jsonl`) and the report (`report.md`, `report.json`):

| folder | goal | what it shows |
|---|---|---|
| `01-ip-investigation` | is 185.220.101.1 malicious? | clean run: 4 sources agree it is a Tor exit, verdict "suspicious" with the reason |
| `02-c2-check-with-timeout` | workstation talked to 162.243.103.246:8080, is it C2? | OTX forced to time out, retried, LLM picks a web search as recovery, the relevance check rejects it (results never mention the IP), the gap is reported and confidence drops to medium. Another search still finds the Feodo Tracker / Emotet history |
| `03-weekly-brief-with-bad-response` | top 3 developments this week + what to patch first | web search returns an HTML error page once, validation catches it, the retry works. Reflection then adds CVE lookups to rank the KEV entries |
| `04-ambiguous-goal` | "is it malicious?" | stops before calling any tool and asks which indicator |
| `05-cve-with-timeout` | how bad is CVE-2024-3400? | CVE tool forced to time out, recovery via web search succeeds, report notes the gap |

The free Gemini tier was overloaded during these runs, so the transcripts also show real 503 and 429 errors, retries and the switch to the lite model, not just the simulated failures.

## Layout

```
triage_agent/
  __main__.py   CLI, .env loading, failure flag
  agent.py      the loop: plan -> execute -> reflect -> report
  planner.py    plan prompt, step validation, fix round, rule-based fallback, reflection
  executor.py   timeouts, validation, retries, recovery, failure injector
  tools.py      the tools and the registry
  llm.py        Gemini REST client with retries and model fallback, scripted fake for tests
  memory.py     step results and the trace/logger
  reporter.py   report prompt, self-check, Markdown output
tests/          offline pytest suite
docs/           architecture diagram, write-up
samples/        real run transcripts
```

See `docs/WRITEUP.md` for design decisions and limitations, and `docs/architecture.png` for the diagram.
