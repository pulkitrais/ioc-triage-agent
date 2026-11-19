# Write-up: IOC triage agent

Pulkit Rai, Agentic AI Engineer Intern take-home, November 2026

**What I built.** An agent that takes a security question in plain English (an IP, domain, hash, CVE, or "what happened this week"), plans which live sources to check, runs them, recovers when one breaks, and writes a short report where every finding points at the tool call it came from. I picked this domain because I do this triage by hand in my SOC work, so I could judge whether the output was actually useful.

## Design decisions

- **Plan as data, checked before it runs.** The LLM returns the plan as JSON and I validate every step against the tool registry (tool exists, required args present) before anything executes. A bad plan goes back once with the exact problems. I kept the plan to a flat list of independent steps because chaining outputs between steps added complexity the problem didn't need; follow-ups happen in the reflect phase instead.
- **The LLM decides, but code keeps it in bounds.** The model picks the plan, the recovery and the follow-ups. Code enforces timeouts, result shapes, one recovery per step, no duplicate calls, max 2 reflect rounds and 12 tool calls. That split made the agent predictable without making it rigid.
- **Three layers of failure handling.** Transport (timeout and retry), validation (wrong shape, like an HTML error page, or a search that never mentions the indicator), and recovery (LLM picks another tool or args, or skips; a static fallback is used if the LLM is down too). If the LLM can't plan at all, a rule-based plan built from regex-extracted indicators still runs.
- **The report has to show its work.** Findings cite step ids, and a plain-Python self-check marks anything that cites a failed or non-existent step, then asks the model to fix it once. Confidence drops when planned steps failed without a recovery. I added this after a run where the model said "according to OTX" even though OTX had timed out.
- **Keyless, live sources and few dependencies.** Only `requests` and `ddgs`. Gemini is called over plain REST so the retry and model fallback logic is visible. Anyone can run it with just a free Gemini key.
- **Induced failures are a flag, not a code edit.** `--simulate-failure timeout:otx_lookup` makes a tool hang for real past its timeout, and `bad_response` returns an HTML error page. An ambiguous goal makes the agent stop and ask instead of guessing.

## What I learned from the real runs

The free Gemini tier was the least reliable part. I saw 503 "high demand", 429 quota errors and requests that hung for over a minute. That is why the client retries, falls back to lighter models and stops trying a model for the rest of the run once it keeps failing. The relevance check also came from a real run: an LLM-chosen recovery search returned vendor landing pages that never mentioned the IP, and plain shape validation let it through.

## Limitations

- Verdicts are only as good as free sources. OTX and web search mix old and current reports, and shared infrastructure (cloud IPs, Tor) needs human judgement. The agent says "suspicious", not "block it".
- The lite Gemini models sometimes write vague findings or pick weak search queries. The self-check catches bad citations, not weak reasoning.
- No caching across runs and no rate limiting per source, so many runs back to back could hit OTX or search limits.
- Tests mock the LLM and tools, so they check the control flow, not answer quality.

## With more time

- An evaluation set: 20 to 30 known-bad and known-good indicators (Feodo, Tor, big CDNs) and a script that scores verdict accuracy and cost per run.
- Keyed sources as optional plugins (VirusTotal, AbuseIPDB, GreyNoise) and a cache with TTLs.
- Run independent steps in parallel; OTX alone takes 10 to 15 seconds.
- Output a Sentinel-ready incident comment or a STIX bundle, since that is where this would live in my workflow.
