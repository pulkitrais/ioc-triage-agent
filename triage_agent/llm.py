"""Small Gemini client over plain REST.

I skipped the official SDK on purpose. The REST call is ~20 lines, it keeps the
dependency list short, and it makes the retry/fallback behaviour easy to see.

The free tier is flaky in practice: while building this I got 503 "high demand"
errors and requests that hung for over a minute on the bigger Flash models.
So every call retries with backoff and then falls back to the next model.
"""

import json
import os
import re
import time

import requests

API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

# Tried in order. flash-latest is the best quality that answered reliably on the
# free tier when I tested; the lite models are the safety net.
DEFAULT_MODELS = ["gemini-flash-latest", "gemini-flash-lite-latest", "gemini-3.1-flash-lite"]

RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class LLMError(Exception):
    pass


def extract_json(text):
    """Pull the first JSON object out of a model reply.

    JSON mode usually returns clean JSON, but the lite models sometimes wrap it
    in ```json fences or add a sentence before it.
    """
    text = text.strip()
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fenced:
        text = fenced.group(1).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        return json.loads(text[start : end + 1])
    raise json.JSONDecodeError("no JSON object found", text, 0)


class GeminiClient:
    def __init__(self, api_key=None, models=None, timeout=30, retries=1, trace=None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "").strip()
        if not self.api_key:
            raise LLMError("GEMINI_API_KEY is not set (put it in .env or export it)")
        env_model = os.environ.get("GEMINI_MODEL")
        self.models = models or ([env_model] if env_model else []) + DEFAULT_MODELS
        self.timeout = timeout
        self.retries = retries
        self.trace = trace
        self.calls = 0
        # Simple circuit breaker: a model that failed all its retries is skipped
        # for the rest of the run. Without this every LLM call in a run paid the
        # same ~30-60s of 503s before reaching a model that works.
        self.skipped = set()

    def _log(self, kind, message, **data):
        if self.trace:
            self.trace.event(kind, message, **data)

    def _post(self, model, prompt):
        body = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
        }
        resp = requests.post(
            API_URL.format(model=model),
            headers={"x-goog-api-key": self.api_key},
            json=body,
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            # never echo request headers here, only the status and Google's message
            try:
                msg = resp.json().get("error", {}).get("message", "")[:160]
            except ValueError:
                msg = resp.text[:160]
            raise requests.HTTPError(f"{resp.status_code}: {msg}", response=resp)
        data = resp.json()
        parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
        if not text:
            raise LLMError(f"empty reply from {model}")
        return text

    def generate_json(self, prompt, purpose="llm"):
        """Return a dict parsed from the model's JSON reply, or raise LLMError."""
        last_error = None
        if self.skipped.issuperset(self.models):
            self.skipped.clear()  # everything was skipped; give them all another chance
        for model in self.models:
            if model in self.skipped:
                continue
            for attempt in range(1, self.retries + 2):
                started = time.time()
                try:
                    self.calls += 1
                    text = self._post(model, prompt)
                    try:
                        result = extract_json(text)
                    except json.JSONDecodeError:
                        # one cheap repair attempt before treating it as a failure
                        self._log("llm", f"{purpose}: reply was not valid JSON, asking {model} to fix it")
                        text = self._post(model, prompt + "\n\nYour previous reply was not valid JSON. Reply with JSON only.")
                        result = extract_json(text)
                    self._log("llm", f"{purpose}: {model} answered in {time.time() - started:.1f}s",
                              model=model, purpose=purpose)
                    return result
                except requests.HTTPError as e:
                    last_error = str(e)
                    status = e.response.status_code if e.response is not None else None
                    if status not in RETRYABLE_STATUS:
                        self._log("llm", f"{purpose}: {model} gave {last_error}, trying next model")
                        self.skipped.add(model)
                        break
                except (requests.Timeout, requests.ConnectionError) as e:
                    last_error = f"{type(e).__name__}"
                except (LLMError, json.JSONDecodeError, KeyError, IndexError) as e:
                    last_error = f"bad reply: {e}"
                if attempt <= self.retries:
                    wait = 2 ** attempt
                    self._log("retry", f"{purpose}: {model} failed ({last_error}), retry {attempt} in {wait}s")
                    time.sleep(wait)
                else:
                    self._log("fallback", f"{purpose}: giving up on {model} ({last_error}), skipping it for this run")
                    self.skipped.add(model)
        raise LLMError(f"all models failed, last error: {last_error}")


class ScriptedLLM:
    """Stand-in for tests: returns canned replies in order, or from a function."""

    def __init__(self, replies):
        self.replies = list(replies) if not callable(replies) else replies
        self.prompts = []
        self.calls = 0

    def generate_json(self, prompt, purpose="llm"):
        self.calls += 1
        self.prompts.append((purpose, prompt))
        if callable(self.replies):
            reply = self.replies(purpose, prompt)
        else:
            if not self.replies:
                raise LLMError("scripted LLM ran out of replies")
            reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply
