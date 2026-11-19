import pytest
import requests

from triage_agent import llm as llm_mod
from triage_agent.llm import GeminiClient, LLMError, extract_json


def test_extract_json_handles_fences_and_chatter():
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Sure! Here it is: {"a": 2} hope that helps') == {"a": 2}


class FakeResp:
    def __init__(self, status, payload):
        self.status_code = status
        self._payload = payload
        self.text = str(payload)

    def json(self):
        return self._payload


def ok(text):
    return FakeResp(200, {"candidates": [{"content": {"parts": [{"text": text}]}}]})


def test_retries_then_falls_back_to_next_model(monkeypatch):
    calls = []

    def fake_post(url, **kwargs):
        calls.append(url)
        if "model-a" in url:
            return FakeResp(503, {"error": {"message": "high demand"}})
        return ok('{"fine": true}')

    monkeypatch.setattr(llm_mod.requests, "post", fake_post)
    monkeypatch.setattr(llm_mod.time, "sleep", lambda s: None)
    client = GeminiClient(api_key="test", models=["model-a", "model-b"], retries=1)
    assert client.generate_json("hi") == {"fine": True}
    assert sum("model-a" in c for c in calls) == 2  # first try + one retry
    # model-a is now skipped for the rest of the run
    calls.clear()
    client.generate_json("again")
    assert all("model-b" in c for c in calls)


def test_raises_when_everything_fails(monkeypatch):
    def fake_post(url, **kwargs):
        raise requests.Timeout()

    monkeypatch.setattr(llm_mod.requests, "post", fake_post)
    monkeypatch.setattr(llm_mod.time, "sleep", lambda s: None)
    with pytest.raises(LLMError):
        GeminiClient(api_key="test", models=["m"], retries=1).generate_json("hi")


def test_missing_key_is_a_clear_error(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(LLMError, match="GEMINI_API_KEY"):
        GeminiClient()
