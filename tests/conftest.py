import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from triage_agent.memory import Trace  # noqa: E402
from triage_agent.tools import Tool, ToolError  # noqa: E402


@pytest.fixture
def trace():
    return Trace(verbose=False)


def fake_registry():
    """Offline tools with the same shape as the real ones."""

    def rep(indicator):
        return {"indicator": indicator, "pulse_count": 12, "top_tags": ["scanner"]}

    def ports(ip):
        return {"ip": ip, "found": True, "ports": [22, 80], "tags": []}

    def search(query, mode="text", max_results=5, timelimit=None):
        return {"query": query, "results": [{"title": "hit", "url": "https://example.org/a", "snippet": f"reports about {query}"}]}

    def broken(ip):
        raise ToolError("HTTP 500 from upstream")

    return {
        "otx_lookup": Tool("otx_lookup", "rep", {"indicator": "ioc"}, rep, required_keys=("pulse_count",),
                           timeout=2, fallback="web_search"),
        "internetdb_lookup": Tool("internetdb_lookup", "ports", {"ip": "ip"}, ports, required_keys=("found",), timeout=2),
        "web_search": Tool("web_search", "search", {"query": "q", "mode": "optional", "max_results": "optional",
                                                     "timelimit": "optional"}, search, required_keys=("results",), timeout=2),
        "broken_tool": Tool("broken_tool", "always fails", {"ip": "ip"}, broken, required_keys=("x",), timeout=2,
                            fallback="internetdb_lookup"),
    }


@pytest.fixture
def registry():
    return fake_registry()
