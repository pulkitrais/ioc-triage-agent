import pytest

from triage_agent.executor import validate
from triage_agent.tools import ToolError, build_registry, calculator, classify, extract_indicators


def test_classify():
    assert classify("8.8.8.8") == "ip"
    assert classify("CVE-2024-3400") == "cve"
    assert classify("d41d8cd98f00b204e9800998ecf8427e") == "hash"
    assert classify("evil-site.xyz") == "domain"
    assert classify("not an indicator") is None


def test_extract_indicators_handles_defanged_domains():
    found = extract_indicators("check 1.2.3.4 and bad[.]example[.]com, also cve-2023-4966")
    assert found["ip"] == ["1.2.3.4"]
    assert "bad.example.com" in found["domain"]
    assert found["cve"] == ["CVE-2023-4966"]


def test_calculator_basic_and_functions():
    assert calculator("0.4*3 + 0.6*1")["result"] == pytest.approx(1.8)
    assert calculator("round(sqrt(16) / 3, 2)")["result"] == 1.33
    assert calculator("days_since('2000-01-01')")["result"] > 9000


@pytest.mark.parametrize("expr", ["__import__('os').system('ls')", "open('x')", "2**10000", "1/0", "'text'"])
def test_calculator_rejects_unsafe_or_bad_input(expr):
    with pytest.raises(ToolError):
        calculator(expr)


def test_validate_catches_html_instead_of_json():
    tool = build_registry()["otx_lookup"]
    with pytest.raises(ToolError, match="unexpected response type"):
        validate(tool, "<html>502 Bad Gateway</html>")
    with pytest.raises(ToolError, match="missing expected field"):
        validate(tool, {"indicator": "1.2.3.4"})
    validate(tool, {"pulse_count": 0})  # no exception


def test_private_ip_is_refused_without_network():
    tool = build_registry()["internetdb_lookup"]
    with pytest.raises(ToolError, match="not a public address"):
        tool.func(ip="192.168.1.10")


def test_every_tool_has_description_and_args():
    for name, tool in build_registry().items():
        assert tool.description and tool.args, name
        assert tool.timeout > 0
