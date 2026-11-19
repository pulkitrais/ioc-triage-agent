"""The tools the agent can call.

Every tool is a plain function that takes keyword args and returns a dict.
If something goes wrong it raises ToolError with a short reason. The executor
handles timeouts, retries and validation, so the tools themselves stay simple.

All of these are free and need no API key. I picked them because they are what
I would actually open in a browser tab when triaging an alert.
"""

import ast
import ipaddress
import math
import operator
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

import requests

USER_AGENT = "ioc-triage-agent/0.1 (student project)"
HTTP_TIMEOUT = 20


class ToolError(Exception):
    pass


@dataclass
class Tool:
    name: str
    description: str
    args: dict  # arg name -> short description, used in the planner prompt
    func: object
    required_keys: tuple = ()  # keys a good result must contain
    timeout: float = 20
    fallback: str | None = None  # tool to try if this one keeps failing
    meta: dict = field(default_factory=dict)


def _get(url, **kwargs):
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=HTTP_TIMEOUT, **kwargs)
    except requests.RequestException as e:
        raise ToolError(f"request failed: {type(e).__name__}") from e
    return resp


def _get_json(url, ok_statuses=(200,), **kwargs):
    resp = _get(url, **kwargs)
    if resp.status_code not in ok_statuses:
        raise ToolError(f"HTTP {resp.status_code} from {url.split('?')[0]}")
    try:
        return resp.status_code, resp.json()
    except ValueError as e:
        raise ToolError(f"response from {url.split('?')[0]} was not JSON") from e


# ---------------------------------------------------------------- indicators

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)


def classify(indicator):
    """Return 'ip', 'cve', 'hash', 'domain' or None."""
    s = indicator.strip()
    try:
        ipaddress.ip_address(s)
        return "ip"
    except ValueError:
        pass
    if CVE_RE.fullmatch(s):
        return "cve"
    if HASH_RE.fullmatch(s):
        return "hash"
    if DOMAIN_RE.fullmatch(s):
        return "domain"
    return None


def extract_indicators(text):
    """Find IOCs in free text. Used as a hint for the planner and for the no-LLM fallback plan."""
    found = {"ip": [], "domain": [], "hash": [], "cve": []}
    for ip in IP_RE.findall(text):
        if classify(ip) == "ip" and ip not in found["ip"]:
            found["ip"].append(ip)
    for cve in CVE_RE.findall(text):
        if cve.upper() not in found["cve"]:
            found["cve"].append(cve.upper())
    for h in HASH_RE.findall(text):
        if h.lower() not in found["hash"]:
            found["hash"].append(h.lower())
    # people write "defanged" IOCs like evil[.]com, so undo that first
    cleaned = text.replace("[.]", ".").replace("(.)", ".")
    for d in DOMAIN_RE.findall(cleaned):
        d = d.lower().rstrip(".")
        if d not in found["domain"] and not IP_RE.fullmatch(d) and "." in d:
            found["domain"].append(d)
    return found


def _public_ip(ip):
    addr = ipaddress.ip_address(ip)
    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast:
        raise ToolError(f"{ip} is not a public address, nothing to look up")
    return ip


# ---------------------------------------------------------------- tools

def web_search(query, mode="text", max_results=5, timelimit=None):
    """DuckDuckGo-style metasearch via the ddgs package.

    ddgs rotates between engines and some of them return nothing from a
    datacenter IP, so I try a couple of backends before calling it a failure.
    """
    from ddgs import DDGS  # imported here so the rest works without it installed

    max_results = max(1, min(int(max_results), 10))
    last = None
    for backend in ("google", "bing", "auto"):
        try:
            if mode == "news":
                rows = DDGS().news(query, max_results=max_results, timelimit=timelimit or "w", backend=backend)
            else:
                rows = DDGS().text(query, max_results=max_results, timelimit=timelimit, backend=backend)
        except Exception as e:  # ddgs raises its own exception types
            last = str(e)[:120]
            continue
        if rows:
            results = []
            for r in rows:
                results.append({
                    "title": r.get("title", ""),
                    "url": r.get("href") or r.get("url", ""),
                    "snippet": (r.get("body") or "")[:300],
                    "date": r.get("date", ""),
                    "source": r.get("source", ""),
                })
            return {"query": query, "mode": mode, "results": results}
    raise ToolError(f"no search results ({last or 'empty'})")


def dns_lookup(name, record_type="A"):
    """Resolve a name with Google's DNS-over-HTTPS JSON API."""
    record_type = record_type.upper()
    _, data = _get_json("https://dns.google/resolve", params={"name": name, "type": record_type})
    status = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN"}.get(data.get("Status"), str(data.get("Status")))
    answers = [a.get("data") for a in data.get("Answer", [])]
    return {"name": name, "type": record_type, "status": status, "answers": answers}


def rdap_lookup(target):
    """Registration data (the modern WHOIS) for an IP or a domain via rdap.org."""
    kind = classify(target)
    if kind not in ("ip", "domain"):
        raise ToolError(f"rdap_lookup needs an IP or domain, got {target!r}")
    status, data = _get_json(f"https://rdap.org/{kind}/{target}", ok_statuses=(200, 404))
    if status == 404:
        return {"target": target, "found": False}
    events = {e.get("eventAction"): e.get("eventDate", "")[:10] for e in data.get("events", [])}
    entities = []
    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        name = ""
        for item in (ent.get("vcardArray") or [None, []])[1]:
            if item and item[0] == "fn":
                name = item[3]
        entities.append({"roles": roles, "name": name or ent.get("handle", "")})
    out = {
        "target": target,
        "found": True,
        "kind": kind,
        "name": data.get("name") or data.get("ldhName"),
        "handle": data.get("handle"),
        "country": data.get("country"),
        "status": data.get("status", []),
        "events": events,
        "entities": entities[:6],
    }
    if kind == "ip":
        out["range"] = f"{data.get('startAddress')} - {data.get('endAddress')}"
    if events.get("registration"):
        reg = datetime.fromisoformat(events["registration"]).date()
        out["registered_days_ago"] = (date.today() - reg).days
    return out


def internetdb_lookup(ip):
    """Shodan InternetDB: open ports, tags and known CVEs for an IP. Free, no key."""
    _public_ip(ip)
    status, data = _get_json(f"https://internetdb.shodan.io/{ip}", ok_statuses=(200, 404))
    if status == 404:
        return {"ip": ip, "found": False}
    return {
        "ip": ip,
        "found": True,
        "ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
        "tags": data.get("tags", []),
        "vulns": data.get("vulns", [])[:15],
    }


def otx_lookup(indicator):
    """AlienVault OTX community reputation. The general endpoint works without a key.

    The raw reply can be hundreds of KB, so I keep only the parts an analyst
    would read: pulse count, a few pulse names, tags, malware families and
    any allowlist ("validation") hits.
    """
    kind = classify(indicator)
    section = {"ip": "IPv4", "domain": "domain", "hash": "file"}.get(kind)
    if not section:
        raise ToolError(f"otx_lookup supports IPs, domains and hashes, got {indicator!r}")
    if kind == "ip" and ipaddress.ip_address(indicator).version == 6:
        section = "IPv6"
    _, data = _get_json(f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general")
    pulse_info = data.get("pulse_info") or {}
    pulses = pulse_info.get("pulses", [])
    tags, families = set(), set()
    for p in pulses[:50]:
        tags.update(t.lower() for t in p.get("tags", [])[:10])
        families.update(m.get("display_name", "") for m in p.get("malware_families", []) if isinstance(m, dict))
    return {
        "indicator": indicator,
        "pulse_count": pulse_info.get("count", len(pulses)),
        "recent_pulses": [{"name": p.get("name", "")[:90], "created": p.get("created", "")[:10]} for p in pulses[:5]],
        "top_tags": sorted(tags)[:20],
        "malware_families": sorted(f for f in families if f)[:10],
        "validation": [v.get("message", v.get("name", "")) for v in data.get("validation", [])][:5],
    }


_TOR_CACHE = {}


def tor_exit_check(ip):
    """Check the Tor Project's live bulk exit list."""
    _public_ip(ip)
    if "list" not in _TOR_CACHE:
        resp = _get("https://check.torproject.org/torbulkexitlist")
        if resp.status_code != 200 or "." not in resp.text:
            raise ToolError(f"could not fetch Tor exit list (HTTP {resp.status_code})")
        _TOR_CACHE["list"] = set(resp.text.split())
    exits = _TOR_CACHE["list"]
    return {"ip": ip, "is_tor_exit": ip in exits, "exit_nodes_in_list": len(exits)}


_KEV_CACHE = {}


def _kev():
    if "data" not in _KEV_CACHE:
        _, data = _get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        if "vulnerabilities" not in data:
            raise ToolError("CISA KEV feed had an unexpected shape")
        _KEV_CACHE["data"] = data
    return _KEV_CACHE["data"]


def cve_lookup(cve_id):
    """CVE record from MITRE plus EPSS score and CISA KEV status."""
    cve_id = cve_id.upper().strip()
    if not CVE_RE.fullmatch(cve_id):
        raise ToolError(f"{cve_id!r} does not look like a CVE id")
    status, rec = _get_json(f"https://cveawg.mitre.org/api/cve/{cve_id}", ok_statuses=(200, 404))
    if status == 404:
        return {"cve": cve_id, "found": False}
    cna = rec.get("containers", {}).get("cna", {})
    desc = next((d.get("value", "") for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "")
    cvss = None
    for m in cna.get("metrics", []):
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            if key in m:
                cvss = {"version": key, "score": m[key].get("baseScore"), "severity": m[key].get("baseSeverity")}
                break
        if cvss:
            break
    out = {
        "cve": cve_id,
        "found": True,
        "title": cna.get("title", ""),
        "description": desc[:500],
        "cvss": cvss,
        "affected": [f"{a.get('vendor', '')} {a.get('product', '')}".strip() for a in cna.get("affected", [])][:5],
        "published": rec.get("cveMetadata", {}).get("datePublished", "")[:10],
    }
    # EPSS and KEV are extras: if they fail I still return the CVE record
    try:
        _, epss = _get_json("https://api.first.org/data/v1/epss", params={"cve": cve_id})
        row = (epss.get("data") or [{}])[0]
        out["epss"] = {"probability": float(row["epss"]), "percentile": float(row["percentile"])} if row else None
    except (ToolError, KeyError, ValueError):
        out["epss"] = "unavailable"
    try:
        kev = next((v for v in _kev()["vulnerabilities"] if v["cveID"] == cve_id), None)
        out["in_cisa_kev"] = bool(kev)
        if kev:
            out["kev"] = {"date_added": kev["dateAdded"], "ransomware_use": kev.get("knownRansomwareCampaignUse")}
    except ToolError:
        out["in_cisa_kev"] = "unavailable"
    return out


def kev_recent(days=7):
    """CVEs CISA added to its Known Exploited Vulnerabilities list in the last N days."""
    days = max(1, min(int(days), 60))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).date().isoformat()
    rows = [v for v in _kev()["vulnerabilities"] if v.get("dateAdded", "") >= cutoff]
    rows.sort(key=lambda v: v["dateAdded"], reverse=True)
    return {
        "days": days,
        "count": len(rows),
        "entries": [
            {
                "cve": v["cveID"],
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "name": v.get("vulnerabilityName"),
                "date_added": v.get("dateAdded"),
                "ransomware_use": v.get("knownRansomwareCampaignUse"),
            }
            for v in rows[:15]
        ],
    }


# A tiny safe calculator. No eval(): I walk the AST and only allow numbers,
# arithmetic and a short list of functions.
_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
    ast.Div: operator.truediv, ast.Pow: operator.pow, ast.Mod: operator.mod,
    ast.FloorDiv: operator.floordiv, ast.USub: operator.neg, ast.UAdd: operator.pos,
}


def _days_since(iso_date):
    return (date.today() - datetime.fromisoformat(str(iso_date)[:10]).date()).days


_FUNCS = {
    "round": round, "min": min, "max": max, "abs": abs, "sum": lambda *a: sum(a),
    "sqrt": math.sqrt, "log": math.log, "log10": math.log10, "days_since": _days_since,
}


def _eval(node):
    if isinstance(node, ast.Expression):
        return _eval(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float, str)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        left, right = _eval(node.left), _eval(node.right)
        if isinstance(node.op, ast.Pow) and abs(right) > 100:
            raise ToolError("exponent too large")
        return _OPS[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.operand))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in _FUNCS:
        return _FUNCS[node.func.id](*[_eval(a) for a in node.args])
    raise ToolError(f"unsupported expression element: {type(node).__name__}")


def calculator(expression):
    """Evaluate arithmetic, e.g. '0.4*3 + 0.6*1' or 'days_since("2024-05-01")'."""
    try:
        tree = ast.parse(str(expression), mode="eval")
        value = _eval(tree)
    except ToolError:
        raise
    except (SyntaxError, ValueError, TypeError, ZeroDivisionError) as e:
        raise ToolError(f"could not evaluate {expression!r}: {e}") from e
    if isinstance(value, str):
        raise ToolError("expression must evaluate to a number")
    return {"expression": expression, "result": round(value, 6) if isinstance(value, float) else value}


# ---------------------------------------------------------------- registry

def build_registry():
    tools = [
        Tool("web_search", "Live web or news search. Use mode='news' with timelimit 'd'/'w'/'m' for recent events.",
             {"query": "search text", "mode": "'text' or 'news' (optional)", "max_results": "1-10 (optional)",
              "timelimit": "'d', 'w' or 'm' (optional)"},
             web_search, required_keys=("results",), timeout=25),
        Tool("dns_lookup", "Resolve a domain (A, AAAA, MX, TXT, NS records) using DNS-over-HTTPS.",
             {"name": "domain", "record_type": "A, AAAA, MX, TXT or NS (optional)"},
             dns_lookup, required_keys=("answers", "status"), timeout=15, fallback="web_search"),
        Tool("rdap_lookup", "Registration info (RDAP/WHOIS) for an IP or domain: owner, country, creation date, domain age.",
             {"target": "IP or domain"}, rdap_lookup, required_keys=("found",), timeout=20, fallback="web_search"),
        Tool("internetdb_lookup", "Shodan InternetDB for an IP: open ports, hostnames, tags (tor, vpn, c2...), known CVEs.",
             {"ip": "public IPv4"}, internetdb_lookup, required_keys=("found",), timeout=15, fallback="web_search"),
        Tool("otx_lookup", "AlienVault OTX community threat intel for an IP, domain or file hash: pulse count, tags, malware families.",
             {"indicator": "IP, domain or hash"}, otx_lookup, required_keys=("pulse_count",), timeout=30,
             fallback="web_search"),
        Tool("tor_exit_check", "Check whether an IP is currently a Tor exit node (live Tor Project list).",
             {"ip": "public IPv4"}, tor_exit_check, required_keys=("is_tor_exit",), timeout=20, fallback="internetdb_lookup"),
        Tool("cve_lookup", "Details for one CVE id: description, CVSS, EPSS exploit probability, CISA KEV status.",
             {"cve_id": "e.g. CVE-2024-3400"}, cve_lookup, required_keys=("found",), timeout=30, fallback="web_search"),
        Tool("kev_recent", "CVEs CISA added to the Known Exploited Vulnerabilities catalog in the last N days.",
             {"days": "1-60"}, kev_recent, required_keys=("entries",), timeout=30, fallback="web_search"),
        Tool("calculator", "Safe arithmetic. Supports + - * / ** %, round, min, max, sqrt, log, days_since('YYYY-MM-DD').",
             {"expression": "math expression"}, calculator, required_keys=("result",), timeout=5),
    ]
    return {t.name: t for t in tools}


def describe_tools(registry):
    lines = []
    for t in registry.values():
        args = ", ".join(f"{k}: {v}" for k, v in t.args.items())
        lines.append(f"- {t.name}({args}): {t.description}")
    return "\n".join(lines)
