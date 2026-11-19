# Triage report

**Goal:** Our firewall shows a workstation connecting to 162.243.103.246 on port 8080 a few times last night. Is this C2 traffic and what should I do?

**Verdict:** suspicious (confidence: medium)  
**Generated:** 2026-11-19T09:38:05+05:30

## Summary

An analysis of the external IP address 162.243.103.246 showed historical associations with malware botnet Command and Control infrastructure, specifically Feodo Tracker / Emotet C&C indicators, alongside open ports including 8080. The IP is hosted on DigitalOcean cloud infrastructure with associated hostnames such as wearoddball.com.

## Findings

- InternetDB lookup shows the IP 162.243.103.246 is active on ports 22, 80, 443, and 8080, and is hosted on cloud infrastructure with associated hostnames 'www.wearoddball.com' and 'wearoddball.com'. [s2]
- RDAP lookup confirms the IP belongs to DigitalOcean, LLC and was registered in September 2013. [s3]
- Tor exit node check confirms the IP is not a Tor exit node. [s4]
- Web search results tie the IP address to AbuseIPDB and Feodo Tracker referencing historical Emotet C&C activity. [s5]

## Recommendations

- Isolate the workstation that initiated outbound connections to IP 162.243.103.246 on port 8080.
- Perform a forensic triage and malware scan on the affected workstation to check for potential Emotet or other botnet infections.
- Block outbound traffic to IP 162.243.103.246 at the firewall level if unauthorized.

## Gaps

- AlienVault OTX lookup failed due to a timeout error.
- Initial targeted web search for the specific IP string yielded no results due to query syntax issues.

## What the agent did

| step | tool | args | result | attempts | time |
|---|---|---|---|---|---|
| s1 | otx_lookup | `{"indicator": "162.243.103.246"}` | failed: timeout: no answer after 30s | 2 | 61.5s |
| s1b | web_search | `{"query": "\"162.243.103.246\" threat intel OR malware OR c2"}` | failed: unexpected result: none of the 5 results mention 162.243.103.246 (recovery for s1) | 1 | 15.93s |
| s2 | internetdb_lookup | `{"ip": "162.243.103.246"}` | ok | 1 | 0.05s |
| s3 | rdap_lookup | `{"target": "162.243.103.246"}` | ok | 1 | 0.15s |
| s4 | tor_exit_check | `{"ip": "162.243.103.246"}` | ok | 1 | 1.5s |
| s5 | web_search | `{"query": "162.243.103.246", "mode": "text"}` | ok | 1 | 18.41s |

## Self-check

- tool calls: 6, failed: 2, recovered: 0, failed with no recovery: 1
- findings backed by evidence: 4, not backed: 0
- result: passed

## Sources

- https://www.abuseipdb.com/check/162.243.103.246
- https://feodotracker.abuse.ch/browse/host/162.243.103.246/
- https://www.shodan.io/host/162.243.103.246
- https://www.virustotal.com/gui/ip-address/162.243.103.246
- https://whoisfreaks.com/tools/dns/reverse/lookup/a/162.243.103.246
