# Triage report

**Goal:** Investigate 185.220.101.1 and tell me if it is malicious

**Verdict:** suspicious (confidence: high)  
**Generated:** 2026-11-19T09:36:16+05:30

## Summary

Investigation of the IP address 185.220.101.1 indicates that it operates as an active Tor exit node registered to Artikel10 e.V. in Germany. While threat intelligence platforms have flagged the IP in various security contexts including honeytrap data and scanning activities, these detections align with its primary function as an anonymity network infrastructure rather than direct targeted malicious attacks.

## Findings

- InternetDB lookup shows the IP hosts open ports 80, 443, 9001, and 9002, with hostnames associated with a Tor exit node and tags indicating self-signed certificates and Tor usage. [s1]
- AlienVault OTX records associate the IP with 50 threat pulses, including recent honeypot detections, web scanning reports, and validation confirming it as a Tor exit node. [s2]
- RDAP lookup reveals the IP is registered to Artikel10 e.V. in Germany under the organization ARTIKEL10. [s3]
- A dedicated Tor exit node check confirms that 185.220.101.1 is currently operating as a verified Tor exit node. [s4]

## Recommendations

- Treat traffic originating from this IP address with caution due to its status as a Tor exit node.
- Implement context-aware access controls if connections from anonymization networks violate organizational policy.

## Gaps

- No specific malicious payload delivery or targeted exploitation attempts could be directly attributed to the IP beyond standard security scanner and honeypot interaction logs typical of public exit nodes.

## What the agent did

| step | tool | args | result | attempts | time |
|---|---|---|---|---|---|
| s1 | internetdb_lookup | `{"ip": "185.220.101.1"}` | ok | 1 | 0.05s |
| s2 | otx_lookup | `{"indicator": "185.220.101.1"}` | ok | 1 | 10.91s |
| s3 | rdap_lookup | `{"target": "185.220.101.1"}` | ok | 1 | 0.48s |
| s4 | tor_exit_check | `{"ip": "185.220.101.1"}` | ok | 1 | 1.07s |

## Self-check

- tool calls: 4, failed: 0, recovered: 0, failed with no recovery: 0
- findings backed by evidence: 4, not backed: 0
- result: passed
