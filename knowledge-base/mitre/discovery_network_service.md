# MITRE ATT&CK — Network Service Discovery

**Framework:** MITRE ATT&CK (Enterprise), Discovery
**Technique:** T1046 (Network Service Discovery)
**Authoritative source:** <https://attack.mitre.org/techniques/T1046/>

> Adversaries enumerate services running on remote hosts — port scans,
> banner grabs, vulnerability sweeps — to find something worth exploiting.
> Discovery is rarely damaging by itself; its value to a defender is as an
> early-warning signal that positions later alerts in a campaign timeline.

## Key points

- **Typical indicators:** IDS signatures for scanning tools (nmap, masscan),
  bursts of connection attempts across many ports from one source, and
  repeated firewall denials from a single origin (the noisy-scan case).
- **Authorized scanners are the dominant false positive:** vulnerability
  management and asset inventory tooling scans continuously. Maintain an
  allow-list of scanner source addresses and alert on scans from anywhere
  else.
- **Severity logic:** medium alone — but correlate forward: a scan followed
  by connection attempts or exploit signatures against the probed services
  from the same source is a materially stronger finding.
- **Response:** identify the source; if unauthorized, review exposure of the
  probed ports, and watch that source for follow-on activity.

## How this knowledge base uses it

Grounds the "port scan" event type (T1046) in the SOC pipeline, the
`network_port_scan` Sigma rule, and the firewall-block-burst correlation
that catches scans manifesting as denial bursts.

*This entry is an original summary; consult the authoritative source above
for complete and current technique detail.*
