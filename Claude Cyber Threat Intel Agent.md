# Claude Cyber Threat Intel Agent

**Summary:** An agent that gathers threat intel on an IP/domain name/online entity from numerous sources (AbuseIPDB, VirusTotal, Any.Run, URLScan.io, Shodan, Censys, etc.) and deconflicts the information taken from those sources before putting it all together into a comprehensive HTML report that maintains the links in order to allow the human in the loop to verify. Can also update reports based on newer threat intel on the same targets.

**Sources:**

- **AbuseIPDB**
  - Attack History, Countries Targeted, Reputation, Community Comments, WHOIS Data
- **VirusTotal**
  - EDR Hits, Related Entities and Files, Community Comments
- **Any.Run, JoeSandbox, HybridAnalysis**
  - Associated Malware, API Calls, Beaconing
- **Shodan/Censys**
  - Exposed Ports, Exposed Certs, Associated Technologies
