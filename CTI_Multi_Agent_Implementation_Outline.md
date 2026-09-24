# Cyber Threat Intelligence Multi-Agent Collection & Reporting System

### Implementation Outline

*Prepared September 24, 2026*

**Architecture:** multi-agent orchestrator on the Claude Agent SDK, with each intelligence source wrapped as an MCP tool server

## 1. Executive Summary

The idea in your original note — an agent that pulls threat intelligence on an IP, domain, or other entity from multiple sources, reconciles disagreements between those sources, and produces a linked, human-verifiable report — is sound and matches a pattern that is already well-suited to agentic AI: parallel data collection, normalization, conflict resolution, and structured writing.

This outline recommends building it as a multi-agent system rather than a single agent with many tools. One orchestrator agent receives the target (IP / domain / hash / URL), fans work out to specialist “collector” sub-agents — one per source or source family — running in parallel, then hands their normalized findings to a deconfliction step and a report-writing step. This mirrors the sub-agent pattern already used in Claude's own agent tooling (a lead agent dispatching scoped, single-purpose sub-agents), and maps cleanly onto the Claude Agent SDK plus the Model Context Protocol (MCP), where each threat-intel source becomes its own MCP server exposing a small set of well-defined tools.

The rest of this document lays out: the architecture and data flow, the normalized data model that makes deconfliction possible, how it maps onto the Claude Agent SDK + MCP concretely, the human-in-the-loop design, operational and security considerations specific to handling threat-intel APIs, and a phased build roadmap starting from a minimal two-source MVP.

## 2. Concept Recap

As described in the source document, the system should, for a given indicator (IP, domain, or online entity):

  - Query multiple threat-intel sources in parallel

  - Deconflict disagreements between those sources (e.g. one source flags malicious, another has no record)

  - Assemble a single comprehensive HTML report that preserves links back to each source, so a human analyst can verify any claim

  - Support re-running against the same target later and updating the report with what has changed

  - Enrich sandbox and infrastructure findings — malware family names, Windows API calls, Linux shared-object/kernel-module names — with explanatory reference context, so the report explains what those findings mean, not just that they occurred

The sources named, and what each contributes:

| **Source**                              | **Category**              | **Data pulled**                                                                       |
| --------------------------------------- | ------------------------- | ------------------------------------------------------------------------------------- |
| **AbuseIPDB**                           | Reputation / abuse feed   | Attack history, countries targeted, abuse confidence score, community comments, WHOIS |
| **VirusTotal**                          | Multi-AV / EDR aggregator | EDR / AV detections, related entities and files, community comments and votes         |
| **Any.Run, JoeSandbox, HybridAnalysis** | Dynamic sandbox analysis  | Associated malware families, API call traces, network beaconing behavior              |
| **Shodan / Censys**                     | Internet-wide scanning    | Exposed ports/services, exposed TLS certs, associated technologies/banners            |

Two things about this list matter architecturally. First, the sources fall into distinct families with different interaction models: reputation/feed lookups (AbuseIPDB, VirusTotal) are fast, cheap, read-only GETs; sandbox services (Any.Run, JoeSandbox, HybridAnalysis) may require a submission + polling workflow if no prior report exists, and are slower and rate-limited; internet-scan sources (Shodan, Censys) are fast lookups but track infrastructure, not verdicts. Second, every source returns opinions or observations, not ground truth — which is exactly why a deconfliction step, not just concatenation, is needed before writing the report.

Two of the data points those sources surface — malware family names from the sandboxes/VirusTotal, and Windows API calls or Linux shared-object (.so) / kernel-object (.ko) names from sandbox traces and infrastructure scans — mean little to an analyst without context. A trace that calls CreateRemoteThread is explainable from Microsoft's own docs; a trace that calls an undocumented native API like NtMapViewOfSection, or a host that exposes libpcap.so.0.8, isn't — Microsoft doesn't publish that, and man pages aren't part of a threat-intel feed. Add five reference sources to close that gap:

| **Source**                  | **Category**                                                   | **Data pulled**                                                                                                                                                                                                                |
| --------------------------- | -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Malpedia**                | Malware family reference                                       | Family profiles, aliases, associated actors/campaigns, and references for malware families named by sandbox or AV sources                                                                                                      |
| **Microsoft documentation** | Windows API reference (official)                               | Win32/COM API function purpose and behavior, for officially documented Windows API calls observed in sandbox traces                                                                                                            |
| **Vergilius Project**       | Windows kernel structure reference (community, build-specific) | Reverse-engineered kernel structure/object layouts (e.g. EPROCESS, ETHREAD, KTHREAD) across Windows builds, for interpreting kernel-mode findings Microsoft doesn't publicly document                                          |
| **ntdoc.m417z.com**         | Windows Native API reference (community, undocumented)         | Function signatures and descriptions for undocumented Nt\*/Zw\* native API calls (ntdll.dll) that malware uses for process injection, syscall-based evasion, etc., and that don't appear in Microsoft's official documentation |
| **Linux documentation**     | Linux library / kernel reference                               | man pages, package metadata, and kernel module documentation for shared object (.so) and kernel object (.ko) files observed on exposed or analyzed hosts                                                                       |

These five are queried differently from the four above: not by indicator (IP/domain/hash/URL), but by the malware family names, API call names, kernel structure names, and library/module names that the Sandbox and Infrastructure collectors already extracted. They're also a different kind of source — reference documentation rather than threat opinion — so they don't get a vote in the deconfliction step, they get cited as context. Section 3 introduces a dedicated enrichment agent for this.

## 3. Recommended Architecture: Multi-Agent Orchestrator Pattern

Use one lead orchestrator agent that fans work out to scoped, single-purpose sub-agents, then converges the results through a deconfliction step before writing. This is the same shape as the sub-agent pattern already built into Claude's own agent tooling: a coordinating agent that spawns narrowly-scoped workers with restricted tool access, then synthesizes their output. Three reasons this beats a single “one agent, many tools” design for this use case:

  - **Parallelism.** The reputation, sandbox, and infrastructure sources are independent — querying them in parallel instead of sequentially cuts wall-clock time substantially, and sandbox lookups in particular can be slow.

  - **Fault isolation.** If Shodan is down or rate-limited, that collector fails without derailing the AbuseIPDB/VirusTotal collectors or corrupting a single agent's context with an error mid-reasoning.

  - **Least privilege & auditability.** Each collector only holds credentials/tools for its own source family. It's easy to see, log, and rate-limit exactly which agent called which external API with which target — important when the targets are sometimes attacker-controlled infrastructure.

High-level flow:

```
  Analyst input (IP / domain / hash / URL)
            |
            v
      ORCHESTRATOR  -- validates target, sets scope
            |  dispatches in parallel
   +--------+-------------------+
   v            v                v
 Reputation   Sandbox        Infrastructure
 collector    collector      collector
 (AbuseIPDB,  (Any.Run,      (Shodan,
  VirusTotal)  JoeSandbox,    Censys)
               HybridAnalysis)
   +--------+-------------------+
            |  normalized records
   +--------+----------------------------+
   v                                      v
 DECONFLICTION AGENT              ENRICHMENT AGENT
 -- all collector records ->      -- malware family / API call /
    consensus verdict,               kernel structure / .so / .ko
    confidence, conflicts             names -> Malpedia, MS docs,
                                       Vergilius, ntdoc.m417z.com,
                                       Linux docs context
   +--------+----------------------------+
            v
      REPORT-WRITER AGENT  -- HTML report, cited links, diffed vs. prior run
            v
      Human analyst review / verification
```

Roles in detail:

| **Agent**                    | **Responsibility**                                                                                                                                                                                                                                                                                                                                                                                                                                                          | **Tools it needs**                                                |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| **Orchestrator**             | Accepts the target + investigation scope, validates/normalizes input (e.g. resolve indicator type), dispatches collector sub-agents in parallel, tracks completion/timeouts, hands results to the deconfliction agent, returns the final report location                                                                                                                                                                                                                    | Sub-agent dispatch only — no direct API access (least privilege)  |
| **Reputation collector**     | Calls AbuseIPDB and VirusTotal, normalizes each into the shared record schema (Section 5)                                                                                                                                                                                                                                                                                                                                                                                   | MCP: abuseipdb.\*, virustotal.\*                                  |
| **Sandbox collector**        | Checks Any.Run / JoeSandbox / HybridAnalysis for existing reports on the indicator; submits for fresh analysis only if explicitly authorized (cost/time implications); normalizes results                                                                                                                                                                                                                                                                                   | MCP: anyrun.\*, joesandbox.\*, hybridanalysis.\*                  |
| **Infrastructure collector** | Calls Shodan and Censys for exposure/technology data, normalizes results                                                                                                                                                                                                                                                                                                                                                                                                    | MCP: shodan.\*, censys.\*                                         |
| **Deconfliction agent**      | Reconciles the normalized records: resolves agreements/conflicts, computes a consensus verdict and confidence score, flags anything that needs analyst attention                                                                                                                                                                                                                                                                                                            | None (pure reasoning over structured input)                       |
| **Enrichment agent**         | Extracts the distinct malware family names, Windows API calls, Windows kernel structure names, and Linux shared-object/kernel-module names from the Sandbox and Infrastructure collectors' records; looks each up in Malpedia, Microsoft's official API documentation, ntdoc.m417z.com and the Vergilius Project (for undocumented Windows internals), and Linux documentation; attaches a plain-language, cited reference annotation to each — not a verdict, just context | MCP: malpedia.\*, msdocs.\*, ntdoc.\*, vergilius.\*, linuxdocs.\* |
| **Report-writer agent**      | Renders the deconflicted findings and reference annotations into the HTML report template, preserving citation links to every source claim; on re-run, diffs against the prior report and highlights changes                                                                                                                                                                                                                                                                | File write; prior-report read (for diffing)                       |

## 4. Data Flow, Step by Step

1.  Analyst submits a target and its type (IP, domain, hash, or URL) to the orchestrator, optionally with a scope flag (e.g. “no live sandbox submission, lookup only”).

2.  Orchestrator validates the input (format, defanging/refanging, private-IP and allow-list checks so internal infrastructure isn't accidentally queried against public feeds) and determines which collectors are relevant to that indicator type (e.g. Shodan/Censys don't apply to a file hash).

3.  Orchestrator dispatches the applicable collector sub-agents concurrently, each with a timeout and its own error handling.

4.  Each collector calls its MCP tool(s), receives raw source data, and maps it into the shared normalized record schema (Section 5) — including the exact source URL for every claim it extracts.

5.  Orchestrator collects all normalized records (or partial results plus failure notes if a source timed out or errored) and passes the full set to the deconfliction agent; it also extracts the distinct malware family names, Windows API calls (documented and undocumented), Windows kernel structure names, and Linux shared-object/kernel-module names present in the Sandbox and Infrastructure collectors' records and passes those to the enrichment agent.

6.  Deconfliction agent groups records by claim type (e.g. “malicious verdict,” “associated malware family,” “exposed service”), resolves agreement/disagreement, and produces a consensus verdict, a confidence score, and an explicit list of unresolved conflicts.

7.  Enrichment agent, running in parallel with deconfliction, looks up each distinct term: Malpedia for malware families, Microsoft's Win32/COM API documentation for documented Windows API calls, ntdoc.m417z.com for undocumented native (Nt\*/Zw\*) API calls that don't appear in Microsoft's own docs, the Vergilius Project for kernel structure/object layouts, and Linux man pages/kernel documentation for shared objects and kernel modules — producing a short cited reference annotation for each, or explicitly noting “no documentation found” when a term doesn't resolve, which is itself informative for custom or unusual artifacts.

8.  Report-writer agent renders the HTML report: executive verdict banner, per-source evidence sections with citation links, reference annotations attached to the relevant malware family/API call/library findings, a flagged-conflicts callout, and (on re-runs) a change log against the prior report for the same indicator.

9.  Report is handed to the analyst for verification; nothing here should auto-trigger a block/allow action without human sign-off (see Section 7).

10. On a later re-run for the same indicator, the orchestrator loads the prior report's records, re-runs collectors, and passes both old and new records to the deconfliction and report-writer agents so the output reads as an update, not a fresh report. Enrichment lookups can be cached aggressively across runs and indicators — a documented Windows API, an undocumented native API call, or a known Malpedia family profile doesn't change often — so re-runs should rarely need to re-query those five sources for terms already seen. Cache Vergilius lookups by (structure name, OS build) rather than by name alone, since kernel layouts differ across builds.

## 5. Core Data Model: the Normalized Indicator Record

Deconfliction is only tractable if every collector emits the same shape of record. Each collector's job is not just “call the API” but “call the API and translate the response into this schema,” one record per discrete claim (a single VirusTotal response might yield five or six records: one verdict, several related-file claims, etc.).

| **Field**                | **Type**      | **Purpose**                                                                                   |
| ------------------------ | ------------- | --------------------------------------------------------------------------------------------- |
| indicator                | string        | The normalized IP / domain / hash / URL being investigated                                    |
| indicator\_type          | enum          | ip | domain | hash | url                                                                      |
| source                   | string        | Which API produced this record, e.g. “VirusTotal”                                             |
| claim\_type              | enum          | verdict | malware\_family | exposed\_service | infrastructure | behavior | reputation\_signal |
| value                    | string/object | The actual observation, e.g. “malicious”, “Emotet”, “port 445 open”                           |
| confidence               | 0–100         | Source-reported confidence if available (e.g. AbuseIPDB abuse score, VT detection ratio)      |
| first\_seen / last\_seen | datetime      | Source-reported temporal bounds, used for recency weighting                                   |
| evidence\_url            | URL           | Direct link back to the source record — this is what makes the report human-verifiable        |
| retrieved\_at            | datetime      | When this collector call was made — needed for the update/diff workflow                       |

Keeping evidence\_url on every single record — not just at the report level — is what lets the report-writer agent cite the exact source for each specific sentence, and is central to the human-verifiability goal in the original concept.

The enrichment agent's output is a different, simpler shape, since these five sources aren't giving an opinion that needs weighing — they're explaining a term. No confidence or verdict field applies:

| **Field**        | **Type** | **Purpose**                                                                                                                                             |
| ---------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| subject          | string   | The term being explained, e.g. “Emotet”, “CreateRemoteThread”, “NtMapViewOfSection”, “libpcap.so.0.8”                                                   |
| subject\_type    | enum     | malware\_family | windows\_api\_call | windows\_kernel\_structure | linux\_shared\_object | linux\_kernel\_object                                       |
| source           | string   | Malpedia | Microsoft documentation | Vergilius Project | ntdoc.m417z.com | Linux documentation                                                          |
| summary          | string   | Plain-language explanation of what the term is/does                                                                                                     |
| evidence\_url    | URL      | Direct link to the Malpedia family page, Microsoft Learn article, Vergilius structure page, ntdoc.m417z.com entry, or man page/kernel doc               |
| version\_context | string   | OS build/version this annotation applies to, when the source is version-specific (e.g. a Vergilius kernel structure layout) — blank when not applicable |
| retrieved\_at    | datetime | When this lookup was made — these can be cached far longer than indicator records                                                                       |

A missing reference annotation (no Malpedia entry, no matching API doc, no man page) is a valid and useful outcome, not a failure — custom or newly-compiled malware artifacts often won't resolve to any documentation, and the report should say so explicitly rather than silently dropping the term.

## 6. Mapping onto the Claude Agent SDK + MCP

### 6.1 Each source is an MCP server

Wrap every threat-intel API behind its own small MCP server, exposing a handful of purpose-built tools rather than a generic HTTP-fetch tool. This keeps each collector sub-agent's tool surface minimal (easier to reason about, easier to rate-limit, easier to log per-source usage) and means adding a ninth source later is additive, not a rewrite.

| **Source** | **Example MCP tools exposed** |
| --- | --- |
| AbuseIPDB | `check(ip)`, `report_history(ip)` |
| VirusTotal | `lookup(indicator)`, `related_objects(indicator)` |
| Any.Run / JoeSandbox / HybridAnalysis | `get_existing_report(hash_or_url)`, `submit_for_analysis(target)` — gated, see Section 7 |
| Shodan / Censys | `host_lookup(ip)`, `cert_search(ip_or_domain)` |
| Malpedia | `search_family(name_or_alias)`, `get_family_profile(name)` |
| Microsoft documentation | `lookup_win32_api(function_name)` |
| Vergilius Project | `lookup_kernel_structure(name, os_build)` |
| ntdoc.m417z.com | `lookup_nt_api(function_name)` |
| Linux documentation | `lookup_shared_object(name)`, `lookup_kernel_module(name)` |

### 6.2 Orchestrator and sub-agents

Implement the orchestrator as the top-level Claude Agent SDK agent. It dispatches collector sub-agents the same way a lead agent spawns scoped workers: each sub-agent definition restricts which MCP servers/tools it can see (a sandbox collector should not have Shodan credentials, and vice versa). Run the three collector families concurrently and give the orchestrator a per-collector timeout with graceful degradation — a report that says “Shodan did not respond within 30s” is far better than a stalled run.

### 6.3 Deconfliction logic

This is the step most worth getting right, since it's the part with no direct upstream API to lean on. A workable approach:

  - **Group by claim\_type** across all sources for the same indicator.

  - **Weight by source reliability and recency** — e.g. a VirusTotal detection from 40 engines two days old outweighs a single AbuseIPDB community comment from 18 months ago. Keep these weights configurable, not hardcoded, since analysts will want to tune them.

  - **Compute a consensus verdict and confidence score** per indicator (e.g. malicious / suspicious / benign / unknown, 0–100).

  - **Explicitly surface disagreement** rather than silently averaging it away — if AbuseIPDB shows heavy abuse reports but VirusTotal shows zero detections, the report should say that plainly, not blend it into a mushy “medium” score. This is the human-in-the-loop safety valve.

### 6.4 Report generation

The report-writer agent's output is HTML, matching the original concept, with:

  - A summary banner: indicator, consensus verdict, confidence score, timestamp

  - One section per source family, each claim written as a sentence with an inline citation link to evidence\_url

  - A “flagged for review” callout box listing every unresolved conflict from the deconfliction step

  - On re-run: a change log section (“VirusTotal detections rose from 3/70 to 41/70 since the last report on …”), built by diffing the new normalized records against the previous run's stored records

### 6.5 State and update/re-run support

Persist each run's normalized records (not just the final rendered HTML) keyed by indicator, so re-runs can diff against a structured prior state rather than re-parsing old HTML. A simple per-indicator JSON history file or a lightweight database table is enough at MVP scale; this is also what enables scheduled re-checks later (e.g. “re-verify all indicators from active incidents nightly”).

### 6.6 Enrichment agent implementation notes

These five sources don't integrate the same way as the four indicator-based sources, and it's worth planning for that difference rather than discovering it mid-build:

  - **Malpedia** has a public JSON API (no key required for read access) keyed by malware family name or alias — this one is a straightforward MCP wrapper, similar in shape to the reputation sources.

  - **Windows API calls need a fallback chain, not one source.** Try Microsoft's official Win32/COM documentation first for well-known functions. When a sandbox trace shows a native Nt\*/Zw\* call that malware used to bypass Win32 and talk to ntdll directly — a common evasion technique — Microsoft's own docs won't have it; fall back to ntdoc.m417z.com, which documents exactly that undocumented surface. Microsoft's Win32/COM reference itself has no general public lookup API for an arbitrary function name, so plan on either a curated local reference table of commonly offense-relevant APIs (process injection, credential access, persistence primitives, etc.) that the team owns and refreshes periodically, or a scoped search/fetch against learn.microsoft.com with the same citation discipline as everything else here.

  - **Kernel-mode findings route to the Vergilius Project.** When a sandbox report or infrastructure finding involves kernel structures — a driver, a kernel exploit, a rootkit walking EPROCESS/ETHREAD chains — look up the relevant structure layout on the Vergilius Project. This is the one enrichment source that's version-specific: kernel structure offsets change across Windows builds, so a lookup needs the target OS build, and the resulting annotation must record which build it applies to (version\_context in Section 5) — citing a Windows 11 24H2 structure layout against a Windows 10 host would mislead an analyst.

  - **Linux shared-object and kernel-module documentation** is similarly not API-driven. Realistic sources are man pages (e.g. man7.org, or man-db on a build host) and package metadata for known .so files tied to common packages, and kernel.org / distro kernel documentation for .ko files. Custom or attacker-authored .so/.ko names — common in malware — won't resolve to any documentation, which the enrichment agent should report as a explicit finding, not an omission.

  - **Label community-sourced references distinctly.** Vergilius Project and ntdoc.m417z.com are community reverse-engineering efforts, not vendor-published documentation like Microsoft's own docs or Malpedia. Tag their citations as “unofficial/community-sourced” in the report so an analyst can weight them accordingly — accurate in practice, but not an authoritative Microsoft statement about the function or structure in question.

  - **Cache aggressively.** Unlike indicator verdicts, these lookups are keyed by a term (an API name, a family name, a structure name, a library name) that recurs across many unrelated investigations and changes documentation rarely — a shared, long-lived cache across all investigations (not just per-indicator) cuts most of the repeat-lookup cost. Key Vergilius cache entries by (structure name, OS build), not by name alone.

## 7. Human-in-the-Loop Design

The original concept explicitly frames this as verification support for a human analyst, not an autonomous action system. A few concrete guardrails keep it that way:

  - **No auto-remediation.** The system produces reports; it should not itself push blocks/allows to a firewall, EDR, or SOAR playbook. Wire that up as a deliberate later integration once the report's judgment has been trusted over time — not in the initial build.

  - **Every claim is a citation, not just the report.** If a sentence can't be traced to an evidence\_url, it shouldn't be in the report body — push it to an “AI-inferred synthesis” subsection instead so an analyst can tell inference apart from sourced fact at a glance.

  - **Conflicts are surfaced, not hidden.** Section 6.3's disagreement callout is the main analyst entry point for the cases that actually need a human judgment call.

  - **Sandbox submission is opt-in per run.** Submitting a live sample/URL to Any.Run/JoeSandbox/HybridAnalysis for fresh analysis (rather than checking for an existing report) can tip off an attacker monitoring their own infrastructure, and costs time/quota — make it a flag the analyst sets, not a default collector behavior.

  - **Reference context is not a verdict.** Malpedia, Microsoft's API docs, Vergilius, ntdoc.m417z.com, and Linux documentation describe what something is, not whether its presence here is malicious. A legitimate Win32 API like CreateRemoteThread or a common shared library must read in the report as descriptive context next to the sandbox behavior that made it noteworthy — never restated as though the documentation source itself flagged it.

  - **Unofficial sources are labeled as such.** Vergilius Project and ntdoc.m417z.com are community reverse-engineering efforts, not Microsoft-published documentation — the report should cite them distinctly from Malpedia and Microsoft's own docs, and show the Windows build a Vergilius structure layout applies to, so an analyst can judge how much weight to give it.

## 8. Security & Operational Considerations

| **Concern**                                                                                       | **Mitigation**                                                                                                                                                                                                                    |
| ------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| API credential sprawl across many sources                                                         | Store all keys in a secrets manager, not in agent config; scope each collector's MCP server to only its own credential                                                                                                            |
| Rate limits / cost (sandbox APIs especially)                                                      | Cache lookups per indicator with a TTL; prefer “check existing report” over fresh submission by default; track per-source quota usage centrally                                                                                   |
| Querying internal/private indicators against public feeds                                         | Orchestrator-level allow-list/deny-list check before any collector is dispatched (RFC1918 ranges, known internal domains)                                                                                                         |
| Tipping off adversaries who monitor lookups of their own infrastructure                           | Default to passive/existing-report lookups; require explicit analyst opt-in for active submission or WHOIS-triggering queries                                                                                                     |
| Source bias / noisy community data (esp. AbuseIPDB comments)                                      | Weight community-submitted signals lower than vendor-verified detections in the deconfliction step; always show the raw source so the analyst can judge for themselves                                                            |
| Report/API response data containing sensitive info (PII in WHOIS, etc.)                           | Define a retention policy for stored reports; redact personal WHOIS contact fields by default unless the investigation specifically needs them                                                                                    |
| Auditability of who investigated what, when                                                       | Log every collector call (source, target, timestamp, requesting analyst) centrally — useful both for compliance and for spotting quota problems                                                                                   |
| Custom/unusual malware artifacts don't match any reference documentation                          | Enrichment agent explicitly reports “no known documentation for this term” rather than omitting it silently — absence of documentation for an unusual API combination or a custom .so/.ko name is itself a signal worth surfacing |
| Community-sourced reference data (Vergilius, ntdoc.m417z.com) may be incomplete or build-specific | Cite these distinctly from vendor documentation in the report; for Vergilius, always record and display the Windows build the structure layout corresponds to so it isn't misapplied to a different build                         |

## 9. Phased Build Roadmap

Start narrow and prove the pipeline before adding breadth — the deconfliction and citation-preservation mechanics matter more early on than having all twelve sources wired up.

| **Phase** | **Goal**                           | **Key deliverables**                                                                                                                                                                                                                                                                                                                                                                                |
| --------- | ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1**     | MVP: prove the pipeline end to end | Single orchestrator + two collectors (AbuseIPDB, VirusTotal) as MCP servers; simple deconfliction (agreement/disagreement only, no weighting yet); static HTML report template with citation links                                                                                                                                                                                                  |
| **2**     | Full source coverage               | Add Shodan/Censys and sandbox (Any.Run/JoeSandbox/HybridAnalysis, existing-report-only) collectors; support all four indicator types (ip/domain/hash/url) with type-aware collector selection; add the enrichment agent (Malpedia, Microsoft API docs, Vergilius Project, ntdoc.m417z.com, Linux docs) once sandbox and infrastructure data is flowing, since that's what gives it terms to look up |
| **3**     | Real deconfliction engine          | Source-weighting and recency-weighting, consensus verdict + confidence score, explicit conflict-flagging surfaced in the report                                                                                                                                                                                                                                                                     |
| **4**     | Update / re-run workflow           | Persisted per-indicator record history, diff-based change log in re-run reports, opt-in scheduled re-checks for indicators tied to open investigations                                                                                                                                                                                                                                              |
| **5**     | Operationalize                     | Central call logging/audit trail, quota dashboards, retention/redaction policy for stored reports, optional SOAR/SIEM/ticketing hand-off (still human-gated) once the report quality has been validated in practice                                                                                                                                                                                 |

## 10. Tech Stack Summary

| **Layer**                    | **Recommendation**                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Agent orchestration          | Claude Agent SDK — orchestrator + collector/deconfliction/report sub-agents, each with scoped tool access                                                                                                                                                                                                                                                                                                                                                                     |
| Source integrations          | One MCP server per source (or tightly related source family), each exposing a small fixed tool set                                                                                                                                                                                                                                                                                                                                                                            |
| Reference/enrichment sources | Malpedia via its public JSON API; Windows API coverage split between Microsoft's official docs (documented Win32/COM calls) and ntdoc.m417z.com (undocumented native calls); Vergilius Project for build-specific kernel structure layouts; Linux .so/.ko documentation via man pages and kernel/package metadata — none of the Windows/Linux internals sources has a general public lookup API, so plan for a curated reference table and/or a scoped search-backed MCP tool |
| Shared record schema         | JSON schema per Section 5, validated at the collector output boundary so malformed source data can't silently corrupt deconfliction                                                                                                                                                                                                                                                                                                                                           |
| Persistence                  | Lightweight store (SQLite/Postgres, or even per-indicator JSON files at MVP scale) keyed by indicator, storing normalized records + rendered reports for diffing                                                                                                                                                                                                                                                                                                              |
| Report output                | Self-contained HTML per the original concept; keep the template simple enough that citation links are unambiguous and easy to click through                                                                                                                                                                                                                                                                                                                                   |
| Caching                      | TTL cache per (source, indicator) pair to control cost/rate-limit exposure on repeated lookups                                                                                                                                                                                                                                                                                                                                                                                |

## 11. Open Questions Worth Deciding Early

  - **API access:** which of the seven credentialed API sources (AbuseIPDB, VirusTotal, Any.Run, JoeSandbox, HybridAnalysis, Shodan, Censys) do you already have keys/tiers for, and are any of them cost- or seat-limited enough to affect which collector gets built first?

  - **Trigger model:** analyst-initiated lookups only, or also automatic triage off an alert feed (e.g. every new EDR alert's source IP gets auto-investigated)? This affects volume and cost planning significantly.

  - **Where reports live:** flat HTML files, a lightweight internal web app, or integrated into an existing case-management/SOAR tool?

  - **Retention:** how long should historical reports and raw source data be kept, especially if WHOIS or other data with personal information is involved?

  - **Reference source approach:** for documented Windows API and Linux .so/.ko documentation, is a curated internal reference table (more reliable, needs upkeep) preferable to a search-backed MCP tool against Microsoft Learn/man pages (broader coverage, less control)? Vergilius Project and ntdoc.m417z.com don't offer that choice — they're the only practical source for undocumented Windows internals — but worth prototyping the documented-API approach against a handful of real sandbox traces before committing.
