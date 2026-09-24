# CAARS — Cyber Threat Intelligence Aggregation, Analysis, and Reporting System

This file gives Claude working context for this project. It supplements (does not replace) the parent `CLAUDE.md` one level up, which sets tone: **professional and concise without leaving out critical detail.** That standard applies with extra weight here — this system's output is read by SOC/IR analysts making real triage decisions, so precision and sourcing discipline matter more than brevity.

Status: **design phase.** Nothing in `/CAARS` is running code yet — this folder currently holds the original concept note, an implementation outline, an HTML report prototype, this file, and a `skills/` folder of draft skills. Treat anything below as the current design intent, not a description of a working system, until the user says otherwise.

## Source documents in this folder

- `Claude Cyber Threat Intel Agent.docx` — the original one-paragraph concept note. Ground truth for *intent*: aggregate multi-source threat intel on an indicator, deconflict it, produce a linked HTML report a human can verify, and support re-running to update that report.
- `CTI_Multi_Agent_Implementation_Outline.docx` — the architecture document this project is currently building toward. Everything in the "Architecture" and "Data Model" sections below is summarized from it. Read it directly for full rationale, the phased roadmap, and open questions if a decision needs more context than this file carries.
- `CTI_Report_Prototype.html` — a static design mock of the report output (sample/fictional data — target IP is an RFC 5737 documentation-reserved address). This is the visual and structural reference for the `cti-report-writer` skill. Open it in a browser to see the intended look before generating a real report.

## What the system does

Given an indicator (IP, domain, file hash, or URL), CAARS queries multiple threat-intel sources in parallel, reconciles disagreements between them, and produces a single self-contained HTML report with a citation link on every sourced claim so an analyst can verify it directly. Re-running against a previously-investigated indicator updates the report and highlights what changed, rather than starting over.

This is explicitly **verification support for a human analyst, not an autonomous action system.** See "Human-in-the-loop guardrails" below before building anything that could be read as automated remediation.

## Architecture: orchestrator + scoped sub-agents

One lead orchestrator agent dispatches scoped, single-purpose sub-agents in parallel, then converges their output through deconfliction and enrichment before a report-writer agent renders the final HTML. This mirrors the sub-agent pattern already built into Claude's own agent tooling (lead agent → scoped workers with restricted tool access → synthesis), and maps onto the Claude Agent SDK with each threat-intel source wrapped as its own MCP server.

| Agent | Responsibility | Tools |
|---|---|---|
| **Orchestrator** | Validates/normalizes the input indicator, determines which collectors apply to that indicator type, dispatches collectors concurrently with timeouts, hands results to deconfliction + enrichment, returns the report location | Sub-agent dispatch only — no direct API access |
| **Reputation collector** | AbuseIPDB, VirusTotal → normalized records | `abuseipdb.*`, `virustotal.*` |
| **Sandbox collector** | Any.Run / JoeSandbox / HybridAnalysis — checks for an *existing* report by default; fresh submission is analyst-opt-in only (see guardrails) | `anyrun.*`, `joesandbox.*`, `hybridanalysis.*` |
| **Infrastructure collector** | Shodan, Censys → exposure/technology data | `shodan.*`, `censys.*` |
| **Deconfliction agent** | Groups records by claim type, weighs by source reliability + recency, computes a consensus verdict/confidence score, explicitly surfaces disagreement rather than averaging it away | Pure reasoning over structured input — no external tools |
| **Enrichment agent** | Runs in parallel with deconfliction. Takes malware family names, Windows API calls, Windows kernel structure names, and Linux `.so`/`.ko` names extracted from sandbox/infra records and looks each up for plain-language, cited context (not a verdict) | `malpedia.*`, `msdocs.*`, `ntdoc.*`, `vergilius.*`, `linuxdocs.*` |
| **Report-writer agent** | Renders deconflicted findings + enrichment annotations into the HTML template, preserving citation links; on re-run, diffs against the prior stored record set and writes a change-log banner | File write; prior-report/record read |

**Why sub-agents instead of one agent with many tools:** parallelism (collectors are independent — sandbox lookups especially are slow), fault isolation (a down/rate-limited source fails without corrupting a shared context mid-reasoning), and least-privilege auditability (each collector only holds credentials for its own source family — relevant because targets are sometimes attacker-controlled infrastructure).

### Indicator sources vs. reference/enrichment sources

These are two different kinds of source and get treated differently:

- **Indicator sources** (AbuseIPDB, VirusTotal, Any.Run/JoeSandbox/HybridAnalysis, Shodan/Censys) are queried *by the indicator* and produce opinions/observations that get a vote in deconfliction.
- **Reference sources** (Malpedia, Microsoft Learn Win32/COM docs, Vergilius Project, ntdoc.m417z.com, Linux man pages/kernel docs) are queried *by a term* the indicator sources surfaced (a malware family name, an API call, a kernel structure, a library/module name). They explain what something is, not whether it's malicious — they don't get a vote, they get cited as context. Restating documentation as though it were a verdict is a correctness bug, not a style nit.
- Vergilius Project and ntdoc.m417z.com are **community reverse-engineering efforts**, not vendor-published docs — tag them distinctly (`community`/`unofficial`) everywhere they're cited, and record the OS build a Vergilius structure layout applies to (`version_context`) since kernel offsets differ across builds.
- A term with **no matching reference documentation is a valid, informative finding** — say so explicitly ("no reference found") rather than dropping it. Custom/attacker-authored artifact names routinely won't resolve, and that absence is itself a signal.

## Data model

Every collector's job is "call the API *and* translate the response into this schema" — one record per discrete claim, not one record per API call.

**Indicator record** (reputation / sandbox / infrastructure collectors):

| Field | Type | Notes |
|---|---|---|
| `indicator` | string | Normalized IP / domain / hash / URL |
| `indicator_type` | enum | `ip \| domain \| hash \| url` |
| `source` | string | e.g. `"VirusTotal"` |
| `claim_type` | enum | `verdict \| malware_family \| exposed_service \| infrastructure \| behavior \| reputation_signal` |
| `value` | string/object | The observation itself |
| `confidence` | 0–100 | Source-reported, if available |
| `first_seen` / `last_seen` | datetime | Source-reported temporal bounds |
| `evidence_url` | URL | **Required.** Direct link back to the source record — this is what makes the report human-verifiable. If a claim has no `evidence_url`, it does not go in the report body. |
| `retrieved_at` | datetime | When this collector call was made — drives the update/diff workflow |

**Enrichment record** (reference sources — no confidence/verdict field; this isn't an opinion):

| Field | Type | Notes |
|---|---|---|
| `subject` | string | The term being explained, e.g. `"NtMapViewOfSection"` |
| `subject_type` | enum | `malware_family \| windows_api_call \| windows_kernel_structure \| linux_shared_object \| linux_kernel_object` |
| `source` | string | `Malpedia \| Microsoft documentation \| Vergilius Project \| ntdoc.m417z.com \| Linux documentation` |
| `summary` | string | Plain-language explanation |
| `evidence_url` | URL | Link to the specific page/entry |
| `version_context` | string | OS build/version this applies to; blank if not version-specific |
| `retrieved_at` | datetime | Enrichment lookups can be cached far longer than indicator records |

Validate both shapes at the collector/enrichment output boundary — malformed source data should fail loudly there, not silently corrupt deconfliction.

## Human-in-the-loop guardrails

These are non-negotiable design constraints carried over from the implementation outline, not suggestions to be traded off for convenience later:

1. **No auto-remediation.** The system produces reports. It does not push blocks/allows to a firewall, EDR, or SOAR playbook. That is a deliberate future integration, not part of this build.
2. **Every claim in the report body is a citation.** If a sentence can't be traced to an `evidence_url`, it belongs in the "AI-inferred synthesis" section (clearly tagged as hypothesis), not stated as fact.
3. **Conflicts are surfaced, never averaged away.** If AbuseIPDB shows heavy abuse and VirusTotal shows zero detections, the report says that plainly — it does not blend into a mushy "medium" score.
4. **Sandbox submission is opt-in per run.** Default to checking for an *existing* sandbox report. Submitting a live sample/URL for fresh detonation can tip off an attacker monitoring their own infrastructure and costs quota — that requires an explicit analyst flag.
5. **Reference context is never restated as a verdict.** A legitimate Win32 API or common library showing up in a trace is descriptive context next to the behavior that made it noteworthy — not evidence on its own.
6. **Unofficial/community sources are labeled as such**, every time, including the OS build a Vergilius layout applies to.

## Report conventions (see `CTI_Report_Prototype.html`)

- Two-column layout: a sticky dark "spine" (verdict, confidence bar, key facts, contents nav, related artifacts) + a light document column with numbered sections.
- Citation superscripts are visually distinct by source class: solid dark badge = official/vendor source, dashed-outline badge = community/unofficial source, dashed "no-ref" tag = term looked up with no documentation found. Preserve this distinction — it's load-bearing, not decorative.
- Section order: Executive Summary → Flagged for Review (conflicts) → per-source-family evidence sections → Deconfliction Detail (table, amber = conflict / sage = agreement) → AI-Inferred Synthesis (explicitly tagged, not sourced to a citation) → Sources (grouped by section, tagged official vs. community).
- On re-run, an amber "Updated since the last report" banner at the top of the Executive Summary states concretely what changed (e.g. "VirusTotal detections rose from 3/89 to 41/89").
- Footer states which agents ran and the retrieval time window — keep this provenance line in every report.

## Draft skills in `skills/`

Preliminary, user-reviewable — not yet registered as live Claude Desktop skills. Each corresponds to one pipeline stage:

- `skills/cti-report-writer/` — renders deconflicted + enriched findings into the HTML report format above.
- `skills/cti-collector-builder/` — scaffolds a new indicator-source MCP collector and its normalization mapping into the Indicator Record schema.
- `skills/cti-deconfliction/` — the grouping/weighting/consensus-scoring/conflict-flagging logic.
- `skills/cti-enrichment/` — the term-lookup-and-annotation logic across the five reference sources.

## Build phase (per implementation outline §9)

1. MVP — orchestrator + AbuseIPDB/VirusTotal collectors, agreement-only deconfliction, static HTML template with citations.
2. Full source coverage — add Shodan/Censys + sandbox collectors, all four indicator types, enrichment agent.
3. Real deconfliction engine — source/recency weighting, confidence scoring, explicit conflict flagging.
4. Update/re-run workflow — persisted per-indicator record history, diff-based change log, opt-in scheduled re-checks.
5. Operationalize — audit logging, quota dashboards, retention/redaction policy, optional human-gated SOAR/SIEM hand-off.

Ask which phase is current before assuming scope on a given task — this file will fall out of date faster than the phase progresses.

## Open questions (per implementation outline §11 — resolve before locking in design)

- Which of the seven credentialed sources are keys/tiers already secured for, and does any cost/seat limit affect build order?
- Analyst-initiated lookups only, or also automatic triage off an alert feed?
- Where do reports live — flat HTML files, an internal web app, or a case-management/SOAR integration?
- Retention policy for historical reports and raw source data, especially WHOIS/PII fields?
- Curated internal reference table vs. search-backed MCP tool for documented Windows APIs and Linux `.so`/`.ko` docs?
