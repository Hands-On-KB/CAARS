# CTI Aggregation, Analysis, and Reporting System (CAARS)
## Summary
CAARS is my attempt at creating a cyber threat intelligence engine using a multi-agent orchestrated system. This is mainly intended to save analysts time for deeper investigation and following up on specific leads or threads.

## Structure
One orchestrator agent receives the target (IP / domain / hash / URL), fans work out to specialist “collector” sub-agents — one per source or source family — running in parallel, then hands their normalized findings to a deconfliction step and a report-writing step. This mirrors the sub-agent pattern already used in Claude's own agent tooling (a lead agent dispatching scoped, single-purpose sub-agents), and maps cleanly onto the Claude Agent SDK plus the Model Context Protocol (MCP), where each threat-intel source becomes its own MCP server exposing a small set of well-defined tools.
