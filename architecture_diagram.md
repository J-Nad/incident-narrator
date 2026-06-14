# Architecture Diagram — Incident Narrator (AI SOC Investigator)

## System Overview

```
┌──────────────────────────────────────────────────────────────────────────┐
│                  INCIDENT NARRATOR — AI SOC INVESTIGATOR                    │
│        Autonomous security-alert triage + incident reporting               │
│            Gemini  ·  Splunk MCP Server  ·  BOTS v3 dataset                │
└──────────────────────────────────────────────────────────────────────────┘

   Security alert                     ┌────────────────────────────────────┐
   (analyst pastes  ──────────────▶   │       Flask App  (main.py)          │
    OR Splunk alert                   │                                     │
    action webhook)  ──────────────▶  │  /api/investigate   /webhook        │
                                       │  /api/health        / (SOC console) │
                                       └───────────────┬─────────────────────┘
                                                       │
                                                       ▼
                              ┌────────────────────────────────────────┐
                              │   SOCInvestigator  (orchestrator.py)     │
                              │   Autonomous investigation loop          │
                              │                                          │
                              │   ┌────────────────────────────────┐    │
                              │   │ 1. Orient (indexes, sourcetypes)│    │
                              │   │ 2. Pivot on alert indicator     │    │
                              │   │ 3. Correlate across data sources│    │
                              │   │ 4. Build the kill chain         │    │
                              │   │ 5. Conclude (only if evidence)  │    │
                              │   │ 6. Write incident report        │    │
                              │   └────────────────────────────────┘    │
                              │                                          │
                              │   ERROR DISCIPLINE:                      │
                              │   tool failure ≠ evidence.               │
                              │   No data → honest "inconclusive"        │
                              │   report, never a fabricated root cause. │
                              └──────────┬───────────────────┬───────────┘
                                         │                   │
                  reasoning + report     │                   │  tool calls
                          ▼              │                   ▼
              ┌────────────────────┐     │     ┌──────────────────────────────┐
              │  Google Gemini      │     │     │  Splunk integration (tools.py) │
              │  gemini-2.5-flash   │     │     │                                │
              │                     │     │     │  PRIMARY: SplunkMCPClient      │
              │  • plans next query │     │     │   JSON-RPC / streamable HTTP   │
              │  • reads results    │     │     │   → splunk_run_query           │
              │  • maps MITRE ATT&CK│     │     │   → splunk_get_indexes         │
              │  • writes report    │     │     │   → splunk_get_metadata        │
              └────────────────────┘     │     │   → saia_generate_spl  (AI)    │
                                         │     │                                │
                                         │     │  FALLBACK: SplunkRestClient    │
                                         │     │   /services/search/jobs        │
                                         │     │   (auto-used if MCP down)      │
                                         │     └───────────────┬────────────────┘
                                         │                     │
                                         │                     ▼
                                         │     ┌──────────────────────────────┐
                                         │     │   Splunk Enterprise (8089)     │
                                         │     │   ┌────────────────────────┐   │
                                         │     │   │ Splunk MCP Server app  │   │
                                         │     │   │ + AI Assistant for SPL │   │
                                         │     │   └────────────────────────┘   │
                                         │     │   index = botsv3 (BOTS v3)     │
                                         │     │   firewall · web · DNS ·       │
                                         │     │   sysmon · CloudTrail · O365   │
                                         │     └──────────────────────────────┘
                                         ▼
                              ┌────────────────────────────┐
                              │   Incident Report (JSON)     │
                              │   • status + severity        │
                              │   • attack narrative         │
                              │   • timeline                 │
                              │   • IOCs                     │
                              │   • MITRE ATT&CK mapping     │
                              │   • affected assets          │
                              │   • root cause               │
                              │   • recommended actions      │
                              │   • evidence SPL queries     │
                              └──────────────┬───────────────┘
                                             ▼
                              Rendered in SOC console · export to Markdown
```

## Data Flow

```
1. INTAKE     A security alert arrives (analyst input or Splunk webhook).

2. ORIENT     Agent calls splunk_get_indexes / splunk_get_metadata via MCP to
              confirm the botsv3 data and available sourcetypes.

3. PIVOT      Agent issues splunk_run_query (MCP) on the relevant sourcetype to
              find the indicator named in the alert (IP, user, host, domain).

4. CORRELATE  Agent runs further queries across firewall, DNS, web, endpoint,
              and cloud sourcetypes to connect related events.

5. REASON     Each tool result is fed back to Gemini, which decides the next
              query or concludes. Tool ERRORS are labelled as tooling problems
              and never enter the evidence chain.

6. REPORT     Gemini synthesises the findings into a structured incident report
              with MITRE ATT&CK mapping. If no data was retrievable, the report
              is honestly marked "inconclusive_tooling".
```

## AI Integration

- **Google Gemini 2.5 Flash** runs the agentic loop: it chooses which Splunk
  queries to run, interprets the returned events, correlates across sources,
  maps activity to MITRE ATT&CK, and writes the final incident report.

## Splunk Integration

- **Splunk MCP Server (primary)** via JSON-RPC over streamable HTTP, using the
  official tools `splunk_run_query`, `splunk_get_indexes`,
  `splunk_get_metadata`, and the Splunk AI Assistant tool `saia_generate_spl`.
- **Splunk REST API (fallback)** through `/services/search/jobs`, used
  automatically if the MCP server is unreachable, so the app degrades
  gracefully instead of failing.
- **Dataset:** Splunk Boss of the SOC (BOTS) v3, a realistic enterprise
  security dataset, queried at `index=botsv3`.
```
```
