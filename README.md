# Incident Narrator — AI SOC Investigator

**Autonomous security-alert triage and incident reporting. Every investigation writes back to Splunk as searchable events, with a live dashboard inside the Splunk UI showing investigation metrics, top threats, and MITRE ATT&CK patterns.**

> Track: **Security** · Splunk Agentic Ops Hackathon 2026

## The Problem

When a security alert fires, a SOC analyst spends 30–60 minutes manually pivoting across firewall, web, DNS, endpoint, and cloud logs in Splunk to answer: *what happened, how bad is it, and what do we do?* With 200+ alerts per day at enterprise scale, most alerts never get fully investigated — they're closed as "reviewed" without deep analysis.

## The Solution

Incident Narrator is an AI agent that autonomously investigates security alerts using Splunk data. It queries across multiple sourcetypes via the Splunk MCP Server, correlates events, builds attack timelines, maps activity to MITRE ATT&CK, and writes structured incident reports — in under 60 seconds.

**The key differentiator:** findings write back into Splunk as events (`index=narrator_investigations`), making every AI investigation searchable, dashboardable, and alertable just like any other security data. Teams can track patterns, measure false positive rates, and build detection rules on top of the AI's findings.

## What Makes This Production-Ready

- **Splunk MCP Server integration** — uses `splunk_run_query`, `splunk_get_indexes`, `splunk_get_metadata`, and `saia_generate_spl` over JSON-RPC, with REST API as automatic fallback
- **Runs against real enterprise data** — Splunk BOTS v3 dataset (firewall, web, DNS, Windows/Sysmon, AWS CloudTrail, Office 365)
- **Writes back to Splunk** — every investigation becomes a searchable event with structured fields (IOCs, MITRE techniques, confidence, severity)
- **Splunk dashboard included** — live metrics inside the Splunk web UI showing investigation volume, confirmed threats, top techniques, and IOC trends
- **Calibrated confidence** — reports include 0-100% confidence with rationale. Honestly returns `false_positive` or `inconclusive` when evidence doesn't support a conclusion
- **Evidence transparency** — shows every SPL query run, whether it went via MCP or REST, and sample results

## How AI Is Used

Google Gemini 2.5 Flash drives an autonomous investigation loop: at each step it decides which Splunk query to run based on findings so far, interprets returned events, correlates indicators across data sources, and maps observed activity to MITRE ATT&CK. When evidence supports a conclusion, it stops and writes the report. This is genuine agentic behavior — the query sequence isn't scripted.

## Architecture

See [`architecture_diagram.md`](./architecture_diagram.png).

```
Alert → Flask API → AI Agent Loop → Splunk MCP/REST → Incident Report → Writes to narrator_investigations index
                                                                      ↓
                                                            Splunk Dashboard (queryable)
```

## Setup

### Prerequisites
- Python 3.9+
- Splunk Enterprise (free trial) with:
  - the **MCP Server for Splunk Platform** app (Splunkbase)
  - the **Splunk AI Assistant for SPL** app (enables `saia_*` MCP tools)
  - the **BOTS v3 dataset** installed at `index=botsv3`
  - the **narrator_investigations** index created (for write-back)
- A Google Gemini API key (free at [aistudio.google.com](https://aistudio.google.com), or $5 for extended quota)

### Install the BOTS v3 dataset
1. Download: `https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz` (320 MB, pre-indexed)
2. Extract and move the `botsv3` folder into `$SPLUNK_HOME/etc/apps/`
3. Restart Splunk
4. Verify in Splunk Search: `index=botsv3 earliest=0 | head 10`

### Configure the MCP Server
1. Install the MCP Server app and the AI Assistant for SPL app from Splunkbase
2. Create a role named `mcp_user` with the `mcp_tool_execute` capability
3. Generate an encrypted token from inside the MCP Server app (shown once)

### Run the app
```bash
pip install -r requirements.txt
cp .env.example .env          # then edit .env with your values
python main.py
# open http://localhost:5000
```

### Install the Splunk Dashboard

The included Splunk dashboard displays investigation metrics, threat trends, and MITRE heatmaps inside the Splunk web UI.

1. In Splunk web, go to **Settings** → **Indexes** → **New Index**
2. Create index: `narrator_investigations`
3. Copy `splunk_dashboard/narrator_dashboard.xml` into Splunk:
   - Windows: `C:\Program Files\Splunk\etc\apps\search\local\data\ui\views\`
   - Linux/Mac: `$SPLUNK_HOME/etc/apps/search/local/data/ui/views/`
4. Restart Splunk
5. Access the dashboard: **Search & Reporting** → **Dashboards** → **"Incident Narrator - AI Investigation Dashboard"**

See [`splunk_dashboard/INSTALL.md`](./splunk_dashboard/INSTALL.md) for detailed instructions.

### Environment variables

| Variable | Description |
| --- | --- |
| `GEMINI_API_KEY` | Google Gemini API key |
| `SPLUNK_HOST` | Splunk management endpoint, e.g. `https://localhost:8089` |
| `SPLUNK_USERNAME` / `SPLUNK_PASSWORD` | Splunk admin login (for REST fallback) |
| `SPLUNK_MCP_TOKEN` | Encrypted token from the MCP Server app |
| `SPLUNK_INDEX` | Dataset index (default `botsv3`) |

## Usage

The web interface provides four views:
- **Dashboard** — KPIs, recent investigations
- **New Investigation** — trigger an investigation with preset scenarios or custom alerts
- **Investigations** — browse saved investigation history
- **Connections** — live status of Splunk MCP, REST, Gemini, and dataset

### Demonstration Scenarios

Three preset scenarios demonstrate different investigation outcomes:

1. **Confirmed Threat** — Web application attack against imreallynotbatman.com. The agent finds brute-force login attempts, successful CMS compromise, and webshell upload. High confidence (75-90%), status: confirmed, with specific IOCs and MITRE mapping.

2. **False Positive** — Internal port scanning from 10.0.2.15. The agent identifies this as legitimate security scanning (internal IP, regular patterns, no exploitation). Low confidence (30-50%), status: false_positive.

3. **Inconclusive** — Ambiguous PowerShell activity on an endpoint. The agent finds the process execution but lacks context to determine intent. Medium confidence (40-60%), status: suspected, recommends human review.

Run all three to show the agent handles threats, benign activity, and ambiguous cases differently with calibrated confidence.

Sample alerts are in [`sample_data/demo_scenarios.json`](./sample_data/demo_scenarios.json).

### Viewing Results in Splunk

After running investigations, query the findings directly in Splunk:

```spl
index=narrator_investigations sourcetype=narrator:investigation 
| stats count by status, severity

index=narrator_investigations status=confirmed 
| table _time, title, confidence, iocs, mitre_techniques

index=narrator_investigations 
| timechart count by severity
```

Or open the included dashboard: **Search & Reporting** → **Dashboards** → **Incident Narrator**

## Project structure

```
incident-narrator/
├── architecture_diagram.md          # system architecture (required)
├── README.md
├── LICENSE                          # MIT
├── requirements.txt
├── .env.example
├── main.py                          # Flask: routes, health, webhook, write-back
├── storage.py                       # SQLite persistence
├── agent/
│   ├── orchestrator.py              # SOCInvestigator: agentic loop + report
│   └── tools.py                     # Splunk MCP + REST clients
├── templates/
│   └── index.html                   # multi-view web interface
├── static/
│   ├── styles.css                   # clean professional design
│   └── app.js                       # frontend SPA
├── splunk_dashboard/
│   ├── narrator_dashboard.xml       # Splunk dashboard (install inside Splunk UI)
│   └── INSTALL.md                   # dashboard setup guide
└── sample_data/
    ├── sample_alerts.json           # example alerts
    └── demo_scenarios.json          # demo script (3 scenarios)
```

## Splunk capabilities used

- **Splunk MCP Server** — primary integration (`splunk_run_query`, `splunk_get_indexes`, `splunk_get_metadata`)
- **Splunk AI Assistant for SPL** — `saia_generate_spl` for natural-language-to-SPL
- **Splunk REST API** — automatic fallback for search execution, write-back for investigation events
- **Splunk BOTS v3** — realistic security dataset (index=botsv3)
- **Splunk Dashboarding** — included Simple XML dashboard for investigation metrics

## License

MIT — see [LICENSE](./LICENSE).
