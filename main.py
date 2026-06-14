import os
import time
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

import storage
from agent.orchestrator import SOCInvestigator
from agent.tools import SplunkMCP, SplunkREST

load_dotenv()
storage.init()

app = Flask(__name__)
INDEX = os.getenv("SPLUNK_INDEX", "botsv3")


def splunk():
    host = os.getenv("SPLUNK_HOST", "https://localhost:8089")
    rest = SplunkREST(host, os.getenv("SPLUNK_USERNAME", "admin"),
                      os.getenv("SPLUNK_PASSWORD", ""), INDEX)
    return SplunkMCP(host, os.getenv("SPLUNK_MCP_TOKEN", ""), rest, INDEX), rest


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/health")
def health():
    mcp, rest = splunk()
    mcp_ok = rest_ok = False
    try:
        mcp_ok = mcp.health()
    except Exception:
        pass
    try:
        rest_ok = rest.health()
    except Exception:
        pass
    index_events = None
    if mcp_ok or rest_ok:
        r = (mcp if mcp_ok else rest).run_query(f"index={INDEX} | head 1", "0", "now", 1)
        index_events = "available" if r.get("ok") else "empty_or_error"
    return jsonify({
        "gemini": bool(os.getenv("GEMINI_API_KEY", "")),
        "mcp": mcp_ok, "rest": rest_ok,
        "host": os.getenv("SPLUNK_HOST", "https://localhost:8089"),
        "index": INDEX, "index_status": index_events,
    })


@app.route("/api/stats")
def stats():
    return jsonify(storage.stats())


@app.route("/api/investigations")
def investigations():
    return jsonify(storage.recent(50))


@app.route("/api/investigations/<int:inv_id>")
def investigation(inv_id):
    d = storage.get(inv_id)
    if not d:
        return jsonify({"error": "not found"}), 404
    return jsonify(d)


@app.route("/api/investigations/<int:inv_id>", methods=["DELETE"])
def remove(inv_id):
    storage.delete(inv_id)
    return jsonify({"ok": True})


@app.route("/api/investigate", methods=["POST"])
def investigate():
    alert = (request.json or {}).get("alert", "").strip()
    if not alert:
        return jsonify({"error": "Provide an alert to investigate"}), 400
    key = os.getenv("GEMINI_API_KEY", "")
    if not key:
        return jsonify({"error": "GEMINI_API_KEY is not set in .env"}), 500

    mcp, _ = splunk()
    soc = SOCInvestigator(key, mcp, index=INDEX)
    start = time.time()
    try:
        trace = soc.investigate(alert)
        report = soc.write_report(alert)
        duration = int((time.time() - start) * 1000)
        inv_id = storage.save(alert, report, trace, duration)
        
        # Write findings back to Splunk for searchability
        write_to_splunk(mcp, inv_id, alert, report, trace, duration)
        
        return jsonify({"id": inv_id, "trace": trace, "report": report,
                        "duration_ms": duration})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def write_to_splunk(splunk_client, inv_id, alert, report, trace, duration_ms):
    """Write investigation summary to Splunk as a searchable event."""
    meta = report.get("_meta", {})
    iocs = report.get("indicators_of_compromise", [])
    mitre = report.get("mitre_attack", [])
    
    event = {
        "investigation_id": inv_id,
        "alert": alert,
        "title": report.get("title", ""),
        "status": report.get("status", ""),
        "severity": report.get("severity", ""),
        "confidence": report.get("confidence", 0),
        "root_cause": report.get("root_cause", ""),
        "ioc_count": len(iocs),
        "iocs": [ioc.get("value") for ioc in iocs],
        "mitre_tactics": list(set(m.get("tactic") for m in mitre if m.get("tactic"))),
        "mitre_techniques": list(set(m.get("technique") for m in mitre if m.get("technique"))),
        "affected_assets": [a.get("asset") for a in report.get("affected_assets", [])],
        "via": "MCP" if meta.get("mcp_used") else "REST",
        "queries_run": len(meta.get("queries_run", [])),
        "duration_ms": duration_ms,
        "step_count": len(trace),
    }
    
    try:
        splunk_client.write_event("narrator_investigations", "narrator:investigation", event)
    except Exception:
        pass  # Non-fatal; local storage is the source of truth


@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.json or {}
    alert = data.get("search_name", "Splunk alert")
    if data.get("result"):
        import json as _json
        alert += " | " + _json.dumps(data["result"])[:400]
    key = os.getenv("GEMINI_API_KEY", "")
    mcp, _ = splunk()
    soc = SOCInvestigator(key, mcp, index=INDEX)
    start = time.time()
    trace = soc.investigate(alert)
    report = soc.write_report(alert)
    inv_id = storage.save(alert, report, trace, int((time.time() - start) * 1000))
    return jsonify({"id": inv_id, "report": report})


if __name__ == "__main__":
    print("\n  Incident Narrator  ·  http://localhost:5000  ·  index =", INDEX, "\n")
    app.run(debug=True, port=5000)
