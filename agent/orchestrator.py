import json
from google import genai

INVESTIGATION_PROMPT = """You are an autonomous SOC analyst investigating a security alert in Splunk BOTS v3 (index=botsv3).

CRITICAL: Data is from 2018. EVERY query must use earliest=0 latest=now or you get 0 results.

AVAILABLE SOURCETYPES:
stream:http (24k) - web traffic with src_ip, site, uri_path, status, http_method
stream:dns (218k) - DNS queries  
stream:ip, stream:tcp, stream:udp (470k+) - network flows
syslog, cisco:asa, aws:cloudtrail - various enterprise logs

SKIP get_indexes and get_metadata (they return empty). Jump straight to queries.

For web alerts, start with:
index=botsv3 sourcetype=stream:http status>=400 earliest=0 latest=now | stats count by src_ip, uri_path, status | sort -count | head 50

Then drill into suspicious IPs found.

Tools:
splunk_run_query(spl, earliest, latest) - run SPL
saia_generate_spl(description) - NL to SPL  
conclude - done investigating
halt_tooling - cannot get data

JSON per step:
{"thinking":"...","action":"splunk_run_query|saia_generate_spl|conclude|halt_tooling","parameters":{...},"findings_so_far":"..."}
"""

REPORT_PROMPT = """Senior SOC analyst writing incident report. Output ONLY valid JSON:
{
"title":"...","status":"confirmed|suspected|false_positive|inconclusive_tooling",
"severity":"critical|high|medium|low|info","confidence":0-100,
"confidence_rationale":"why this confidence and what would change it",
"executive_summary":"2-3 sentences","attack_narrative":"plain English story",
"timeline":[{"time":"...","event":"..."}],
"indicators_of_compromise":[{"type":"ip|domain|user|host","value":"...","context":"..."}],
"mitre_attack":[{"tactic":"...","technique":"T1234 Name","evidence":"..."}],
"affected_assets":[{"asset":"...","impact":"..."}],"root_cause":"...",
"recommended_actions":[{"priority":"P0|P1|P2","action":"...","owner":"..."}],
"evidence_queries":["SPL that produced findings"]
}

Calibration: High confidence (80-100) needs multiple sources. Low (0-40) for weak signals.
If no data retrieved: status inconclusive_tooling, severity info, confidence <30.
Return ONLY JSON.
"""

class SOCInvestigator:
    def __init__(self, api_key, splunk, model="gemini-2.5-flash", index="botsv3"):
        self.client = genai.Client(api_key=api_key)
        self.model = model
        self.splunk = splunk
        self.index = index
        self.trace = []
        self.data_pulls = 0
        self.tool_failures = 0
        self.queries = []
        self.mcp_used = False

    def investigate(self, alert, callback=None, max_steps=9):
        self.trace, self.data_pulls, self.tool_failures = [], 0, 0
        self.queries, self.mcp_used = [], False
        convo = [{"role": "user", "content":
                  f"ALERT: {alert}\n\nData: index={self.index} (2018, use earliest=0 latest=now)\n"
                  f"SKIP metadata. Start with: index=botsv3 sourcetype=stream:http status>=400 earliest=0 latest=now | stats count by src_ip, uri_path, status | sort -count | head 50\n"
                  f"Then drill into suspicious IPs. Your first action NOW."}]

        for step in range(max_steps):
            try:
                resp = self.client.models.generate_content(
                    model=self.model, contents=self._gemini(convo),
                    config=genai.types.GenerateContentConfig(
                        system_instruction=INVESTIGATION_PROMPT, temperature=0.2, max_output_tokens=1500))
                text = (resp.text or "").strip()
            except Exception as e:
                entry = {"step": step + 1, "type": "agent_error", "error": str(e)}
                self.trace.append(entry)
                if callback:
                    callback(entry)
                break

            action = self._parse(text)
            if not action:
                convo.append({"role": "model", "content": text})
                convo.append({"role": "user", "content": "Respond with valid JSON."})
                continue

            entry = {"step": step + 1, "thinking": action.get("thinking", ""),
                     "action": action.get("action", ""), "findings": action.get("findings_so_far", "")}
            act = action.get("action")
            p = action.get("parameters", {}) or {}

            if act == "conclude":
                entry["type"] = "conclusion"
                entry["summary"] = p.get("summary", "")
                self.trace.append(entry)
                if callback:
                    callback(entry)
                break
            if act == "halt_tooling":
                entry["type"] = "halt_tooling"
                entry["reason"] = p.get("reason", "")
                self.trace.append(entry)
                if callback:
                    callback(entry)
                break

            if act == "splunk_run_query":
                spl = p.get("spl", "")
                entry["query"] = spl
                r = self.splunk.run_query(spl, p.get("earliest", "0"), p.get("latest", "now"))
                if r.get("ok"):
                    self.queries.append(spl)
                feedback = self._record(entry, r, "events")
            elif act == "saia_generate_spl":
                feedback = self._record(entry, self.splunk.generate_spl(p.get("description", "")), "spl")
            else:
                feedback = self._record(entry, {"ok": False, "error": f"Unknown: {act}", "kind": "tool_error"}, "unknown")

            self.trace.append(entry)
            if callback:
                callback(entry)
            convo.append({"role": "model", "content": text})
            convo.append({"role": "user", "content": feedback})

        return self.trace

    def _record(self, entry, result, label):
        if result.get("ok"):
            via = result.get("via", "mcp")
            if via == "mcp":
                self.mcp_used = True
            data = result.get("data", [])
            count = len(data) if isinstance(data, list) else 1
            entry.update({"via": via, "ok": True, "result_count": count,
                          "preview": data[:5] if isinstance(data, list) else data})
            self.data_pulls += 1
            blob = json.dumps(data, default=str)
            if len(blob) > 3000:
                blob = blob[:3000] + "...(truncated)"
            if count == 0:
                return f"TOOL OK (via {via}): 0 events. Valid finding. Next step?"
            return f"TOOL OK (via {via}): {count} {label}.\n{blob}\n\nAnalyze and decide next, or conclude."
        self.tool_failures += 1
        entry.update({"via": result.get("via", "mcp"), "ok": False,
                      "tool_error": result.get("error", ""), "error_kind": result.get("kind", "tool_error")})
        return f"TOOL ERROR ({result.get('kind')}): {result.get('error')}\nTooling problem, not evidence. Try alternative or halt_tooling."

    def write_report(self, alert):
        no_data = self.data_pulls == 0
        lines = [f"ALERT: {alert}", "LOG:"]
        for e in self.trace:
            lines.append(f"\nStep {e.get('step','?')} {e.get('action','?')}")
            if e.get("thinking"):
                lines.append(f"Why: {e['thinking'][:300]}")
            if e.get("query"):
                lines.append(f"SPL: {e['query'][:400]}")
            if e.get("ok") is True:
                lines.append(f"Result: {e.get('result_count',0)} events via {e.get('via')}")
            elif e.get("ok") is False:
                lines.append(f"ERROR: {e.get('tool_error','')[:200]}")
            if e.get("summary"):
                lines.append(f"Found: {e['summary'][:500]}")
        findings_text = "\n".join(lines)
        if no_data:
            findings_text += "\n\nNO DATA RETRIEVED. Set inconclusive_tooling, severity info, confidence <30."

        try:
            resp = self.client.models.generate_content(
                model=self.model,
                contents=[{"role": "user", "parts": [{"text": f"Write incident report.\n\n{findings_text}"}]}],
                config=genai.types.GenerateContentConfig(
                    system_instruction=REPORT_PROMPT, temperature=0.1, max_output_tokens=3500))
            raw = (resp.text or "").strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
                if raw.endswith("```"):
                    raw = raw[:-3]
                raw = raw.strip()
            report = json.loads(raw)
        except Exception as e:
            report = {"title": "Report error", "status": "inconclusive_tooling", "severity": "info",
                      "confidence": 0, "executive_summary": f"Report generation failed: {str(e)[:200]}",
                      "timeline": [], "indicators_of_compromise": [], "mitre_attack": [],
                      "affected_assets": [], "recommended_actions": [], "root_cause": "Report error",
                      "evidence_queries": []}

        if no_data:
            report["status"] = "inconclusive_tooling"
            report["severity"] = "info"
            report["confidence"] = min(report.get("confidence", 0), 30)

        report["_meta"] = {"mcp_used": self.mcp_used, "tool_failures": self.tool_failures,
                           "data_pulls": self.data_pulls, "queries_run": self.queries}
        return report

    def _gemini(self, convo):
        return [{"role": "model" if m["role"] == "model" else "user",
                 "parts": [{"text": m["content"]}]} for m in convo]

    def _parse(self, text):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        if "```" in text:
            for b in text.split("```"):
                b = b.strip()
                if b.startswith("json"):
                    b = b[4:].strip()
                try:
                    return json.loads(b)
                except json.JSONDecodeError:
                    continue
        s, e = text.find("{"), text.rfind("}")
        if s != -1 and e > s:
            try:
                return json.loads(text[s:e + 1])
            except json.JSONDecodeError:
                pass
        return None
