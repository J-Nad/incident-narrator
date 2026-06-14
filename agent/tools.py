import json
import uuid
import requests
import urllib3
import xml.etree.ElementTree as ET

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def ok(data, via="mcp", meta=None):
    return {"ok": True, "data": data, "via": via, "meta": meta or {}}


def fail(error, via="mcp", kind="tool_error"):
    return {"ok": False, "error": str(error), "via": via, "kind": kind}


class SplunkMCP:
    """Talks to the Splunk MCP Server over JSON-RPC. Falls back to the REST
    client when the MCP endpoint can't be reached, so a missing or misconfigured
    MCP app never takes the whole tool offline."""

    candidate_paths = ["/services/mcp", "/services/mcp/", "/en-US/services/mcp"]

    def __init__(self, host, token, rest=None, index="botsv3"):
        self.host = host.rstrip("/")
        self.token = token
        self.rest = rest
        self.index = index
        self.session_id = None
        self.endpoint = None
        self.ready = False

    def _headers(self):
        h = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        return h

    def _read(self, resp):
        ctype = resp.headers.get("Content-Type", "")
        body = resp.text
        if "text/event-stream" in ctype or body.startswith("data:") or "\ndata:" in body:
            for line in reversed(body.splitlines()):
                line = line.strip()
                if line.startswith("data:"):
                    payload = line[5:].strip()
                    if payload and payload != "[DONE]":
                        return json.loads(payload)
            raise ValueError("empty SSE stream")
        return resp.json()

    def _rpc(self, method, params=None, timeout=70):
        body = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method}
        if params is not None:
            body["params"] = params
        resp = requests.post(self.endpoint, headers=self._headers(), json=body,
                             verify=False, timeout=timeout)
        sid = resp.headers.get("Mcp-Session-Id")
        if sid:
            self.session_id = sid
        if resp.status_code in (401, 403):
            raise PermissionError(f"MCP auth failed (HTTP {resp.status_code})")
        resp.raise_for_status()
        return self._read(resp)

    def _connect(self):
        if self.ready:
            return
        last = None
        for path in self.candidate_paths:
            self.endpoint = self.host + path
            try:
                res = self._rpc("initialize", {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "incident-narrator", "version": "1.0"},
                })
                if "error" in res:
                    last = res["error"]
                    continue
                try:
                    self._rpc("notifications/initialized")
                except Exception:
                    pass
                self.ready = True
                return
            except Exception as e:
                last = e
        raise ConnectionError(f"MCP initialize failed: {last}")

    def _tool(self, name, args, timeout=80):
        self._connect()
        res = self._rpc("tools/call", {"name": name, "arguments": args}, timeout=timeout)
        if "error" in res:
            raise RuntimeError(f"{name}: {res['error']}")
        result = res.get("result", {})
        blocks = result.get("content", [])
        text = "\n".join(b.get("text", "") for b in blocks
                         if isinstance(b, dict) and b.get("type") == "text")
        if result.get("isError"):
            raise RuntimeError(f"{name} returned error: {text[:300]}")
        return text

    @staticmethod
    def _decode(text):
        text = (text or "").strip()
        if not text:
            return []
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            rows = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    rows.append({"_raw": line})
            return rows or text

    def run_query(self, spl, earliest="0", latest="now", limit=100):
        search = spl.strip()
        if not search.lower().startswith("search ") and not search.startswith("|"):
            search = "search " + search
        try:
            raw = self._tool("splunk_run_query", {
                "query": search,
                "earliest_time": earliest,
                "latest_time": latest,
                "max_results": limit,
            })
            parsed = self._decode(raw)
            if isinstance(parsed, dict) and "results" in parsed:
                rows = parsed["results"]
            elif isinstance(parsed, list):
                rows = parsed
            else:
                rows = [{"_raw": raw}] if raw else []
            return ok(rows, "mcp", {"tool": "splunk_run_query", "spl": search})
        except PermissionError as e:
            return fail(e, "mcp", "auth_error")
        except Exception as e:
            if self.rest:
                r = self.rest.run_query(spl, earliest, latest, limit)
                r["meta"]["fallback_from"] = "mcp"
                return r
            return fail(e, "mcp", "connection_error")

    def get_indexes(self):
        try:
            return ok(self._decode(self._tool("splunk_get_indexes", {})),
                      "mcp", {"tool": "splunk_get_indexes"})
        except PermissionError as e:
            return fail(e, "mcp", "auth_error")
        except Exception as e:
            return self.rest.get_indexes() if self.rest else fail(e, "mcp", "connection_error")

    def get_metadata(self, index=None, kind="sourcetypes"):
        index = index or self.index
        try:
            raw = self._tool("splunk_get_metadata", {"index": index, "type": kind})
            return ok(self._decode(raw), "mcp", {"tool": "splunk_get_metadata"})
        except PermissionError as e:
            return fail(e, "mcp", "auth_error")
        except Exception as e:
            if self.rest:
                return self.rest.run_query(f"| metadata type={kind} index={index}",
                                           "-30d", "now", 200)
            return fail(e, "mcp", "connection_error")

    def generate_spl(self, description):
        try:
            raw = self._tool("saia_generate_spl", {"text": description})
            parsed = self._decode(raw)
            spl = None
            if isinstance(parsed, dict):
                spl = parsed.get("spl") or parsed.get("query") or parsed.get("search")
            if not spl and isinstance(raw, str):
                spl = raw.strip()
            return ok({"spl": spl, "raw": raw}, "mcp", {"tool": "saia_generate_spl"})
        except Exception as e:
            return fail(e, "mcp", "tool_error")

    def write_event(self, index, sourcetype, event_data):
        """Write an event to a Splunk index via REST (HEC not available in free trial)."""
        if not self.rest:
            return fail("No REST client for write-back", "mcp", "config_error")
        return self.rest.write_event(index, sourcetype, event_data)

    def health(self):
        try:
            self._connect()
            return True
        except Exception:
            return False


class SplunkREST:
    """Direct REST access. Doubles as the fallback path for the MCP client."""

    def __init__(self, host, username, password, index="botsv3"):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.index = index
        self.key = None

    def _session(self):
        if self.key:
            return self.key
        resp = requests.post(f"{self.host}/services/auth/login",
                             data={"username": self.username, "password": self.password},
                             verify=False, timeout=30)
        if resp.status_code in (401, 403):
            raise PermissionError("Splunk REST auth failed")
        resp.raise_for_status()
        self.key = ET.fromstring(resp.text).findtext("sessionKey")
        return self.key

    def _auth(self):
        return {"Authorization": f"Splunk {self._session()}"}

    def run_query(self, spl, earliest="0", latest="now", limit=100):
        search = spl.strip()
        if not search.lower().startswith("search ") and not search.startswith("|"):
            search = "search " + search
        try:
            resp = requests.post(f"{self.host}/services/search/jobs",
                                 headers=self._auth(),
                                 data={"search": search, "earliest_time": earliest,
                                       "latest_time": latest, "exec_mode": "oneshot",
                                       "output_mode": "json", "count": limit},
                                 verify=False, timeout=120)
            if resp.status_code in (401, 403):
                return fail("REST auth failed", "rest", "auth_error")
            resp.raise_for_status()
            return ok(resp.json().get("results", []), "rest", {"spl": search})
        except PermissionError as e:
            return fail(e, "rest", "auth_error")
        except requests.exceptions.RequestException as e:
            return fail(e, "rest", "connection_error")
        except Exception as e:
            return fail(e, "rest", "tool_error")

    def get_indexes(self):
        try:
            resp = requests.get(f"{self.host}/services/data/indexes",
                                headers=self._auth(),
                                params={"output_mode": "json", "count": 100},
                                verify=False, timeout=30)
            if resp.status_code in (401, 403):
                return fail("REST auth failed", "rest", "auth_error")
            resp.raise_for_status()
            entries = resp.json().get("entry", [])
            idx = [{"name": e.get("name", ""),
                    "totalEventCount": e.get("content", {}).get("totalEventCount", "0")}
                   for e in entries]
            return ok(idx, "rest")
        except requests.exceptions.RequestException as e:
            return fail(e, "rest", "connection_error")
        except Exception as e:
            return fail(e, "rest", "tool_error")

    def health(self):
        try:
            self._session()
            return True
        except Exception:
            return False

    def write_event(self, index, sourcetype, event_data):
        """Write investigation results back to Splunk as an event."""
        try:
            import time as _time
            event = {
                "time": _time.time(),
                "sourcetype": sourcetype,
                "index": index,
                "event": event_data if isinstance(event_data, str) else json.dumps(event_data),
            }
            resp = requests.post(f"{self.host}/services/receivers/simple",
                                 headers=self._auth(),
                                 params={"sourcetype": sourcetype, "index": index},
                                 data=event["event"],
                                 verify=False, timeout=30)
            if resp.status_code in (401, 403):
                return fail("Write auth failed", "rest", "auth_error")
            resp.raise_for_status()
            return ok({"written": True, "index": index}, "rest")
        except Exception as e:
            return fail(e, "rest", "write_error")
