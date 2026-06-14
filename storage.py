import sqlite3
import json
import time
import os
import threading

_DB_PATH = os.path.join(os.path.dirname(__file__), "narrator.db")
_lock = threading.Lock()


def _connect():
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init():
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at REAL NOT NULL,
                alert TEXT NOT NULL,
                status TEXT,
                severity TEXT,
                confidence INTEGER,
                title TEXT,
                report_json TEXT,
                trace_json TEXT,
                via TEXT,
                duration_ms INTEGER
            )
            """
        )
        conn.commit()


def save(alert, report, trace, duration_ms):
    meta = report.get("_meta", {})
    via = "MCP Server" if meta.get("mcp_used") else "REST"
    with _lock, _connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO investigations
              (created_at, alert, status, severity, confidence, title,
               report_json, trace_json, via, duration_ms)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                time.time(),
                alert,
                report.get("status", ""),
                report.get("severity", ""),
                int(report.get("confidence", 0) or 0),
                report.get("title", ""),
                json.dumps(report),
                json.dumps(trace),
                via,
                duration_ms,
            ),
        )
        conn.commit()
        return cur.lastrowid


def get(inv_id):
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM investigations WHERE id = ?", (inv_id,)
        ).fetchone()
    if not row:
        return None
    return _row_to_detail(row)


def recent(limit=50):
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM investigations ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_row_to_summary(r) for r in rows]


def stats():
    with _connect() as conn:
        rows = conn.execute("SELECT status, severity, duration_ms FROM investigations").fetchall()
    total = len(rows)
    confirmed = sum(1 for r in rows if r["status"] == "confirmed")
    suspected = sum(1 for r in rows if r["status"] == "suspected")
    false_pos = sum(1 for r in rows if r["status"] == "false_positive")
    durations = [r["duration_ms"] for r in rows if r["duration_ms"]]
    avg_ms = int(sum(durations) / len(durations)) if durations else 0
    crit_high = sum(1 for r in rows if r["severity"] in ("critical", "high"))
    return {
        "total": total,
        "confirmed": confirmed,
        "suspected": suspected,
        "false_positive": false_pos,
        "critical_high": crit_high,
        "avg_duration_ms": avg_ms,
    }


def delete(inv_id):
    with _lock, _connect() as conn:
        conn.execute("DELETE FROM investigations WHERE id = ?", (inv_id,))
        conn.commit()


def _row_to_summary(row):
    return {
        "id": row["id"],
        "created_at": row["created_at"],
        "alert": row["alert"],
        "status": row["status"],
        "severity": row["severity"],
        "confidence": row["confidence"],
        "title": row["title"],
        "via": row["via"],
        "duration_ms": row["duration_ms"],
    }


def _row_to_detail(row):
    d = _row_to_summary(row)
    d["report"] = json.loads(row["report_json"]) if row["report_json"] else {}
    d["trace"] = json.loads(row["trace_json"]) if row["trace_json"] else []
    return d
