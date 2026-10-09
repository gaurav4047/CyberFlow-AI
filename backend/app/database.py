from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
from typing import Any
from uuid import uuid4

import os

if os.environ.get("VERCEL"):
    DATA_DIR = Path("/tmp/cyberflow_data")
else:
    DATA_DIR = Path(os.environ.get("DATA_DIR", Path(__file__).resolve().parents[1] / "data"))
DATABASE_PATH = DATA_DIR / "cyberflow.db"


class ClosingConnection(sqlite3.Connection):
    """Make sqlite's transaction context manager close the file handle as well."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, str):
        value = re.sub(
            r"(?i)\b(api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*([^\s,;\"']+)",
            r"\1=[REDACTED]",
            value,
        )
        value = re.sub(r"\bsk-[A-Za-z0-9_-]{20,}\b", "[REDACTED]", value)
        return re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*", "Bearer [REDACTED]", value)
    return value


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH, timeout=10, factory=ClosingConnection)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database() -> None:
    with connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS app_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT OR IGNORE INTO app_metadata (key, value) VALUES ('schema_version', '2');
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                agent TEXT NOT NULL CHECK (agent IN ('ctf', 'bug_bounty', 'soc')),
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'completed',
                severity TEXT,
                summary TEXT NOT NULL,
                input_json TEXT NOT NULL,
                result_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS investigations_agent_date
                ON investigations(agent, created_at DESC);
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL UNIQUE REFERENCES investigations(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                agent TEXT NOT NULL,
                created_at TEXT NOT NULL,
                markdown TEXT NOT NULL,
                json_data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS reports_agent_date
                ON reports(agent, created_at DESC);
            """
        )


def _decode_record(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "title": row["title"],
        "agent": row["agent"],
        "created_at": row["created_at"],
        "status": row["status"],
        "severity": row["severity"],
        "summary": row["summary"],
        "input": json.loads(row["input_json"]),
        "result": json.loads(row["result_json"]),
    }


def create_investigation(
    *,
    title: str,
    agent: str,
    input_data: dict[str, Any],
    result_data: dict[str, Any],
    severity: str | None = None,
    summary: str | None = None,
) -> dict[str, Any]:
    input_data = _redact_value(input_data)
    result_data = _redact_value(result_data)
    investigation_id = str(uuid4())
    report_id = str(uuid4())
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    summary_text = (summary or str(result_data.get("result", "Investigation saved."))).strip()[:240]
    markdown = result_data.get("report_markdown") or (
        f"# {title}\n\n"
        f"- **Investigation:** `{investigation_id}`\n"
        f"- **Type:** {agent.replace('_', ' ').title()}\n"
        f"- **Created:** {created_at}\n"
        f"- **Severity:** {severity or 'Not assessed'}\n\n"
        "## Submitted information\n\n"
        f"```json\n{json.dumps(input_data, indent=2, ensure_ascii=False)}\n```\n\n"
        "## Analysis result\n\n"
        f"{result_data.get('result', 'No analysis text was supplied.')}\n"
    )
    report_json = {
        "investigation_id": investigation_id,
        "title": title,
        "agent": agent,
        "created_at": created_at,
        "severity": severity,
        "input": input_data,
        "result": result_data,
    }

    with connect() as connection:
        connection.execute(
            """INSERT INTO investigations
            (id, title, agent, created_at, status, severity, summary, input_json, result_json)
            VALUES (?, ?, ?, ?, 'completed', ?, ?, ?, ?)""",
            (
                investigation_id,
                title.strip(),
                agent,
                created_at,
                severity,
                summary_text,
                json.dumps(input_data, ensure_ascii=False),
                json.dumps(result_data, ensure_ascii=False),
            ),
        )
        connection.execute(
            """INSERT INTO reports
            (id, investigation_id, title, agent, created_at, markdown, json_data)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                report_id,
                investigation_id,
                title.strip(),
                agent,
                created_at,
                markdown,
                json.dumps(report_json, ensure_ascii=False),
            ),
        )
        row = connection.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
    assert row is not None
    return _decode_record(row)


def list_investigations(
    *,
    search: str = "",
    agent: str = "all",
    date_from: str = "",
    date_to: str = "",
    sort: str = "newest",
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if search.strip():
        term = f"%{search.strip()}%"
        clauses.append("(title LIKE ? OR summary LIKE ? OR agent LIKE ?)")
        params.extend((term, term, term))
    if agent != "all":
        clauses.append("agent = ?")
        params.append(agent)
    if date_from:
        clauses.append("date(created_at) >= date(?)")
        params.append(date_from)
    if date_to:
        clauses.append("date(created_at) <= date(?)")
        params.append(date_to)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    order = "ASC" if sort == "oldest" else "DESC"
    with connect() as connection:
        rows = connection.execute(
            f"SELECT * FROM investigations {where} ORDER BY created_at {order}", params
        ).fetchall()
    return [_decode_record(row) for row in rows]


def get_investigation(investigation_id: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,)).fetchone()
    return _decode_record(row) if row else None


def delete_investigation(investigation_id: str) -> bool:
    with connect() as connection:
        cursor = connection.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,))
    return cursor.rowcount > 0


def list_reports(*, search: str = "", agent: str = "all") -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if search.strip():
        term = f"%{search.strip()}%"
        clauses.append("(r.title LIKE ? OR i.summary LIKE ? OR r.agent LIKE ?)")
        params.extend((term, term, term))
    if agent != "all":
        clauses.append("r.agent = ?")
        params.append(agent)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect() as connection:
        rows = connection.execute(
            f"""SELECT r.id, r.investigation_id, r.title, r.agent, r.created_at,
                i.severity, i.summary
                FROM reports r JOIN investigations i ON i.id = r.investigation_id
                {where} ORDER BY r.created_at DESC""",
            params,
        ).fetchall()
    return [dict(row) for row in rows]


def get_report(report_id: str) -> dict[str, Any] | None:
    with connect() as connection:
        row = connection.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "investigation_id": row["investigation_id"],
        "title": row["title"],
        "agent": row["agent"],
        "created_at": row["created_at"],
        "markdown": row["markdown"],
        "json": json.loads(row["json_data"]),
    }


def delete_report(report_id: str) -> bool:
    with connect() as connection:
        cursor = connection.execute("DELETE FROM reports WHERE id = ?", (report_id,))
    return cursor.rowcount > 0


def clear_local_data() -> None:
    with connect() as connection:
        connection.execute("DELETE FROM reports")
        connection.execute("DELETE FROM investigations")


def overview() -> dict[str, Any]:
    with connect() as connection:
        counts = connection.execute(
            "SELECT agent, COUNT(*) AS count FROM investigations GROUP BY agent"
        ).fetchall()
        total_reports = connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        recent = connection.execute(
            "SELECT id, title, agent, created_at, status, severity, summary "
            "FROM investigations ORDER BY created_at DESC LIMIT 5"
        ).fetchall()
    by_agent = {row["agent"]: row["count"] for row in counts}
    return {
        "total_investigations": sum(by_agent.values()),
        "ctf_investigations": by_agent.get("ctf", 0),
        "bug_bounty_reports": by_agent.get("bug_bounty", 0),
        "soc_investigations": by_agent.get("soc", 0),
        "total_reports": total_reports,
        "recent_activity": [dict(row) for row in recent],
    }
