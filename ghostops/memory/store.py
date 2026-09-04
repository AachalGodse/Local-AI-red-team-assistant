"""Engagement persistence — one SQLite DB per engagement.

Structured storage is the source of truth (deterministic queries like "list
open ports" never depend on embedding luck). A vector/RAG layer can be added
later on top of this for fuzzy free-text recall.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from ghostops.models import (
    ActivityLog,
    Credential,
    Engagement,
    Finding,
    Host,
    Phase,
    Service,
    Severity,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagement (
    id TEXT PRIMARY KEY,
    name TEXT,
    scope TEXT,          -- json list
    phase TEXT,
    created_at TEXT,
    stealth INTEGER,
    model TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY,
    hostname TEXT,
    os TEXT,
    status TEXT
);
CREATE TABLE IF NOT EXISTS services (
    ip TEXT,
    port INTEGER,
    proto TEXT,
    name TEXT,
    product TEXT,
    version TEXT,
    state TEXT,
    extra TEXT,
    PRIMARY KEY (ip, port, proto)
);
CREATE TABLE IF NOT EXISTS findings (
    title TEXT,
    severity TEXT,
    host TEXT,
    port INTEGER,
    description TEXT,
    source TEXT,
    references_json TEXT,
    PRIMARY KEY (title, host, port)
);
CREATE TABLE IF NOT EXISTS credentials (
    service TEXT,
    host TEXT,
    username TEXT,
    secret TEXT,
    source TEXT,
    PRIMARY KEY (service, host, username, secret)
);
CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    kind TEXT,
    summary TEXT,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS web_targets (
    url TEXT PRIMARY KEY
);
"""


class EngagementStore:
    """Load/save a single Engagement to a SQLite file."""

    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    # ------------------------------------------------------------------ save
    def save(self, e: Engagement) -> None:
        c = self.conn
        c.execute("DELETE FROM engagement")
        c.execute(
            "INSERT INTO engagement VALUES (?,?,?,?,?,?,?)",
            (e.id, e.name, json.dumps(e.scope), e.phase.value,
             e.created_at, int(e.stealth), e.model),
        )
        # Rebuild child tables from in-memory truth.
        for tbl in ("hosts", "services", "findings", "credentials",
                    "web_targets"):
            c.execute(f"DELETE FROM {tbl}")
        for h in e.hosts:
            c.execute("INSERT OR REPLACE INTO hosts VALUES (?,?,?,?)",
                      (h.ip, h.hostname, h.os, h.status))
            for s in h.services:
                c.execute(
                    "INSERT OR REPLACE INTO services VALUES (?,?,?,?,?,?,?,?)",
                    (h.ip, s.port, s.proto, s.name, s.product,
                     s.version, s.state, s.extra),
                )
        for f in e.findings:
            c.execute(
                "INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?)",
                (f.title, f.severity.value, f.host, f.port,
                 f.description, f.source, json.dumps(f.references)),
            )
        for cr in e.credentials:
            c.execute("INSERT OR REPLACE INTO credentials VALUES (?,?,?,?,?)",
                      (cr.service, cr.host, cr.username, cr.secret, cr.source))
        for u in e.web_targets:
            c.execute("INSERT OR REPLACE INTO web_targets VALUES (?)", (u,))
        # Activity is append-only; sync any rows not yet persisted.
        c.execute("DELETE FROM activity")
        for a in e.activity:
            c.execute(
                "INSERT INTO activity (timestamp, kind, summary, detail) "
                "VALUES (?,?,?,?)",
                (a.timestamp, a.kind, a.summary, a.detail),
            )
        c.commit()

    # ------------------------------------------------------------------ load
    def load(self) -> Engagement | None:
        row = self.conn.execute("SELECT * FROM engagement LIMIT 1").fetchone()
        if row is None:
            return None
        e = Engagement(
            id=row["id"],
            name=row["name"] or "",
            scope=json.loads(row["scope"] or "[]"),
            phase=Phase(row["phase"]) if row["phase"] else Phase.RECON,
            created_at=row["created_at"] or "",
            stealth=bool(row["stealth"]),
            model=row["model"] or "dolphin-mistral",
        )
        hosts: dict[str, Host] = {}
        for hr in self.conn.execute("SELECT * FROM hosts"):
            hosts[hr["ip"]] = Host(
                ip=hr["ip"], hostname=hr["hostname"] or "",
                os=hr["os"] or "", status=hr["status"] or "up",
            )
        for sr in self.conn.execute("SELECT * FROM services"):
            host = hosts.get(sr["ip"])
            if host is not None:
                host.services.append(Service(
                    port=sr["port"], proto=sr["proto"], name=sr["name"] or "",
                    product=sr["product"] or "", version=sr["version"] or "",
                    state=sr["state"] or "open", extra=sr["extra"] or "",
                ))
        e.hosts = list(hosts.values())
        for fr in self.conn.execute("SELECT * FROM findings"):
            e.findings.append(Finding(
                title=fr["title"],
                severity=Severity(fr["severity"]) if fr["severity"] else Severity.INFO,
                host=fr["host"] or "", port=fr["port"],
                description=fr["description"] or "", source=fr["source"] or "",
                references=json.loads(fr["references_json"] or "[]"),
            ))
        for cr in self.conn.execute("SELECT * FROM credentials"):
            e.credentials.append(Credential(
                service=cr["service"], host=cr["host"] or "",
                username=cr["username"] or "", secret=cr["secret"] or "",
                source=cr["source"] or "",
            ))
        for ar in self.conn.execute("SELECT * FROM activity ORDER BY id"):
            e.activity.append(ActivityLog(
                timestamp=ar["timestamp"], kind=ar["kind"],
                summary=ar["summary"], detail=ar["detail"] or "",
            ))
        for wr in self.conn.execute("SELECT url FROM web_targets"):
            e.web_targets.append(wr["url"])
        return e

    def close(self) -> None:
        self.conn.close()


def list_engagements(directory: str | Path) -> list[dict]:
    """Return metadata for every engagement DB found in `directory`."""
    d = Path(directory)
    out: list[dict] = []
    if not d.is_dir():
        return out
    for db in sorted(d.glob("*.db")):
        try:
            conn = sqlite3.connect(str(db))
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM engagement LIMIT 1").fetchone()
            if row:
                counts = {
                    "hosts": conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0],
                    "ports": conn.execute("SELECT COUNT(*) FROM services").fetchone()[0],
                    "findings": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
                }
                out.append({
                    "id": row["id"], "name": row["name"],
                    "phase": row["phase"], "created_at": row["created_at"],
                    "scope": json.loads(row["scope"] or "[]"), **counts,
                })
            conn.close()
        except Exception:
            continue
    return out
