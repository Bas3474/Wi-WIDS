import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional

from schemas import Incident

DB_PATH = Path(__file__).resolve().parent.parent / "incidents.db"

COLUMNS = [
    "timestamp", "attack_type", "severity", "layer", "src_mac", "bssid", "ssid",
    "victim_count", "channel", "rssi", "frame_rate", "impact", "action", "source",
]


@contextmanager
def _conn() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db() -> None:
    with _conn() as c:
        with c:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute(
                """CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL, attack_type TEXT, severity TEXT, layer TEXT,
                    src_mac TEXT, bssid TEXT, ssid TEXT, victim_count INTEGER,
                    channel INTEGER, rssi INTEGER, frame_rate REAL,
                    impact TEXT, action TEXT, source TEXT)"""
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents(timestamp DESC)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_incidents_type ON incidents(attack_type)")


def insert_incident(inc: Incident) -> Incident:
    data = inc.model_dump(mode="json")
    with _conn() as c:
        with c:
            cur = c.execute(
                f"INSERT INTO incidents ({','.join(COLUMNS)}) VALUES ({','.join('?' * len(COLUMNS))})",
                [data[k] for k in COLUMNS],
            )
            inc.id = cur.lastrowid
    return inc


def list_incidents(limit: int = 200, q: Optional[str] = None) -> list[dict]:
    sql, args = "SELECT * FROM incidents", []
    if q:
        like = f"%{q}%"
        sql += " WHERE attack_type LIKE ? OR src_mac LIKE ? OR ssid LIKE ? OR severity LIKE ?"
        args = [like] * 4
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(sql, args)]


def counts_by_severity() -> dict:
    with _conn() as c:
        rows = c.execute("SELECT severity, COUNT(*) n FROM incidents GROUP BY severity").fetchall()
    return {r["severity"]: r["n"] for r in rows}


def clear_all() -> None:
    with _conn() as c:
        with c:
            c.execute("DELETE FROM incidents")
