"""SQLite schema and query helpers for cvekit."""
import sqlite3
from pathlib import Path

DEFAULT_DB = Path.home() / ".local" / "share" / "cvekit" / "cvekit.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id       TEXT PRIMARY KEY,
    rhel_version TEXT NOT NULL,
    severity     TEXT,
    cvss_score   REAL,
    summary      TEXT,
    published    TEXT,
    modified     TEXT,
    source       TEXT DEFAULT 'rhsda'
);

CREATE TABLE IF NOT EXISTS kpatch_coverage (
    cve_id       TEXT NOT NULL,
    rhel_version TEXT NOT NULL,
    kernel       TEXT,
    patch_id     TEXT,
    available    INTEGER DEFAULT 0,
    PRIMARY KEY (cve_id, rhel_version)
);

CREATE TABLE IF NOT EXISTS leapp_inhibitor (
    package_name TEXT NOT NULL,
    from_ver     TEXT NOT NULL,
    to_ver       TEXT NOT NULL,
    reason       TEXT,
    fix          TEXT,
    PRIMARY KEY (package_name, from_ver, to_ver)
);

CREATE TABLE IF NOT EXISTS sap_note_xref (
    cve_id    TEXT NOT NULL,
    sap_note  TEXT NOT NULL,
    component TEXT,
    title     TEXT,
    url       TEXT,
    PRIMARY KEY (cve_id, sap_note)
);

CREATE TABLE IF NOT EXISTS sync_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_at    TEXT DEFAULT (datetime('now')),
    source    TEXT,
    records   INTEGER,
    status    TEXT
);
"""


def connect(db_path: Path = None) -> sqlite3.Connection:
    path = db_path or DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn
