"""Database abstraction layer supporting SQLite (with WAL mode) and PostgreSQL."""
from __future__ import annotations

import os
import sqlite3

SCHEMA_SQLITE = """
CREATE TABLE IF NOT EXISTS campaigns(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  created TEXT NOT NULL,
  total INTEGER NOT NULL,
  leaks INTEGER NOT NULL,
  asr REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  goal TEXT,
  attack TEXT,
  verdict TEXT,
  owasp TEXT,
  prompt TEXT,
  response TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_campaign ON findings(campaign_id);
"""

SCHEMA_POSTGRES = """
CREATE TABLE IF NOT EXISTS campaigns(
  id SERIAL PRIMARY KEY,
  target VARCHAR(100) NOT NULL,
  created TIMESTAMP NOT NULL,
  total INTEGER NOT NULL,
  leaks INTEGER NOT NULL,
  asr DOUBLE PRECISION NOT NULL
);

CREATE TABLE IF NOT EXISTS findings(
  id SERIAL PRIMARY KEY,
  campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  goal TEXT,
  attack VARCHAR(100),
  verdict VARCHAR(50),
  owasp TEXT,
  prompt TEXT,
  response TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_campaign ON findings(campaign_id);
"""


class Database:
    """Manages database connectivity and schema lifecycle."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_sqlite()

    def _init_sqlite(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA foreign_keys=ON")
            # Enable Write-Ahead Logging (WAL) for superior concurrent read/write throughput
            try:
                conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError:
                pass
            conn.executescript(SCHEMA_SQLITE)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn


def init_db(db_path: str) -> Database:
    return Database(db_path)


def get_db(db_path: str) -> sqlite3.Connection:
    return Database(db_path).connect()
