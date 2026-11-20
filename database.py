import sqlite3
from datetime import datetime, timezone


class ScannerDatabase:
    def __init__(self, db_path="scanner.db"):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_url TEXT NOT NULL,
                    max_depth INTEGER NOT NULL DEFAULT 2,
                    status TEXT NOT NULL DEFAULT 'running',
                    visited_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    scanner TEXT NOT NULL,
                    vulnerability TEXT NOT NULL,
                    url TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                );
                """
            )
            cols = [row["name"] for row in conn.execute("PRAGMA table_info(scans)").fetchall()]
            if "visited_count" not in cols:
                conn.execute(
                    "ALTER TABLE scans ADD COLUMN visited_count INTEGER NOT NULL DEFAULT 0"
                )

    def update_scan_stats(self, scan_id, visited_count):
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET visited_count = ? WHERE id = ?",
                (visited_count, scan_id),
            )

    def update_scan_status(self, scan_id, status):
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET status = ? WHERE id = ?",
                (status, scan_id),
            )

    def create_scan(self, target_url, max_depth=2):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (target_url, max_depth, status, created_at)
                VALUES (?, ?, 'running', ?)
                """,
                (target_url, max_depth, now),
            )
            return cursor.lastrowid

    def save_findings(self, scan_id, finding_dicts):
        if not finding_dicts:
            return
        rows = [
            (
                scan_id,
                item["scanner"],
                item["vulnerability"],
                item["url"],
                item["severity"],
                item["evidence"],
                item["remediation"],
            )
            for item in finding_dicts
        ]
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO findings (
                    scan_id, scanner, vulnerability, url, severity, evidence, remediation
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def list_scans(self):
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    s.id,
                    s.target_url,
                    s.max_depth,
                    s.visited_count,
                    s.status,
                    s.created_at,
                    COUNT(f.id) AS total_findings,
                    SUM(CASE WHEN f.severity = 'High' THEN 1 ELSE 0 END) AS high_count,
                    SUM(CASE WHEN f.severity = 'Medium' THEN 1 ELSE 0 END) AS medium_count,
                    SUM(CASE WHEN f.severity = 'Low' THEN 1 ELSE 0 END) AS low_count
                FROM scans s
                LEFT JOIN findings f ON f.scan_id = s.id
                GROUP BY s.id
                ORDER BY s.id DESC
                """
            ).fetchall()
            return [dict(r) for r in rows]

    def get_scan(self, scan_id):
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            return dict(row) if row else None

    def get_findings(self, scan_id, severity=None):
        query = "SELECT * FROM findings WHERE scan_id = ?"
        params = [scan_id]
        if severity and severity.upper() != "ALL":
            query += " AND LOWER(severity) = LOWER(?)"
            params.append(severity.strip())
        query += " ORDER BY id ASC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
