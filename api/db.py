"""SQLite database layer for Cerberus."""

import json
import sqlite3
import datetime
from contextlib import contextmanager

from core.config import Config


def get_db_path():
    return Config.DB_PATH


def init_db():
    """Initialize the database schema."""
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                domain TEXT NOT NULL UNIQUE,
                target_type TEXT DEFAULT 'domain',
                emails TEXT DEFAULT '[]',
                tags TEXT DEFAULT '[]',
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                results TEXT DEFAULT '{}',
                started_at TEXT,
                completed_at TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (target_id) REFERENCES targets(id)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                target_id INTEGER NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                remediation TEXT,
                status TEXT DEFAULT 'open',
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (scan_id) REFERENCES scans(id),
                FOREIGN KEY (target_id) REFERENCES targets(id)
            );

            CREATE TABLE IF NOT EXISTS compliance_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                scan_id INTEGER,
                framework TEXT NOT NULL,
                score INTEGER NOT NULL,
                grade TEXT NOT NULL,
                details TEXT DEFAULT '{}',
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (target_id) REFERENCES targets(id),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS breaches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                breach_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                source TEXT,
                detected_at TEXT DEFAULT (datetime('now')),
                status TEXT DEFAULT 'new',
                FOREIGN KEY (target_id) REFERENCES targets(id)
            );

            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id INTEGER NOT NULL,
                report_type TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (target_id) REFERENCES targets(id)
            );
        """)


@contextmanager
def get_connection():
    """Get a database connection as a context manager."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# --- Targets ---

def create_target(name: str, domain: str, target_type: str = "domain", emails: list = None, tags: list = None) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO targets (name, domain, target_type, emails, tags) VALUES (?, ?, ?, ?, ?)",
            (name, domain, target_type, json.dumps(emails or []), json.dumps(tags or [])),
        )
        return cursor.lastrowid


def get_targets() -> list:
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM targets ORDER BY created_at DESC").fetchall()
        return [_row_to_dict(r) for r in rows]


def get_target(target_id: int) -> dict:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        return _row_to_dict(row) if row else None


# --- Scans ---

def create_scan(target_id: int, scan_type: str) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO scans (target_id, scan_type, status, started_at) VALUES (?, ?, 'running', datetime('now'))",
            (target_id, scan_type),
        )
        return cursor.lastrowid


def update_scan(scan_id: int, status: str, results: dict = None):
    with get_connection() as conn:
        conn.execute(
            "UPDATE scans SET status = ?, results = ?, completed_at = datetime('now') WHERE id = ?",
            (status, json.dumps(results or {}), scan_id),
        )


def get_scans(target_id: int = None, limit: int = 50) -> list:
    with get_connection() as conn:
        if target_id:
            rows = conn.execute(
                "SELECT * FROM scans WHERE target_id = ? ORDER BY created_at DESC LIMIT ?",
                (target_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [_row_to_dict(r) for r in rows]


# --- Findings ---

def create_finding(scan_id: int, target_id: int, severity: str, category: str,
                   title: str, description: str = "", remediation: str = "") -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO findings (scan_id, target_id, severity, category, title, description, remediation) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (scan_id, target_id, severity, category, title, description, remediation),
        )
        return cursor.lastrowid


def get_findings(target_id: int = None, severity: str = None, status: str = None, limit: int = 100) -> list:
    with get_connection() as conn:
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        if target_id:
            query += " AND target_id = ?"
            params.append(target_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [_row_to_dict(r) for r in rows]


def update_finding_status(finding_id: int, status: str):
    with get_connection() as conn:
        conn.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))


# --- Compliance Scores ---

def save_compliance_score(target_id: int, scan_id: int, framework: str, score: int, grade: str, details: dict = None):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO compliance_scores (target_id, scan_id, framework, score, grade, details) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (target_id, scan_id, framework, score, grade, json.dumps(details or {})),
        )


def get_compliance_scores(target_id: int = None) -> list:
    with get_connection() as conn:
        if target_id:
            rows = conn.execute(
                "SELECT * FROM compliance_scores WHERE target_id = ? ORDER BY created_at DESC",
                (target_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM compliance_scores ORDER BY created_at DESC"
            ).fetchall()
        return [_row_to_dict(r) for r in rows]


# --- Breaches ---

def create_breach(target_id: int, breach_type: str, severity: str, title: str,
                  description: str = "", source: str = ""):
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO breaches (target_id, breach_type, severity, title, description, source) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (target_id, breach_type, severity, title, description, source),
        )


def get_breaches(target_id: int = None, status: str = None) -> list:
    with get_connection() as conn:
        query = "SELECT * FROM breaches WHERE 1=1"
        params = []
        if target_id:
            query += " AND target_id = ?"
            params.append(target_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY detected_at DESC"
        rows = conn.execute(query, params).fetchall()
        return [_row_to_dict(r) for r in rows]


# --- Reports ---

def create_report(target_id: int, report_type: str, title: str, content: str) -> int:
    with get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO reports (target_id, report_type, title, content) VALUES (?, ?, ?, ?)",
            (target_id, report_type, title, content),
        )
        return cursor.lastrowid


def get_reports(target_id: int = None) -> list:
    with get_connection() as conn:
        if target_id:
            rows = conn.execute(
                "SELECT * FROM reports WHERE target_id = ? ORDER BY created_at DESC",
                (target_id,),
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM reports ORDER BY created_at DESC").fetchall()
        return [_row_to_dict(r) for r in rows]


# --- Dashboard ---

def get_dashboard_stats(target_id: int = None) -> dict:
    with get_connection() as conn:
        where = "WHERE target_id = ?" if target_id else ""
        params = (target_id,) if target_id else ()

        # Finding counts by severity
        severity_counts = {}
        for sev in ("critical", "high", "medium", "low"):
            q = f"SELECT COUNT(*) FROM findings {where}{' AND' if where else 'WHERE'} severity = ? AND status = 'open'"
            p = params + (sev,)
            severity_counts[sev] = conn.execute(q, p).fetchone()[0]

        # Total targets
        total_targets = conn.execute("SELECT COUNT(*) FROM targets").fetchone()[0]

        # Latest scan
        latest_scan = conn.execute(
            f"SELECT * FROM scans {where} ORDER BY created_at DESC LIMIT 1", params
        ).fetchone()

        # Latest compliance scores
        compliance = {}
        for framework in ("owasp_top_10", "soc2", "gdpr", "pci_dss", "iso_27001"):
            q = f"SELECT score, grade FROM compliance_scores {where}{' AND' if where else 'WHERE'} framework = ? ORDER BY created_at DESC LIMIT 1"
            p = params + (framework,)
            row = conn.execute(q, p).fetchone()
            if row:
                compliance[framework] = {"score": row["score"], "grade": row["grade"]}

        # Breach count
        breach_count = conn.execute(
            f"SELECT COUNT(*) FROM breaches {where}{' AND' if where else 'WHERE'} status = 'new'", params
        ).fetchone()[0]

        total_findings = sum(severity_counts.values())
        # Calculate overall security score (inverse of risk)
        risk = (
            severity_counts["critical"] * 25
            + severity_counts["high"] * 15
            + severity_counts["medium"] * 5
            + severity_counts["low"] * 1
        )
        security_score = max(0, 100 - min(100, risk))

        return {
            "security_score": security_score,
            "grade": _score_grade(security_score),
            "total_targets": total_targets,
            "total_findings": total_findings,
            "severity_counts": severity_counts,
            "compliance": compliance,
            "breach_alerts": breach_count,
            "latest_scan": _row_to_dict(latest_scan) if latest_scan else None,
        }


def _score_grade(score: int) -> str:
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    return "F"


def _row_to_dict(row) -> dict:
    if row is None:
        return None
    d = dict(row)
    # Parse JSON fields
    for key in ("results", "details", "emails", "tags"):
        if key in d and isinstance(d[key], str):
            try:
                d[key] = json.loads(d[key])
            except (json.JSONDecodeError, TypeError):
                pass
    return d
