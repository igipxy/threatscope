import json
import sqlite3
from pathlib import Path

from .models import Finding, ScanResult


def initialize_database(database_path: str) -> None:
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                provider TEXT NOT NULL,
                analysis_status TEXT NOT NULL DEFAULT 'completed',
                scanned_at TEXT NOT NULL,
                findings TEXT NOT NULL
            )
            """
        )
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
        if "analysis_status" not in columns:
            connection.execute(
                "ALTER TABLE scans ADD COLUMN analysis_status TEXT NOT NULL DEFAULT 'completed'"
            )


def save_scan(database_path: str, result: ScanResult) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO scans
            (id, target, target_type, score, verdict, provider, analysis_status, scanned_at, findings)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.id,
                result.target,
                result.target_type,
                result.score,
                result.verdict,
                result.provider,
                result.analysis_status,
                result.scanned_at.isoformat(),
                json.dumps([finding.model_dump() for finding in result.findings]),
            ),
        )


def update_scan(
    database_path: str,
    scan_id: str,
    score: int,
    verdict: str,
    findings: list[Finding],
    provider: str,
) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            UPDATE scans
            SET score = ?, verdict = ?, provider = ?, analysis_status = 'completed', findings = ?
            WHERE id = ?
            """,
            (
                score,
                verdict,
                provider,
                json.dumps([finding.model_dump() for finding in findings]),
                scan_id,
            ),
        )


def list_scans(database_path: str, limit: int = 20) -> list[ScanResult]:
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ?", (limit,)
        ).fetchall()

    return [
        ScanResult(
            id=row["id"],
            target=row["target"],
            target_type=row["target_type"],
            score=row["score"],
            verdict="low_risk" if row["verdict"] == "clean" else row["verdict"],
            provider=row["provider"],
            analysis_status=row["analysis_status"] if "analysis_status" in row.keys() else "completed",
            scanned_at=row["scanned_at"],
            findings=json.loads(row["findings"]),
        )
        for row in rows
    ]
