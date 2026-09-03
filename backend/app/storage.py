import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import ScanResult


def initialize_database(database_path: str) -> None:
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                cache_key TEXT NOT NULL,
                target_type TEXT NOT NULL,
                score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                provider TEXT NOT NULL,
                analysis_mode TEXT NOT NULL DEFAULT 'local',
                cacheable INTEGER NOT NULL DEFAULT 1,
                analysis_status TEXT NOT NULL DEFAULT 'completed',
                scanned_at TEXT NOT NULL,
                findings TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS provider_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                requested_at TEXT NOT NULL
            )
            """
        )
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
        if "cache_key" not in columns:
            connection.execute("ALTER TABLE scans ADD COLUMN cache_key TEXT NOT NULL DEFAULT ''")
        if "analysis_status" not in columns:
            connection.execute("ALTER TABLE scans ADD COLUMN analysis_status TEXT NOT NULL DEFAULT 'completed'")
        if "analysis_mode" not in columns:
            connection.execute("ALTER TABLE scans ADD COLUMN analysis_mode TEXT NOT NULL DEFAULT 'local'")
            connection.execute(
                """
                UPDATE scans
                SET analysis_mode = 'virustotal'
                WHERE provider LIKE '%VirusTotal%'
                """
            )
        if "cacheable" not in columns:
            connection.execute("ALTER TABLE scans ADD COLUMN cacheable INTEGER NOT NULL DEFAULT 1")


def row_to_scan(row: sqlite3.Row) -> ScanResult:
    return ScanResult(
        id=row["id"],
        target=row["target"],
        target_type=row["target_type"],
        score=row["score"],
        verdict="low_risk" if row["verdict"] == "clean" else row["verdict"],
        provider=row["provider"],
        analysis_status="completed",
        scanned_at=row["scanned_at"],
        findings=json.loads(row["findings"]),
    )


def save_scan(
    database_path: str,
    result: ScanResult,
    analysis_mode: str = "local",
    *,
    cache_target: str | None = None,
    cacheable: bool = True,
    max_stored_scans: int = 500,
) -> None:
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO scans
            (id, target, cache_key, target_type, score, verdict, provider, analysis_mode, cacheable, analysis_status, scanned_at, findings)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.id, result.target, _cache_key(cache_target or result.target), result.target_type, result.score, result.verdict,
                result.provider, analysis_mode, int(cacheable), result.analysis_status, result.scanned_at.isoformat(),
                json.dumps([finding.model_dump() for finding in result.findings]),
            ),
        )
        connection.execute(
            """
            DELETE FROM scans
            WHERE id NOT IN (
                SELECT id FROM scans ORDER BY scanned_at DESC LIMIT ?
            )
            """,
            (max(1, max_stored_scans),),
        )


def _cache_key(target: str) -> str:
    return hashlib.sha256(target.encode("utf-8")).hexdigest()


def get_cached_scan(
    database_path: str,
    target: str,
    max_age_seconds: int,
    analysis_mode: str = "local",
) -> ScanResult | None:
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT * FROM scans
            WHERE (cache_key = ? OR (cache_key = '' AND target = ?))
              AND analysis_mode = ? AND cacheable = 1
            ORDER BY scanned_at DESC
            LIMIT 1
            """,
            (_cache_key(target), target, analysis_mode),
        ).fetchone()
    if not row:
        return None
    result = row_to_scan(row)
    scanned_at = result.scanned_at
    if scanned_at.tzinfo is None:
        scanned_at = scanned_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - scanned_at > timedelta(seconds=max_age_seconds):
        return None
    return result


def list_scans(database_path: str, limit: int = 20) -> list[ScanResult]:
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM scans ORDER BY scanned_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [row_to_scan(row) for row in rows]


def reserve_provider_request(
    database_path: str,
    provider: str,
    max_per_minute: int,
    max_per_day: int,
) -> tuple[bool, str]:
    now = datetime.now(timezone.utc)
    minute_cutoff = (now - timedelta(minutes=1)).isoformat()
    day_cutoff = (now - timedelta(days=1)).isoformat()
    with sqlite3.connect(database_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        minute_count = connection.execute(
            "SELECT COUNT(*) FROM provider_requests WHERE provider = ? AND requested_at >= ?",
            (provider, minute_cutoff),
        ).fetchone()[0]
        if minute_count >= max_per_minute:
            return False, "per-minute budget reached"
        day_count = connection.execute(
            "SELECT COUNT(*) FROM provider_requests WHERE provider = ? AND requested_at >= ?",
            (provider, day_cutoff),
        ).fetchone()[0]
        if day_count >= max_per_day:
            return False, "daily budget reached"
        connection.execute(
            "INSERT INTO provider_requests (provider, requested_at) VALUES (?, ?)",
            (provider, now.isoformat()),
        )
    return True, ""
