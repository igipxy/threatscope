import json
import sqlite3

from app.storage import initialize_database


def test_initialize_database_migrates_legacy_scan_cache_columns(tmp_path):
    database_path = tmp_path / "legacy.db"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE scans (
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
        connection.execute(
            """
            INSERT INTO scans
            (id, target, target_type, score, verdict, provider, analysis_status, scanned_at, findings)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "legacy-scan",
                "example.com",
                "domain",
                5,
                "low_risk",
                "ThreatScope + VirusTotal report",
                "completed",
                "2026-08-20T00:00:00+00:00",
                json.dumps([]),
            ),
        )

    initialize_database(str(database_path))

    with sqlite3.connect(database_path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
        analysis_mode, cacheable = connection.execute(
            "SELECT analysis_mode, cacheable FROM scans WHERE id = ?",
            ("legacy-scan",),
        ).fetchone()

    assert {"analysis_mode", "cacheable"}.issubset(columns)
    assert analysis_mode == "virustotal"
    assert cacheable == 1
