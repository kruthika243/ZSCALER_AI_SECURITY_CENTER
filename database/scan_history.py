
import json
from datetime import datetime, timezone

from database.db import get_connection


def save_scan(result: dict):

    google_result = result.get("google_safe_browsing", {})

    google_status = google_result.get("status", "NOT_CHECKED")

    google_matches = json.dumps(
        google_result.get("matches", [])
    )

    # Google threat matches override the overall verdict.
    if google_status == "MATCH":
        overall_verdict = "CRITICAL"
    else:
        overall_verdict = result["risk_level"]

    with get_connection() as connection:

        connection.execute("""
            INSERT INTO scans (
                url,
                hostname,
                risk_score,
                risk_level,
                reasons,
                features,
                recommendation,
                scanned_at,
                google_status,
                google_matches,
                overall_verdict
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result["url"],
            result["hostname"],
            result["risk_score"],
            result["risk_level"],
            json.dumps(result["reasons"]),
            json.dumps(result["features"]),
            result["recommendation"],
            datetime.now(timezone.utc).isoformat(),
            google_status,
            google_matches,
            overall_verdict
        ))

        connection.commit()


def get_scan_history(limit=100):

    with get_connection() as connection:

        rows = connection.execute("""
            SELECT *
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return [dict(row) for row in rows]


def get_scan_counts():

    with get_connection() as connection:

        rows = connection.execute("""
            SELECT risk_level, COUNT(*) AS total
            FROM scans
            GROUP BY risk_level
        """).fetchall()

        total = connection.execute("""
            SELECT COUNT(*) FROM scans
        """).fetchone()[0]

    counts = {
        "LOW": 0,
        "MODERATE": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }

    for row in rows:
        counts[row["risk_level"]] = row["total"]

    counts["TOTAL"] = total

    return counts
