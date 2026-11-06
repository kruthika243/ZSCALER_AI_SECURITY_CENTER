
import sqlite3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "database" / "security_scans.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(str(DB_PATH))
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():

    with get_connection() as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                hostname TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                reasons TEXT,
                features TEXT,
                recommendation TEXT,
                scanned_at TEXT NOT NULL,
                google_status TEXT,
                google_matches TEXT,
                overall_verdict TEXT
            )
        """)

        # Safely migrate existing databases.
        # Existing scan records are preserved.
        existing_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(scans)"
            ).fetchall()
        }

        new_columns = {
            "google_status": "TEXT",
            "google_matches": "TEXT",
            "overall_verdict": "TEXT",
        }

        for column, column_type in new_columns.items():

            if column not in existing_columns:
                connection.execute(
                    f"ALTER TABLE scans ADD COLUMN {column} {column_type}"
                )

        connection.commit()
