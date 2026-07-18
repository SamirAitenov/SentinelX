import sqlite3

DATABASE = "sentinelx.db"


def initialize_database():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file TEXT,
        risk TEXT,
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    connection.commit()
    connection.close()


def save_threat(file, risk):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
    INSERT INTO threats(file, risk)
    VALUES (?, ?)
    """, (file, risk))

    connection.commit()
    connection.close()


def get_threat_count():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
    SELECT COUNT(*) FROM threats
    """)

    count = cursor.fetchone()[0]

    connection.close()

    return count


def get_threat_counts_by_risk():
    """Returns a dict like {"HIGH": 3, "MEDIUM": 1, "LOW": 0}."""

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
    SELECT risk, COUNT(*) FROM threats GROUP BY risk
    """)

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for risk, count in cursor.fetchall():
        counts[risk] = count

    connection.close()

    return counts


def delete_threat_by_file(file_path):
    """Removes threat record(s) matching a file path (used when a file is restored/deleted)."""

    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()

    cursor.execute("""
    DELETE FROM threats WHERE file = ?
    """, (file_path,))

    connection.commit()
    connection.close()