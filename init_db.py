import sqlite3

from config import BASE_DIR, DB_PATH

conn = sqlite3.connect(DB_PATH)
with open(BASE_DIR / "schema.sql") as f:
    conn.executescript(f.read())
conn.close()
print("Created", DB_PATH)