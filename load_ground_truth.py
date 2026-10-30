import sqlite3

from config import CHOSEN_CWES, DB_PATH, JULIET_DIR
from pipeline.labels import load_juliet

conn = sqlite3.connect(DB_PATH)
rows = load_juliet(conn, JULIET_DIR, CHOSEN_CWES)
conn.commit()
conn.close()
print("Added", rows, "labelled functions")