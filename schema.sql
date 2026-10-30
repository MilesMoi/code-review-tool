CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    input_name TEXT NOT NULL,
    tool TEXT NOT NULL,
    model_name TEXT,
    prompt_version TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    source_tool TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER,
    cwe TEXT,
    severity TEXT,
    message TEXT
);

CREATE TABLE IF NOT EXISTS ground_truth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dataset TEXT NOT NULL,
    file TEXT NOT NULL,
    function_name TEXT,
    start_line INTEGER,
    end_line INTEGER,
    cwe TEXT,
    is_vulnerable INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    tool TEXT NOT NULL,
    cwe TEXT,
    true_pos INTEGER,
    false_pos INTEGER,
    false_neg INTEGER,
    precision REAL,
    recall REAL,
    f1 REAL
);