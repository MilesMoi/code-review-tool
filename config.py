from pathlib import Path

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "scans.db"
JULIET_DIR = Path(r"C:\projects\data\juliet")
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5-coder:7b"
CHOSEN_CWES = ["CWE121", "CWE122", "CWE190", "CWE416", "CWE476"]
UPLOAD_DIR = BASE_DIR / "uploads"
MAX_UPLOAD_BYTES = 50_000  # about 1,500 lines of C