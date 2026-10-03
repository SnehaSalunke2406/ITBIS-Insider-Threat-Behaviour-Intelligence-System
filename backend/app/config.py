from pathlib import Path
import os
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "itbis")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
SQLITE_PATH = os.getenv("SQLITE_PATH", str(BASE_DIR / "itbis_local.db"))
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "itbis")
JWT_SECRET = os.getenv("JWT_SECRET", "change-this-local-secret")
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "480"))
AUTO_SEED = os.getenv("AUTO_SEED", "true").lower() == "true"
PREFER_POSTGRES = os.getenv("PREFER_POSTGRES", "true").lower() == "true"
