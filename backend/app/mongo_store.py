from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

try:
    from pymongo import MongoClient, ASCENDING
    from pymongo.errors import PyMongoError
except Exception:  # optional at runtime in SQLite-only demos
    MongoClient = None
    ASCENDING = None
    PyMongoError = Exception

from .config import MONGO_URL, MONGO_DB

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
ACTIVITY_FILE = DATA_DIR / "activity_fallback.json"
BASELINE_FILE = DATA_DIR / "behavioral_baselines_fallback.json"
ANOMALY_FILE = DATA_DIR / "anomaly_results_fallback.json"

_client = None
_db = None


def _ensure_files() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    for path in (ACTIVITY_FILE, BASELINE_FILE, ANOMALY_FILE):
        if not path.exists():
            path.write_text("[]", encoding="utf-8")


def _read(path: Path) -> list[dict[str, Any]]:
    _ensure_files()
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []


def _write(path: Path, rows: list[dict[str, Any]]) -> None:
    _ensure_files()
    path.write_text(json.dumps(rows, indent=2, default=str), encoding="utf-8")


def get_db():
    global _client, _db
    if _db is not None:
        return _db
    if MongoClient is None:
        return None
    try:
        _client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=800)
        _client.admin.command("ping")
        _db = _client[MONGO_DB]
        return _db
    except Exception:
        _client = None
        _db = None
        return None


def mongo_status():
    db = get_db()
    return {"connected": db is not None, "database": MONGO_DB, "fallback": "local JSON"}


def insert_activity(doc: dict) -> dict:
    payload = dict(doc)
    payload["created_at"] = datetime.now(timezone.utc).isoformat()
    db = get_db()
    if db is not None:
        try:
            result = db.activity_logs.insert_one({**doc, "created_at": datetime.now(timezone.utc)})
            return {"stored": True, "storage": "mongodb", "id": str(result.inserted_id)}
        except PyMongoError:
            pass
    rows = _read(ACTIVITY_FILE)
    payload["_id"] = f"local-{len(rows)+1}"
    rows.insert(0, payload)
    _write(ACTIVITY_FILE, rows[:1000])
    return {"stored": True, "storage": "local-json", "id": payload["_id"]}


def recent_activities(limit: int = 50) -> list[dict[str, Any]]:
    db = get_db()
    if db is not None:
        try:
            docs = list(db.activity_logs.find({}, {"_id": 0}).sort("created_at", -1).limit(limit))
            for d in docs:
                if isinstance(d.get("created_at"), datetime):
                    d["created_at"] = d["created_at"].isoformat()
            return docs
        except Exception:
            pass
    return _read(ACTIVITY_FILE)[:limit]


def save_baseline(employee_id: str, baseline: dict[str, Any]) -> dict:
    doc = dict(baseline)
    doc["employee_id"] = employee_id
    db = get_db()
    if db is not None:
        try:
            db.behavioral_baselines.update_one(
                {"employee_id": employee_id},
                {"$set": doc},
                upsert=True,
            )
            return {"stored": True, "storage": "mongodb"}
        except PyMongoError:
            pass
    rows = [x for x in _read(BASELINE_FILE) if x.get("employee_id") != employee_id]
    rows.insert(0, doc)
    _write(BASELINE_FILE, rows)
    return {"stored": True, "storage": "local-json"}


def get_baseline(employee_id: str) -> dict[str, Any] | None:
    db = get_db()
    if db is not None:
        try:
            doc = db.behavioral_baselines.find_one({"employee_id": employee_id}, {"_id": 0})
            if doc:
                return doc
        except Exception:
            pass
    for row in _read(BASELINE_FILE):
        if row.get("employee_id") == employee_id:
            return row
    return None


def recent_anomalies(employee_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    db = get_db()
    if db is not None:
        try:
            query = {"employee_id": employee_id} if employee_id else {}
            docs = list(db.anomaly_results.find(query, {"_id": 0}).sort("created_at", -1).limit(limit))
            for d in docs:
                if isinstance(d.get("created_at"), datetime):
                    d["created_at"] = d["created_at"].isoformat()
            return docs
        except Exception:
            pass
    rows = _read(ANOMALY_FILE)
    if employee_id:
        rows = [x for x in rows if x.get("employee_id") == employee_id]
    return rows[:limit]


def save_anomaly(result: dict[str, Any]) -> dict:
    payload = dict(result)
    payload.setdefault("created_at", datetime.now(timezone.utc).isoformat())
    db = get_db()
    if db is not None:
        try:
            out = db.anomaly_results.insert_one({**payload, "created_at": datetime.now(timezone.utc)})
            return {"stored": True, "storage": "mongodb", "id": str(out.inserted_id)}
        except PyMongoError:
            pass
    rows = _read(ANOMALY_FILE)
    payload["_id"] = f"local-{len(rows)+1}"
    rows.insert(0, payload)
    _write(ANOMALY_FILE, rows[:1000])
    return {"stored": True, "storage": "local-json", "id": payload["_id"]}


def seed_normal_activity(employees: list[dict[str, Any]]) -> None:
    """Seed a small, deterministic normal-history dataset for demo baseline learning."""
    existing = recent_activities(1000)
    if existing:
        return
    normal = []
    templates = [
        ("09:04", "login", {"time": "09:04", "new_device": False}),
        ("09:12", "login", {"time": "09:12", "new_device": False}),
        ("14:10", "file_download", {"files": 28, "size_mb": 180}),
        ("15:25", "file_download", {"files": 34, "size_mb": 210}),
        ("16:40", "file_download", {"files": 42, "size_mb": 290}),
    ]
    for employee in employees:
        for _, event_type, details in templates:
            normal.append({
                "employee_id": employee["employee_id"],
                "event_type": event_type,
                "source": "Mock SIEM",
                "details": details,
            })
    for item in normal:
        insert_activity(item)
