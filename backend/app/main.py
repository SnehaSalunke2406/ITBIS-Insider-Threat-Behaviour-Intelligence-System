from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.responses import FileResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from collections import defaultdict
import time

from .config import AUTO_SEED
from .database import engine, SessionLocal, get_db, DB_MODE
from .models import Base, User, Employee, Alert, Incident, AuditEvent
from .security import hash_password, verify_password, create_token, decode_token
from .mongo_store import (
    mongo_status,
    insert_activity,
    recent_activities,
    save_baseline,
    get_baseline,
    recent_anomalies,
    save_anomaly,
    seed_normal_activity,
)
from .intelligence import (
    analyze_activity,
    default_baseline,
    build_baseline_from_activities,
)

BASE_DIR = Path(__file__).resolve().parents[2]
FRONTEND = BASE_DIR / "frontend"
app = FastAPI(
    title="Insider Threat Behaviour Intelligence System",
    version="2.0.0",
    description="Explainable behaviour-baseline and insider-threat anomaly monitoring platform.",
)
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)
app.mount("/static", StaticFiles(directory=FRONTEND), name="static")


class LoginRequest(BaseModel):
    email: str
    password: str


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None


class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None


class ActivityRequest(BaseModel):
    employee_id: str = Field(..., min_length=1)
    event_type: str = Field(..., min_length=1)
    source: str = "Mock SIEM"
    details: dict = Field(default_factory=dict)


class SimulateRequest(BaseModel):
    employee_id: str = Field(..., min_length=1)
    scenario: str = Field(..., min_length=1)


def seed_if_needed():
    if not AUTO_SEED:
        return
    db = SessionLocal()
    try:
        Base.metadata.create_all(engine)
        if db.query(User).count() == 0:
            users = [
                ("admin@ueba.com", "admin"),
                ("analyst@ueba.com", "security_analyst"),
                ("soc@ueba.com", "soc_engineer"),
                ("manager@ueba.com", "security_manager"),
            ]
            for email, role in users:
                db.add(User(email=email, role=role, password_hash=hash_password("admin123")))
            db.commit()
        if db.query(Employee).count() == 0:
            employees = [
                Employee(employee_id="EMP1001", name="Aarav Kulkarni", department="Finance", designation="Accounts Executive", device_info="WIN-FIN-21", access_privileges="Finance shares", risk_score=18),
                Employee(employee_id="EMP1002", name="Neha Patil", department="Engineering", designation="Software Engineer", device_info="WIN-ENG-07", access_privileges="Source code, customer files", risk_score=42),
                Employee(employee_id="EMP1003", name="Rohan Deshmukh", department="HR", designation="HR Executive", device_info="WIN-HR-03", access_privileges="HR records", risk_score=8),
                Employee(employee_id="EMP1004", name="Vikram Joshi", department="Sales", designation="Sales Manager", device_info="WIN-SAL-11", access_privileges="CRM, exports", risk_score=76),
                Employee(employee_id="EMP1005", name="Maya Shah", department="IT", designation="System Administrator", device_info="WIN-IT-01", access_privileges="Privileged admin", risk_score=28),
            ]
            db.add_all(employees)
            db.commit()
            analyst = db.query(User).filter(User.email == "analyst@ueba.com").first()
            e4 = db.query(Employee).filter(Employee.employee_id == "EMP1004").first()
            e2 = db.query(Employee).filter(Employee.employee_id == "EMP1002").first()
            db.add(Alert(employee_id=e4.id, severity="high", message="After-hours access pattern detected", assigned_to=analyst.id if analyst else None))
            db.add(Alert(employee_id=e2.id, severity="medium", message="Large file download differs from baseline", assigned_to=analyst.id if analyst else None))
            db.add(Incident(employee_id=e4.id, severity="high", status="investigating", title="Suspicious after-hours activity", description="Observed access outside the employee baseline window."))
            db.commit()

        employees = db.query(Employee).all()
        employee_payload = [{"employee_id": e.employee_id, "device_info": e.device_info} for e in employees]
        seed_normal_activity(employee_payload)
        history = recent_activities(1000)
        for e in employees:
            if get_baseline(e.employee_id) is None:
                baseline = build_baseline_from_activities(e.employee_id, e.device_info or "Windows workstation", history)
                save_baseline(e.employee_id, baseline)
    finally:
        db.close()


@app.on_event("startup")
def startup():
    seed_if_needed()


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(FRONTEND / "index.html")


@app.get("/api/health")
def health():
    postgres = False
    try:
        with engine.connect() as c:
            c.execute(text("SELECT 1"))
            postgres = True
    except Exception:
        pass
    return {"status": "ok", "database_mode": DB_MODE, "postgres_connected": postgres if DB_MODE == "postgresql" else False, "mongo": mongo_status()}


def current_user(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")
    try:
        return decode_token(authorization.split(" ", 1)[1])
    except Exception:
        raise HTTPException(401, "Invalid or expired token")


def audit(db: Session, actor: str, action: str, target: str = ""):
    db.add(AuditEvent(actor_email=actor, action=action, target=target))
    db.commit()


def employee_dict(e: Employee):
    return {
        "id": e.id,
        "employee_id": e.employee_id,
        "name": e.name,
        "department": e.department,
        "designation": e.designation,
        "device_info": e.device_info,
        "access_privileges": e.access_privileges,
        "risk_score": round(float(e.risk_score or 0), 1),
    }


def resolve_employee(db: Session, employee_id: str) -> Employee:
    employee = db.query(Employee).filter(Employee.employee_id == employee_id.strip()).first()
    if not employee:
        raise HTTPException(404, f"Employee {employee_id} not found")
    return employee


def perform_analysis(body: ActivityRequest, user: dict, db: Session):
    employee = resolve_employee(db, body.employee_id)
    baseline = get_baseline(employee.employee_id) or default_baseline(employee.employee_id, employee.device_info or "Windows workstation")
    activity_doc = body.model_dump()
    storage = insert_activity(activity_doc)
    analysis = analyze_activity(activity_doc, baseline)
    anomaly_doc = {
        "employee_id": employee.employee_id,
        "event_type": body.event_type,
        "anomaly_score": analysis["anomaly_score"],
        "severity": analysis["severity"],
        "is_anomaly": analysis["is_anomaly"],
        "reasons": analysis["reasons"],
        "deviations": analysis["deviations"],
        "recommendation": analysis["recommendation"],
    }
    analysis_storage = save_anomaly(anomaly_doc)

    previous_risk = float(employee.risk_score or 0)
    current_risk = max(previous_risk, float(analysis["anomaly_score"]))
    employee.risk_score = round(min(100, current_risk), 1)

    alert_created = None
    incident_created = None
    if analysis["anomaly_score"] >= 30:
        analyst = db.query(User).filter(User.role == "security_analyst").first()
        message = f"{body.event_type.replace('_', ' ').title()} deviates from baseline: " + analysis["reasons"][0]
        # Cooldown for the same employee/event so repeated refreshes do not flood the alert queue.
        recent_same = (
            db.query(Alert)
            .filter(Alert.employee_id == employee.id, Alert.message == message, Alert.status != "resolved")
            .order_by(Alert.created_at.desc())
            .first()
        )
        if recent_same is None:
            alert = Alert(
                employee_id=employee.id,
                severity=analysis["severity"],
                message=message[:500],
                assigned_to=analyst.id if analyst else None,
                status="open",
            )
            db.add(alert)
            db.flush()
            alert_created = alert.id
    if analysis["anomaly_score"] >= 60:
        incident = (
            db.query(Incident)
            .filter(Incident.employee_id == employee.id, Incident.status != "resolved")
            .order_by(Incident.created_at.desc())
            .first()
        )
        if incident is None:
            incident = Incident(
                employee_id=employee.id,
                severity=analysis["severity"],
                status="investigating",
                title=f"Behaviour anomaly: {body.event_type.replace('_', ' ').title()}",
                description="; ".join(analysis["reasons"]),
            )
            db.add(incident)
            db.flush()
            incident_created = incident.id
    db.commit()
    audit(db, user["email"], "Analysed activity", employee.employee_id)
    return {
        "employee": employee_dict(employee),
        "activity": {**activity_doc, "storage": storage["storage"]},
        "analysis": analysis,
        "alert_created": alert_created,
        "incident_created": incident_created,
        "analysis_storage": analysis_storage,
    }


_login_attempts: dict[str, list[float]] = defaultdict(list)
LOGIN_WINDOW_SECONDS = 300
MAX_LOGIN_ATTEMPTS = 8

def _check_login_rate(ip: str):
    now = time.time()
    recent = [t for t in _login_attempts[ip] if now - t < LOGIN_WINDOW_SECONDS]
    _login_attempts[ip] = recent
    if len(recent) >= MAX_LOGIN_ATTEMPTS:
        raise HTTPException(429, "Too many login attempts. Try again in a few minutes.")
    recent.append(now)

@app.post("/api/auth/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    _check_login_rate(request.client.host if request.client else "unknown")
    user = db.query(User).filter(func.lower(User.email) == body.email.lower().strip()).first()
    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password")
    token = create_token(user.id, user.email, user.role)
    audit(db, user.email, "Login", "Web dashboard")
    return {"token": token, "user": {"id": user.id, "email": user.email, "role": user.role}}


@app.get("/api/me")
def me(user=Depends(current_user)):
    return user


@app.get("/api/dashboard")
def dashboard(user=Depends(current_user), db: Session = Depends(get_db)):
    employees = db.query(Employee).order_by(Employee.risk_score.desc()).all()
    open_alerts = db.query(Alert).filter(Alert.status != "resolved").count()
    open_incidents = db.query(Incident).filter(Incident.status != "resolved").count()
    high_risk = sum(1 for e in employees if (e.risk_score or 0) >= 70)
    avg_risk = round(sum((e.risk_score or 0) for e in employees) / len(employees), 1) if employees else 0
    anomalies = [a for a in recent_anomalies(limit=200) if a.get("is_anomaly")]
    return {
        "employees_monitored": len(employees),
        "open_alerts": open_alerts,
        "open_incidents": open_incidents,
        "high_risk_employees": high_risk,
        "avg_risk": avg_risk,
        "behavior_anomalies": len(anomalies),
        "employees": [employee_dict(e) for e in employees[:6]],
    }


@app.get("/api/employees")
def employees(user=Depends(current_user), db: Session = Depends(get_db)):
    return [employee_dict(e) for e in db.query(Employee).order_by(Employee.risk_score.desc()).all()]


@app.get("/api/alerts")
def alerts(user=Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(Alert, Employee, User).join(Employee, Alert.employee_id == Employee.id).outerjoin(User, Alert.assigned_to == User.id).order_by(Alert.created_at.desc()).all()
    return [{"id": a.id, "employee_id": e.employee_id, "employee_name": e.name, "severity": a.severity, "message": a.message, "status": a.status, "assigned_to": u.email if u else None, "created_at": a.created_at.isoformat()} for a, e, u in rows]


@app.patch("/api/alerts/{alert_id}")
def update_alert(alert_id: int, body: AlertUpdate, user=Depends(current_user), db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    if body.status:
        a.status = body.status
    if body.severity:
        a.severity = body.severity
    db.commit()
    audit(db, user["email"], "Updated alert", str(alert_id))
    return {"message": "Alert updated"}


@app.get("/api/incidents")
def incidents(user=Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(Incident, Employee).join(Employee, Incident.employee_id == Employee.id).order_by(Incident.created_at.desc()).all()
    return [{"id": i.id, "employee_id": e.employee_id, "employee_name": e.name, "title": i.title, "description": i.description, "severity": i.severity, "status": i.status, "created_at": i.created_at.isoformat()} for i, e in rows]


@app.get("/api/incidents/{incident_id}/timeline")
def incident_timeline(incident_id: int, user=Depends(current_user), db: Session = Depends(get_db)):
    """Return an explainable investigation timeline for one incident.

    The timeline combines the structured incident/alert records with the mock activity
    and anomaly records generated by the behaviour-intelligence engine.
    """
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    employee = db.get(Employee, incident.employee_id)
    if not employee:
        raise HTTPException(404, "Incident employee not found")

    events: list[dict] = [{
        "timestamp": incident.created_at.isoformat(),
        "type": "incident",
        "title": "Incident created",
        "detail": incident.title,
        "severity": incident.severity,
    }]

    for alert in db.query(Alert).filter(Alert.employee_id == incident.employee_id).order_by(Alert.created_at.asc()).all():
        events.append({
            "timestamp": alert.created_at.isoformat(),
            "type": "alert",
            "title": "Alert generated",
            "detail": alert.message,
            "severity": alert.severity,
            "status": alert.status,
        })

    for activity_event in [a for a in recent_activities(500) if a.get("employee_id") == employee.employee_id]:
        ts = activity_event.get("created_at") or activity_event.get("timestamp")
        if not ts:
            continue
        details = activity_event.get("details") or {}
        events.append({
            "timestamp": ts,
            "type": "activity",
            "title": f"{str(activity_event.get('event_type', 'activity')).replace('_', ' ').title()} detected",
            "detail": f"{activity_event.get('source', 'Activity source')} • {details}",
        })

    for anomaly in recent_anomalies(employee.employee_id, 200):
        ts = anomaly.get("created_at")
        if not ts:
            continue
        reasons = anomaly.get("reasons") or []
        events.append({
            "timestamp": ts,
            "type": "anomaly",
            "title": f"Behaviour analysis completed — score {anomaly.get('anomaly_score', 0)}/100",
            "detail": "; ".join(reasons) if reasons else "No deviation reason recorded.",
            "severity": anomaly.get("severity", "low"),
        })

    def sort_key(item):
        value = item.get("timestamp") or ""
        return value

    events = sorted(events, key=sort_key)
    return {
        "incident": {
            "id": incident.id,
            "employee_id": employee.employee_id,
            "employee_name": employee.name,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "created_at": incident.created_at.isoformat(),
        },
        "timeline": events,
    }


@app.patch("/api/incidents/{incident_id}")
def update_incident(incident_id: int, body: IncidentUpdate, user=Depends(current_user), db: Session = Depends(get_db)):
    i = db.get(Incident, incident_id)
    if not i:
        raise HTTPException(404, "Incident not found")
    if body.status:
        i.status = body.status
    if body.severity:
        i.severity = body.severity
    db.commit()
    audit(db, user["email"], "Updated incident", str(incident_id))
    return {"message": "Incident updated"}


@app.get("/api/activity")
def activity(user=Depends(current_user)):
    return recent_activities(50)


@app.post("/api/activity")
def add_activity(body: ActivityRequest, user=Depends(current_user), db: Session = Depends(get_db)):
    return perform_analysis(body, user, db)


@app.get("/api/intelligence/overview")
def intelligence_overview(user=Depends(current_user), db: Session = Depends(get_db)):
    anomalies = recent_anomalies(limit=500)
    counts: dict[str, int] = {}
    for a in anomalies:
        if a.get("is_anomaly"):
            counts[a.get("employee_id", "unknown")] = counts.get(a.get("employee_id", "unknown"), 0) + 1
    output = []
    for e in db.query(Employee).order_by(Employee.risk_score.desc()).all():
        baseline = get_baseline(e.employee_id) or default_baseline(e.employee_id, e.device_info or "Windows workstation")
        output.append({
            **employee_dict(e),
            "baseline_source": baseline.get("source", "default"),
            "baseline": baseline.get("indicators", {}),
            "anomaly_count": counts.get(e.employee_id, 0),
        })
    return output


@app.get("/api/intelligence/employee/{employee_id}")
def intelligence_employee(employee_id: str, user=Depends(current_user), db: Session = Depends(get_db)):
    e = resolve_employee(db, employee_id)
    return {
        "employee": employee_dict(e),
        "baseline": get_baseline(e.employee_id) or default_baseline(e.employee_id, e.device_info or "Windows workstation"),
        "activities": [a for a in recent_activities(200) if a.get("employee_id") == e.employee_id][:20],
        "anomalies": recent_anomalies(e.employee_id, 20),
    }


@app.post("/api/intelligence/learn/{employee_id}")
def learn_baseline(employee_id: str, user=Depends(current_user), db: Session = Depends(get_db)):
    e = resolve_employee(db, employee_id)
    activities = recent_activities(1000)
    baseline = build_baseline_from_activities(e.employee_id, e.device_info or "Windows workstation", activities)
    storage = save_baseline(e.employee_id, baseline)
    audit(db, user["email"], "Learned behavioural baseline", e.employee_id)
    return {"employee_id": e.employee_id, "baseline": baseline, "storage": storage["storage"]}


@app.post("/api/intelligence/simulate")
def simulate(body: SimulateRequest, user=Depends(current_user), db: Session = Depends(get_db)):
    scenarios = {
        "normal_login": {"event_type": "login", "source": "Mock SIEM", "details": {"time": "09:08", "new_device": False}},
        "after_hours_login": {"event_type": "login", "source": "Mock SIEM", "details": {"time": "02:14", "device": "NEW-LAPTOP-77", "new_device": True, "ip_unusual": True, "ip": "10.40.20.77"}},
        "mass_download": {"event_type": "file_download", "source": "Mock DLP", "details": {"files": 184, "size_mb": 850, "source_system": "SharePoint"}},
        "usb_exfiltration": {"event_type": "usb_connect", "source": "Mock Endpoint", "details": {"device": "USB-EXFIL-01", "after_hours": True}},
        "privilege_change": {"event_type": "privilege_change", "source": "Mock IAM", "details": {"old_level": "standard", "new_level": "admin", "new_privilege": True}},
        "external_email": {"event_type": "email_sent", "source": "Mock Email Security", "details": {"external_recipient": True, "attachments_mb": 150}},
    }
    if body.scenario not in scenarios:
        raise HTTPException(400, "Unknown scenario. Use normal_login, after_hours_login, mass_download, usb_exfiltration, privilege_change, or external_email.")
    payload = scenarios[body.scenario]
    request = ActivityRequest(employee_id=body.employee_id, **payload)
    return perform_analysis(request, user, db)


@app.get("/api/reports/risk")
def risk_report(user=Depends(current_user), db: Session = Depends(get_db)):
    rows = db.query(Employee.department, func.avg(Employee.risk_score).label("avg_risk"), func.count(Employee.id).label("employees")).group_by(Employee.department).order_by(func.avg(Employee.risk_score).desc()).all()
    return [{"department": d, "avg_risk": round(float(r), 1), "employees": n} for d, r, n in rows]


@app.get("/api/audit")
def audit_log(user=Depends(current_user), db: Session = Depends(get_db)):
    return [{"id": x.id, "actor": x.actor_email, "action": x.action, "target": x.target, "created_at": x.created_at.isoformat()} for x in db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(100).all()]
