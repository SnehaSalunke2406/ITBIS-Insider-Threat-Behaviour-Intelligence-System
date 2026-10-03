from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(512), nullable=False)
    role = Column(String(60), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class Employee(Base):
    __tablename__ = "employees"
    id = Column(Integer, primary_key=True)
    employee_id = Column(String(50), unique=True, nullable=False)
    name = Column(String(120), nullable=False)
    department = Column(String(120), nullable=False)
    designation = Column(String(120), nullable=False)
    manager_id = Column(Integer, ForeignKey("employees.id"), nullable=True)
    device_info = Column(String(255), default="Windows workstation")
    access_privileges = Column(String(500), default="Standard")
    risk_score = Column(Float, default=0.0)
    manager = relationship("Employee", remote_side=[id], backref="reports")

class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True)
    employee_id = Column(Integer, ForeignKey("employees.id"), nullable=False)
    status = Column(String(30), default="open", nullable=False)
    severity = Column(String(30), default="medium", nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    employee_id = Column(Integer, ForeignKey("employees.id"), nullable=False)
    severity = Column(String(30), default="medium", nullable=False)
    message = Column(String(500), nullable=False)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    status = Column(String(30), default="open", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(Integer, primary_key=True)
    actor_email = Column(String(255), nullable=False)
    action = Column(String(255), nullable=False)
    target = Column(String(255), default="")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
