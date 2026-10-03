from __future__ import annotations

from datetime import datetime, timezone
from statistics import mean
from typing import Any

DEFAULT_WORKING_START = 9 * 60
DEFAULT_WORKING_END = 18 * 60


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _minutes(value: Any) -> int | None:
    if value is None:
        return None
    text = str(value).strip()
    if ":" not in text:
        return None
    try:
        hour, minute = text.split(":", 1)
        h, m = int(hour), int(minute)
        if 0 <= h <= 23 and 0 <= m <= 59:
            return h * 60 + m
    except (TypeError, ValueError):
        return None
    return None


def default_baseline(employee_id: str, device_info: str = "Windows workstation") -> dict[str, Any]:
    return {
        "employee_id": employee_id,
        "indicators": {
            "working_hours": {"start": "09:00", "end": "18:00"},
            "avg_login_time": "09:00-09:30",
            "avg_download_files": 35,
            "avg_download_mb": 250,
            "known_devices": [device_info],
            "typical_event_frequency_per_day": 20,
        },
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "source": "demo baseline",
    }


def _working_window(baseline: dict[str, Any]) -> tuple[int, int]:
    indicators = baseline.get("indicators", {})
    working = indicators.get("working_hours", {})
    start = _minutes(working.get("start")) or DEFAULT_WORKING_START
    end = _minutes(working.get("end")) or DEFAULT_WORKING_END
    return start, end


def build_baseline_from_activities(employee_id: str, device_info: str, activities: list[dict[str, Any]]) -> dict[str, Any]:
    base = default_baseline(employee_id, device_info)
    login_minutes: list[int] = []
    downloads: list[float] = []
    download_mb: list[float] = []
    devices = {device_info}
    for item in activities:
        if item.get("employee_id") != employee_id:
            continue
        details = item.get("details") or {}
        event_type = str(item.get("event_type", "")).lower()
        if event_type == "login":
            m = _minutes(details.get("time") or details.get("login_time"))
            if m is not None:
                login_minutes.append(m)
            if details.get("device"):
                devices.add(str(details["device"]))
        elif event_type == "file_download":
            if details.get("files") is not None:
                downloads.append(_num(details.get("files")))
            if details.get("size_mb") is not None:
                download_mb.append(_num(details.get("size_mb")))
    indicators = base["indicators"]
    if login_minutes:
        avg = round(mean(login_minutes))
        indicators["avg_login_time"] = f"{avg // 60:02d}:{avg % 60:02d}"
        indicators["working_hours"] = {
            "start": f"{max(0, (min(login_minutes) - 30)) // 60:02d}:{max(0, (min(login_minutes) - 30)) % 60:02d}",
            "end": "18:00",
        }
    if downloads:
        indicators["avg_download_files"] = round(mean(downloads), 1)
    if download_mb:
        indicators["avg_download_mb"] = round(mean(download_mb), 1)
    indicators["known_devices"] = sorted(devices)
    base["last_updated"] = datetime.now(timezone.utc).isoformat()
    base["source"] = "learned from activity history"
    return base


def analyze_activity(activity: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    event_type = str(activity.get("event_type", "unknown")).lower()
    details = activity.get("details") or {}
    score = 0
    reasons: list[str] = []
    deviations: list[dict[str, Any]] = []
    start, end = _working_window(baseline)
    indicators = baseline.get("indicators", {})

    event_time = details.get("time") or details.get("login_time")
    minutes = _minutes(event_time)
    after_hours = bool(details.get("after_hours"))
    if minutes is not None:
        after_hours = minutes < start or minutes > end
    if after_hours:
        score += 35 if event_type == "login" else 20
        reasons.append("Activity occurred outside the employee's normal working window")
        deviations.append({"indicator": "working_hours", "observed": event_time, "baseline": f"{start // 60:02d}:{start % 60:02d}-{end // 60:02d}:{end % 60:02d}"})

    if bool(details.get("new_device")):
        score += 25
        reasons.append("A device not seen in the normal baseline was used")
        deviations.append({"indicator": "device", "observed": details.get("device", "new device"), "baseline": indicators.get("known_devices", [])})
    elif details.get("device") and str(details["device"]) not in [str(x) for x in indicators.get("known_devices", [])]:
        score += 20
        reasons.append("Device differs from known devices in the baseline")
        deviations.append({"indicator": "device", "observed": details.get("device"), "baseline": indicators.get("known_devices", [])})

    avg_files = max(1.0, _num(indicators.get("avg_download_files"), 35))
    if event_type == "file_download" and details.get("files") is not None:
        files = _num(details.get("files"))
        multiplier = files / avg_files
        if multiplier >= 4:
            score += 35
            reasons.append(f"File download volume is {multiplier:.1f}× above the learned baseline")
        elif multiplier >= 2:
            score += 25
            reasons.append(f"File download volume is {multiplier:.1f}× above the learned baseline")
        if multiplier >= 2:
            deviations.append({"indicator": "download_volume", "observed_files": files, "baseline_files": avg_files})

    avg_mb = max(10.0, _num(indicators.get("avg_download_mb"), 250))
    if event_type == "file_download" and details.get("size_mb") is not None:
        size_mb = _num(details.get("size_mb"))
        if size_mb >= avg_mb * 3:
            score += 25
            reasons.append("Downloaded data volume is significantly above the employee baseline")
            deviations.append({"indicator": "download_size_mb", "observed": size_mb, "baseline": avg_mb})
        elif size_mb >= avg_mb * 2:
            score += 15
            reasons.append("Downloaded data volume is above the employee baseline")

    if event_type in {"privilege_change", "privilege_escalation"} or details.get("privilege_change") or details.get("new_privilege"):
        score += 45
        reasons.append("Privilege level changed unexpectedly")
        deviations.append({"indicator": "privileges", "observed": details.get("new_level") or details.get("new_privilege"), "baseline": "standard/approved role access"})

    if event_type == "usb_connect":
        score += 10
        if after_hours:
            score += 20
            reasons.append("USB activity occurred outside normal working hours")
        else:
            reasons.append("USB device connection requires monitoring")
        deviations.append({"indicator": "usb_activity", "observed": details.get("device", "USB device"), "baseline": "approved removable media only"})

    if event_type == "email_sent" and details.get("external_recipient"):
        score += 15
        reasons.append("Email was sent to an external recipient")
        deviations.append({"indicator": "external_email", "observed": True, "baseline": False})
        if _num(details.get("attachments_mb")) >= 100:
            score += 15
            reasons.append("Large attachment sent to an external recipient")

    if details.get("ip_unusual"):
        score += 15
        reasons.append("Source IP is unusual for this employee")
        deviations.append({"indicator": "source_ip", "observed": details.get("ip"), "baseline": "known office/network ranges"})

    score = min(100, int(score))
    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    else:
        severity = "low"
    if not reasons:
        reasons.append("No strong deviation from the current behavioural baseline was detected")

    return {
        "anomaly_score": score,
        "severity": severity,
        "is_anomaly": score >= 30,
        "reasons": reasons,
        "deviations": deviations,
        "recommendation": "Investigate and correlate related events" if score >= 60 else "Continue monitoring",
    }
