# Insider Threat Behaviour Intelligence System

A student-scale security analytics application that learns normal employee activity patterns, scores behaviour drift, and creates explainable alerts/incidents for investigation.

## Windows quick start
1. Keep the folder extracted.
2. Double-click `START_ITBIS.bat`.
3. Open `http://localhost:8000`.
4. Login with `admin@ueba.com` / `admin123`.

Docker is not required for this Windows version. PostgreSQL is used when configured; otherwise the app falls back to a local SQLite database so the demo can start on a normal Windows machine. MongoDB is used when available and falls back to local JSON storage when it is not running.

## Core intelligence demo
Open **Behaviour Intelligence** and simulate:
- normal login
- after-hours + new device
- mass file download
- USB activity
- unexpected privilege change
- external email + large attachment

The engine compares the event with the employee baseline, produces an anomaly score and explanation, updates the employee risk score, and creates an alert/incident when thresholds are reached.

See `PROJECT_STATUS.md` for implemented features and the next improvements.
