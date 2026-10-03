# ITBIS Project Status

## Exact project title
**Insider Threat Behaviour Intelligence System**

## What is implemented
- FastAPI backend and browser dashboard
- Login/JWT authentication
- PostgreSQL support with SQLite fallback for Windows demonstration
- MongoDB support for `activity_logs`, `behavioral_baselines`, and `anomaly_results`
- Employee, alert, incident, report, and audit views
- Mock activity feed, as allowed by the internship guide
- Behavioural baseline creation from historical activity
- Explainable anomaly scoring using working-hours, device, download-volume, USB, privilege-change, external-email, and unusual-IP signals
- Automatic employee risk-score update
- Automatic medium+ alerts and high/critical incidents
- Behaviour Intelligence page with scenario simulation
- Baseline-learning action per employee

## Still optional / next improvements
1. Fine-grained role permissions for all pages and endpoints.
2. More historical data so baselines become more realistic.
3. A statistical/ML detector (for example Isolation Forest) after the rule-based engine is stable.
4. Real security connectors (AD, EDR, DLP, SIEM). These are **not required for the student project guide**, which explicitly permits mock log data.

## Recommended demo flow
1. Login as `admin@ueba.com` / `admin123`.
2. Open **Behaviour Intelligence**.
3. Select `EMP1004`.
4. Run **After-hours + new device**.
5. Show the anomaly score, reasons, new alert, and incident.
6. Open **Alerts** and **Incidents** to show the workflow.
7. Open **Activity Logs** to show the event stored.
8. Open **Risk Reports** to show the employee/department risk change.
