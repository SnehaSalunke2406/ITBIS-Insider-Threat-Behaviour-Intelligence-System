# Local Windows deployment

## Zero-Docker demo
Use `START_ITBIS.bat`. It prefers Python 3.12 and starts the FastAPI app.

## PostgreSQL
Create a database named `itbis` in pgAdmin. Edit `.env` and set `DB_USER`, `DB_PASSWORD`, `DB_HOST`, and `DB_PORT`. Keep `PREFER_POSTGRES=true`. A password containing `@` is safe because the application encodes the username/password separately.

## MongoDB
Start MongoDB locally on port 27017. The dashboard will then store POSTed activity events in the `activity_logs` collection and `/api/health` will show MongoDB connected.
