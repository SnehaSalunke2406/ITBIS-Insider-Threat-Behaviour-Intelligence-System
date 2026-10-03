# Verification checklist

- Python syntax checked with `py_compile`.
- Frontend JavaScript uses browser-native APIs only.
- Startup path uses Python 3.12 if installed at the standard Windows location.
- SQLAlchemy has a zero-Docker SQLite fallback for a reliable local demo.
- PostgreSQL support uses separate DB_* variables, so passwords containing `@` do not corrupt the host name.
- MongoDB connectivity is optional at startup and health status is visible via `/api/health`.

A full Windows/PostgreSQL/MongoDB live integration cannot be certified from this build environment because it does not provide the user's Windows services or Docker Desktop engine.
