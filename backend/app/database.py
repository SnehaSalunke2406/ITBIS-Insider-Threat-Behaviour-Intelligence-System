from urllib.parse import quote_plus
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from .config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, SQLITE_PATH, PREFER_POSTGRES


def postgres_url() -> str:
    return (
        f"postgresql+psycopg://{quote_plus(DB_USER)}:{quote_plus(DB_PASSWORD)}@"
        f"{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )


def build_engine():
    if PREFER_POSTGRES and DB_PASSWORD:
        try:
            e = create_engine(postgres_url(), pool_pre_ping=True, future=True)
            with e.connect() as c:
                c.execute(text("SELECT 1"))
            return e, "postgresql"
        except Exception:
            pass
    e = create_engine(f"sqlite:///{SQLITE_PATH}", connect_args={"check_same_thread": False}, future=True)
    return e, "sqlite"

engine, DB_MODE = build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
