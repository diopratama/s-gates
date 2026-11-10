from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

database_url = make_url(settings.DATABASE_URL)
if database_url.drivername == "postgresql":
    # SQLAlchemy 2.1 defaults postgresql:// to psycopg (v3), while this
    # project installs psycopg2-binary. Select the installed driver explicitly.
    database_url = database_url.set(drivername="postgresql+psycopg2")

engine = create_engine(
    database_url,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
