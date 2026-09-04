from contextlib import asynccontextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import audit, auth, scans, scopes, users
from app.config import settings
from app.database import SessionLocal
from app.seed import seed_admin

BASE_DIR = Path(__file__).resolve().parent.parent


def run_migrations() -> None:
    """Накатывает миграции Alembic до последней версии (замена Base.metadata.create_all)."""
    cfg = Config(str(BASE_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BASE_DIR / "alembic"))
    command.upgrade(cfg, "head")


@asynccontextmanager
async def lifespan(app: FastAPI):
    run_migrations()
    db = SessionLocal()
    try:
        seed_admin(db)
    finally:
        db.close()
    yield


app = FastAPI(title="Network Scanner API", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(scopes.router)
app.include_router(scans.router)
app.include_router(audit.router)


@app.get("/health", tags=["system"])
def health():
    return {"status": "ok"}
