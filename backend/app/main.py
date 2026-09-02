from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth, scans, scopes, users
from app.database import Base, SessionLocal, engine
from app.seed import seed_admin


@asynccontextmanager
async def lifespan(app: FastAPI):
    # На старте: создаём таблицы (в проде замени на Alembic-миграции) и сидим админа
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_admin(db)
    finally:
        db.close()
    yield


app = FastAPI(title="Network Scanner API", version="0.1.0", lifespan=lifespan)

# CORS для фронтенда (в проде укажи конкретный домен вместо *)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(scopes.router)
app.include_router(scans.router)


@app.get("/health", tags=["system"])
def health():
    return {"status": "ok"}
