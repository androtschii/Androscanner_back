from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database
    database_url: str = "postgresql+psycopg://scanner:scanner@db:5432/scanner"

    # JWT — обязателен, дефолта нет намеренно: слабый секрет в проде хуже,
    # чем приложение, которое не стартует без .env
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Default admin (создаётся при первом запуске)
    default_admin_username: str = "admin"
    default_admin_password: str = "admin"  # смени после первого входа!

    # Redis (для Celery в следующих фазах)
    redis_url: str = "redis://redis:6379/0"

    # CORS — домены фронтенда, которым разрешены запросы к API
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]


settings = Settings()
