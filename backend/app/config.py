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

    # Redis / Celery
    redis_url: str = "redis://redis:6379/0"

    # true  — сканы уходят в Celery (prod, Docker: есть Redis и Linux)
    # false — выполняются через FastAPI BackgroundTasks (dev на Windows:
    #         нативного Redis нет, Celery Windows официально не поддерживает)
    use_celery: bool = False

    # Путь к nmap. Пусто = искать в PATH (так на Linux/в Docker).
    # На Windows nmap ставится в Program Files и в PATH не попадает.
    nmap_path: str = ""

    # CORS — домены фронтенда, которым разрешены запросы к API
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Уведомления в Telegram. Пусто = уведомления выключены — отсутствие
    # бота не должно быть обязательным условием для работы сканера.
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""


settings = Settings()
