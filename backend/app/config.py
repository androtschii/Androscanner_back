from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database
    database_url: str = "postgresql+psycopg://scanner:scanner@db:5432/scanner"

    # JWT
    jwt_secret: str = "CHANGE_ME_IN_PRODUCTION"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    # Default admin (создаётся при первом запуске)
    default_admin_username: str = "admin"
    default_admin_password: str = "admin"  # смени после первого входа!

    # Redis (для Celery в следующих фазах)
    redis_url: str = "redis://redis:6379/0"


settings = Settings()
