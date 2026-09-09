import os
import tempfile

# Переменные окружения должны быть выставлены ДО первого импорта app.config —
# Settings() создаётся один раз при импорте модуля и дальше не меняется.

# TEST_DATABASE_URL позволяет прогнать тот же набор тестов на PostgreSQL.
# По умолчанию — SQLite во временном файле: локально не нужно поднимать базу.
# В CI прогоняются обе, потому что они расходятся в поведении: именно так
# был найден баг с часовыми поясами (SQLite терял зону, PostgreSQL — нет).
_default_db = "sqlite+pysqlite:///" + os.path.join(
    tempfile.mkdtemp(prefix="androscanner-test-"), "test.db"
).replace("\\", "/")

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", _default_db)
os.environ["JWT_SECRET"] = "test-secret-only-for-pytest-not-for-production"
os.environ["DEFAULT_ADMIN_USERNAME"] = "admin"
os.environ["DEFAULT_ADMIN_PASSWORD"] = "admin"

import pytest
from fastapi.testclient import TestClient

from app.main import app


def pytest_report_header(config):
    """Показываем в шапке отчёта, на какой базе идёт прогон —
    иначе непонятно, что именно проверено."""
    url = os.environ["DATABASE_URL"]
    backend = "PostgreSQL" if url.startswith("postgresql") else "SQLite"
    return f"база данных: {backend}"


@pytest.fixture(scope="session")
def client():
    """Один клиент на всю сессию: lifespan прогоняет реальные alembic-миграции
    и сидер admin один раз."""
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def admin_headers(client):
    r = client.post("/auth/login", data={"username": "admin", "password": "admin"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session", autouse=True)
def home_scope(client, admin_headers):
    """Единственный разрешённый диапазон для всех тестов сессии."""
    r = client.post(
        "/scopes",
        headers=admin_headers,
        json={"cidr": "192.168.1.0/24", "description": "test home network"},
    )
    assert r.status_code == 200


@pytest.fixture(scope="session")
def viewer_headers(client, admin_headers):
    client.post(
        "/users",
        headers=admin_headers,
        json={"username": "test_viewer", "password": "viewerpass123", "role": "viewer"},
    )
    r = client.post("/auth/login", data={"username": "test_viewer", "password": "viewerpass123"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}
