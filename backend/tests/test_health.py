"""Тесты проверки работоспособности.

Раньше /health отвечал «ok», не проверяя ничего. Такой ответ вреднее
отсутствия проверки: оркестратор считает контейнер живым, а он не может
достучаться до базы.
"""

from unittest.mock import patch


def test_health_is_public(client):
    """Проверка должна работать без токена — иначе оркестратор
    не сможет ей воспользоваться."""
    assert client.get("/health").status_code == 200


def test_health_reports_each_dependency(client):
    checks = client.get("/health").json()["checks"]
    assert set(checks) == {"database", "redis", "nmap"}
    for name, check in checks.items():
        assert "ok" in check, f"{name} без признака ok"
        assert "detail" in check, f"{name} без пояснения"


def test_healthy_when_database_reachable(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["checks"]["database"]["ok"] is True


def test_returns_503_when_database_is_down(client):
    """Главное свойство: недоступная база должна давать 503, а не 200."""
    with patch("app.api.health._check_database", return_value=(False, "недоступна: OperationalError")):
        r = client.get("/health")

    assert r.status_code == 503
    assert r.json()["status"] == "degraded"
    assert r.json()["checks"]["database"]["ok"] is False


def test_returns_503_when_redis_is_down(client):
    with patch("app.api.health._check_redis", return_value=(False, "недоступен: ConnectionError")):
        r = client.get("/health")

    assert r.status_code == 503
    assert r.json()["checks"]["redis"]["ok"] is False


def test_redis_not_checked_when_celery_disabled(client):
    """Без Celery Redis не нужен — не стоит считать сервис больным
    из-за отсутствия того, чем он не пользуется."""
    checks = client.get("/health").json()["checks"]
    assert checks["redis"]["ok"] is True
    assert "не используется" in checks["redis"]["detail"]


def test_missing_nmap_does_not_make_service_unhealthy(client):
    """Без nmap нельзя запускать новые сканы, но всё уже собранное
    остаётся доступным — это предупреждение, а не отказ."""
    with patch("app.api.health._check_nmap", return_value=(False, "не найден: PortScannerError")):
        r = client.get("/health")

    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["checks"]["nmap"]["ok"] is False
    assert r.json()["checks"]["nmap"]["critical"] is False


def test_health_response_is_not_cached(client):
    """Закэшированная проверка здоровья бесполезна."""
    assert client.get("/health").headers["Cache-Control"] == "no-store"
