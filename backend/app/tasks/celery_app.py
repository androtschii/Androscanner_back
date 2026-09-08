"""Celery-приложение.

Здесь только конфигурация брокера — задачи объявлены в runner.py и
подключаются через include, чтобы не было циклического импорта.

Запуск воркера:
    Linux/Docker:  celery -A app.tasks.celery_app worker --loglevel=info
    Windows (dev): celery -A app.tasks.celery_app worker --loglevel=info --pool=solo

--pool=solo обязателен на Windows: Celery официально не поддерживает
Windows с версии 4, форк-пул там не работает.
"""

from celery import Celery

from app.config import settings

celery_app = Celery(
    "androscanner",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.tasks.runner"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    # Скан — операция долгая: full по /24 идёт десятки минут
    task_time_limit=3600,
    task_soft_time_limit=3300,
    task_track_started=True,
    # Не набирать пачку задач на воркер: сканы тяжёлые, лучше по одной
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)
