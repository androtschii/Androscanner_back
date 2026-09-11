FROM python:3.12-slim

# Системные зависимости:
#   nmap                    — сам движок сканирования (без него воркер бесполезен)
#   libpango-1.0-0, ...     — WeasyPrint рендерит PDF через Pango и cairo
#   fonts-dejavu-core       — шрифт из шаблона отчёта; без него кириллица
#                             в PDF превратится в квадраты
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# ВНИМАНИЕ: здесь стоял `setcap ...+eip` на nmap, и он ЛОМАЛ образ.
#
# Effective-права на файле требуют, чтобы контейнер мог их выдать. CAP_NET_ADMIN
# в наборе Docker по умолчанию отсутствует, поэтому execve падал с EPERM
# ещё до запуска программы:
#
#     exec /usr/bin/nmap: operation not permitted
#
# То есть nmap становился незапускаемым вообще — включая контейнер api,
# где /health проверяет его наличие. Поймано в CI шагом «nmap внутри образа».
#
# Права nmap получает от процесса: контейнер работает от root, а воркеру
# docker-compose выдаёт cap_add NET_RAW и NET_ADMIN. setcap понадобился бы
# только при запуске от непривилегированного пользователя, чего здесь нет.

WORKDIR /code

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
