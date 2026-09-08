FROM python:3.12-slim

# Системные зависимости:
#   nmap                    — сам движок сканирования (без него воркер бесполезен)
#   libcap2-bin             — setcap, чтобы nmap мог raw-сокеты без полного root
#   libpango-1.0-0, ...     — WeasyPrint рендерит PDF через Pango и cairo
#   fonts-dejavu-core       — шрифт из шаблона отчёта; без него кириллица
#                             в PDF превратится в квадраты
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        libcap2-bin \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libcairo2 \
        libgdk-pixbuf-2.0-0 \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# Позволяет nmap делать SYN-скан и ARP без запуска всего процесса от root.
# Контейнеру всё равно нужен cap_add: NET_RAW/NET_ADMIN в docker-compose.
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/lib/nmap/nmap \
    || setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap \
    || true

WORKDIR /code

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
