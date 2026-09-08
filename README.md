# Network Scanner — Backend (Фаза 1.5)

Каркас бэкенда сетевого сканера: FastAPI + PostgreSQL + JWT + RBAC (3 роли).
Движок сканирования и фронтенд — следующие фазы.

## Что уже работает

- Авторизация по JWT (`/auth/login`)
- Три роли: **admin**, **analyst**, **viewer** с разграничением прав
- Управление пользователями (admin)
- Allowed scope — разрешённые для скана диапазоны (admin)
- Создание/просмотр/удаление сканов с **проверкой scope** (скан вне диапазона → 403),
  единая точка допуска — `app/security/scope.py::assert_in_scope()`
- Audit-log всех действий + эндпоинт `GET /audit` (только admin)
- Автосоздание админа при первом запуске
- Миграции схемы через **Alembic** (накатываются автоматически при старте)
- Swagger-документация на `/docs`

## Матрица прав

| Действие | admin | analyst | viewer |
|---|:---:|:---:|:---:|
| Управление пользователями | ✅ | ❌ | ❌ |
| Настройка scope | ✅ | ❌ | ❌ |
| Запуск скана | ✅ | ✅ | ❌ |
| Удаление скана | ✅ | ❌ | ❌ |
| Просмотр сканов | ✅ | ✅ | ✅ |
| Просмотр audit-log | ✅ | ❌ | ❌ |

## Запуск локально на Windows (проверено)

Nmap/scapy пока не задействованы, поэтому для Фазы 1.5 админ-прав и WSL не требуется —
всё работает на нативном Python и SQLite.

```powershell
winget install --id Python.Python.3.12 --scope user
```

```bash
cd backend
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
cp .env.example .env
# в .env поменяй JWT_SECRET на свой:
#   .venv/Scripts/python.exe -c "import secrets;print(secrets.token_hex(32))"
# и укажи DATABASE_URL=sqlite+pysqlite:///./scanner.db
.venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

- API: http://127.0.0.1:8000
- Swagger: http://127.0.0.1:8000/docs
- Дефолтный вход: `admin` / `admin` — **смени пароль сразу!**

## Запуск через Docker (для прод-стека с Postgres/Redis)

```bash
cp backend/.env.example backend/.env   # поменять JWT_SECRET!
docker compose up --build
```

## Тесты

```bash
cd backend
.venv/Scripts/python.exe -m pip install -r requirements-dev.txt
.venv/Scripts/python.exe -m pytest -v
```

Тесты гоняются на изолированной временной SQLite-базе (см. `tests/conftest.py`) через
реальные alembic-миграции — не на dev-базе `scanner.db`.

## Миграции (Alembic)

Накатываются автоматически при старте приложения (`app/main.py::run_migrations`).
Ручные команды:

```bash
cd backend
.venv/Scripts/python.exe -m alembic revision --autogenerate -m "описание изменения"
.venv/Scripts/python.exe -m alembic upgrade head
```

## Быстрая проверка (curl)

```bash
# вход
TOKEN=$(curl -s -X POST localhost:8000/auth/login \
  -d "username=admin&password=admin" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

# добавить свой диапазон
curl -X POST localhost:8000/scopes -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"cidr":"192.168.1.0/24","description":"home"}'

# запустить скан (в пределах scope)
curl -X POST localhost:8000/scans -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"target":"192.168.1.10","profile":"quick"}'

# журнал действий (только admin)
curl localhost:8000/audit -H "Authorization: Bearer $TOKEN"
```

## Структура

```
backend/
├── alembic/          # миграции схемы БД
├── app/
│   ├── main.py        # сборка приложения, миграции при старте, сидер
│   ├── config.py      # настройки (.env)
│   ├── database.py    # подключение к БД
│   ├── models/        # User, Scan, AllowedScope, AuditLog
│   ├── schemas/       # Pydantic-схемы
│   ├── auth/          # JWT + RBAC (security.py, deps.py)
│   ├── security/      # scope.py — единая точка допуска к сканированию
│   ├── scanner/       # движок: profiles, engine, parser, arp, privileges
│   ├── tasks/         # celery_app, runner (тело задачи + диспетчер)
│   └── api/           # роуты: auth, users, scopes, scans, audit
└── tests/             # pytest: scope, RBAC, движок, задачи
```

## Профили сканирования

| Профиль | Аргументы nmap | Права админа | Что делает |
|---|---|:---:|---|
| `discovery` | `-sn -PR` | **нужны** | ARP-поиск живых хостов в своём сегменте |
| `quick` | `-sT -T4 --top-ports 100` | не нужны | TCP connect-скан 100 популярных портов |
| `full` | `-sS -sV -O -T4 -p-` | **нужны** | SYN-скан всех портов + сервисы + ОС |

`quick` работает без прав не потому, что «ослаблен» — connect-скан это
отдельный тип сканирования, ему raw-сокеты не нужны в принципе.

Если профилю нужны права, а их нет, скан помечается `failed` с объяснением.
Молчаливой подмены профиля на более слабый **нет** — это скрыло бы от вас,
что скан на самом деле увидел меньше, чем вы просили.

## Фоновое выполнение

Тело задачи (`app/tasks/runner.py::execute_scan`) от способа запуска не зависит.
Выбирает диспетчер по настройке `USE_CELERY`:

| `USE_CELERY` | Как выполняется | Когда |
|---|---|---|
| `false` | FastAPI BackgroundTasks, прямо в процессе API | dev на Windows |
| `true` | `run_scan.delay(scan_id)` через Redis | prod, Docker |

Второй режим по умолчанию выключен: нативного Redis под Windows не существует,
а Celery официально не поддерживает Windows с версии 4.

### Запуск воркера

```bash
# Linux / Docker
celery -A app.tasks.celery_app worker --loglevel=info --concurrency=2

# Windows
celery -A app.tasks.celery_app worker --loglevel=info --pool=solo
```

`--pool=solo` на Windows обязателен: форк-пул там не работает.

### Redis на Windows

Официальных сборок Redis под Windows нет. Рабочий вариант —
[Memurai](https://www.memurai.com/) (Redis-совместимый сервер, есть бесплатная
Developer Edition):

```powershell
winget install --id Memurai.MemuraiDeveloper
```

Ставится как служба Windows и сразу слушает `127.0.0.1:6379`, перезагрузка
не нужна. Отвечает как Redis 7.2.

Полная связка для локальной проверки — три процесса:

```powershell
# 1) Memurai уже работает службой, проверить:  redis-cli ping

# 2) воркер
$env:PYTHONIOENCODING="utf-8"
.\.venv\Scripts\python.exe -m celery -A app.tasks.celery_app worker --loglevel=info --pool=solo

# 3) API с включённой очередью
$env:USE_CELERY="true"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## Запуск через Docker

```bash
docker compose up --build
```

Поднимет `db`, `redis`, `api` и `worker`. Воркер работает в host-сети —
иначе он сидел бы в своей подсети и ARP-discovery не видел бы вашу локалку.
Из-за этого он обращается к Postgres и Redis по `127.0.0.1`, а не по именам
сервисов: в host-режиме внутренний DNS Docker недоступен.

## Заметки

- `JWT_SECRET` обязателен — без него приложение не стартует
  (сознательно: слабый дефолт в проде хуже, чем явная ошибка запуска).
- CORS ограничен списком `cors_origins` в `.env` (по умолчанию — Vite dev-сервер
  `localhost:5173`), не `*`.
- Warning `error reading bcrypt version` не появляется — bcrypt зафиксирован
  на версии `4.0.1`, совместимой с passlib `1.7.4`.
- На Windows nmap не попадает в `PATH` — путь задаётся через `NMAP_PATH`.

## Следующие шаги (по плану)

- **Фаза 4:** страница деталей скана, дашборд с графиками, админка
- **Фаза 5:** аналитика, diff между сканами, граф сети, PDF-отчёты
- **Фаза 6:** hardening, документация, деплой
