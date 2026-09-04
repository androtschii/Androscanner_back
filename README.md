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
├── alembic/         # миграции схемы БД
├── app/
│   ├── main.py       # сборка приложения, миграции при старте, сидер
│   ├── config.py     # настройки (.env)
│   ├── database.py   # подключение к БД
│   ├── models/        # User, Scan, AllowedScope, AuditLog
│   ├── schemas/        # Pydantic-схемы
│   ├── auth/           # JWT + RBAC (security.py, deps.py)
│   ├── security/        # scope.py — единая точка допуска к сканированию
│   └── api/              # роуты: auth, users, scopes, scans, audit
└── tests/            # pytest: allowed-scope, RBAC
```

## Заметки

- `JWT_SECRET` теперь обязателен — без него приложение не стартует
  (сознательно: слабый дефолт в проде хуже, чем явная ошибка запуска).
- CORS ограничен списком `cors_origins` в `.env` (по умолчанию — Vite dev-сервер
  `localhost:5173`), не `*`.
- Warning `error reading bcrypt version` больше не появляется — bcrypt зафиксирован
  на версии `4.0.1`, совместимой с passlib `1.7.4`.

## Следующие шаги (по плану)

- **Фаза 2:** движок nmap/scapy в `app/scanner/`
- **Фаза 3:** Celery-задача `run_scan.delay(scan.id)` — заглушка отмечена в `api/scans.py`
- **Фаза 4:** React-фронтенд
