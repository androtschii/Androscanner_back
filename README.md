# Network Scanner — Backend (Фазы 0–1)

Каркас бэкенда сетевого сканера: FastAPI + PostgreSQL + JWT + RBAC (3 роли).
Это результат дней 1–5 из плана. Движок сканирования и фронтенд — следующие фазы.

## Что уже работает

- Авторизация по JWT (`/auth/login`)
- Три роли: **admin**, **analyst**, **viewer** с разграничением прав
- Управление пользователями (admin)
- Allowed scope — разрешённые для скана диапазоны (admin)
- Создание/просмотр/удаление сканов с **проверкой scope** (скан вне диапазона → 403)
- Audit-log всех действий
- Автосоздание админа при первом запуске
- Swagger-документация на `/docs`

## Матрица прав

| Действие | admin | analyst | viewer |
|---|:---:|:---:|:---:|
| Управление пользователями | ✅ | ❌ | ❌ |
| Настройка scope | ✅ | ❌ | ❌ |
| Запуск скана | ✅ | ✅ | ❌ |
| Удаление скана | ✅ | ❌ | ❌ |
| Просмотр сканов | ✅ | ✅ | ✅ |

## Запуск через Docker (рекомендуется)

```bash
docker compose up --build
```

- API: http://localhost:8000
- Swagger: http://localhost:8000/docs
- Дефолтный вход: `admin` / `admin` — **смени пароль сразу!**

## Запуск локально без Docker

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
# для локального запуска можно использовать SQLite:
export DATABASE_URL="sqlite+pysqlite:///./scanner.db"
uvicorn app.main:app --reload
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
```

## Структура

```
backend/app/
├── main.py         # сборка приложения, старт, сидер
├── config.py       # настройки (.env)
├── database.py     # подключение к БД
├── models/         # User, Scan, AllowedScope, AuditLog
├── schemas/        # Pydantic-схемы
├── auth/           # JWT + RBAC (security.py, deps.py)
└── api/            # роуты: auth, users, scopes, scans
```

## Заметки

- Warning `error reading bcrypt version` в логах — безобидная несовместимость версий
  passlib/bcrypt, на работу не влияет. Можно игнорировать.
- В проде: замени `create_all` на Alembic-миграции, укажи реальный `JWT_SECRET`,
  ограничь CORS конкретным доменом.

## Следующие шаги (по плану)

- **Фаза 2 (дни 6–9):** движок nmap/scapy в `app/scanner/`
- **Фаза 3 (дни 10–12):** Celery-задача `run_scan.delay(scan.id)` — заглушка отмечена в `api/scans.py`
- **Фаза 4 (дни 13–16):** React-фронтенд
