"""Security-заголовки для всех ответов API.

Это API, а не сайт: HTML он почти не отдаёт, поэтому набор узкий и по делу.
Заголовки, осмысленные только для страниц с разметкой, здесь были бы шумом.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

HEADERS = {
    # Браузер не должен угадывать тип: PDF-отчёт с чужим Content-Type
    # мог бы быть истолкован как HTML и выполнен
    "X-Content-Type-Options": "nosniff",
    # API не предназначен для встраивания во фрейм
    "X-Frame-Options": "DENY",
    # Не утекать адрес панели на сторонние ресурсы
    "Referrer-Policy": "no-referrer",
    # Ответы содержат данные о твоей сети — не кэшировать нигде
    "Cache-Control": "no-store",
}

# Строгий CSP: API не рисует страниц, поэтому запрещаем всё
API_CSP = "default-src 'none'; frame-ancestors 'none'"

# Swagger и ReDoc — единственные страницы с разметкой. Им нужны скрипты
# и стили с CDN, под общий запрет они не подходят.
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        for name, value in HEADERS.items():
            response.headers.setdefault(name, value)

        if not request.url.path.startswith(DOCS_PATHS):
            response.headers.setdefault("Content-Security-Policy", API_CSP)

        return response
