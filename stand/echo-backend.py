#!/usr/bin/env python3
# Echo backend for the reference stand: returns the request body as text/plain.
#
# Зачем он вместо flask-приложения эталона: nginx стенда проксирует /check_server на
# flask-app:5000, пересылая телом строку "$ssl_cipher#$ssl_ciphers#$ssl_curves#$ssl_protocol",
# и матрице нужен только этот текст обратно. Родной flask-образ эталона (`server/flask`)
# при этом собирает ВТОРОЙ bee2evp+OpenSSL (~20 минут CI), который в отдаче текста не
# участвует, приложение в образ не копирует (авторы монтируют исходники томом), а
# requirements.txt пинит Flask 1.1.2, который Dockerfile игнорирует (`pip install flask`).
# Криптографическая часть эталона — контейнеры btls256/384/512, их мы не трогаем; бэкенд —
# отчётная обвязка, и её замена на эквивалент по контракту записана в PROCESS.md §4 и §5.
#
# ⚠ Ответ - сырой текст, не HTML: матрица ищет имя криптонабора дословно, и рендер
# страницы вокруг него ничего не добавил бы, кроме мест, где можно ошибиться.
import http.server


class Echo(http.server.BaseHTTPRequestHandler):
    def _echo(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # nginx шлёт метод клиента как есть: /check_server приходит и GET-ом (с телом,
    # которое ставит proxy_set_body), и POST-ом — отвечаем одинаково.
    do_GET = _echo
    do_POST = _echo

    def log_message(self, fmt: str, *args: object) -> None:
        # Штатный логгер пишет на stderr каждой строкой запроса; матрице это шум,
        # а причины отказов видны со стороны шлюза и nginx стенда.
        pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer(("0.0.0.0", 5000), Echo).serve_forever()
