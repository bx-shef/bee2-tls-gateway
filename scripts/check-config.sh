#!/usr/bin/env bash
# Проверки конфигурации шлюза — та часть, которая является чистым текстом и потому
# проверяема без Docker, OpenSSL и банка.
#
# ЗАЧЕМ. `nginx.conf.template` рендерится в `entrypoint.sh` через `envsubst` с ЯВНЫМ списком
# переменных. Этот список — рукописная копия плейсхолдеров шаблона, и ничто не заставляет их
# совпадать: `envsubst` молча оставит не перечисленный `${GW_NEW}` в выводе как обычный текст,
# и ошибка вылезет падением `nginx -t` НА СТАРТЕ КОНТЕЙНЕРА — на сервере, во время выката, —
# а не в pull request. Остальное про образ стерегут гейты внутри Dockerfile; эта щель
# проверяется здесь, поэтому здесь и проверяется.
#
# ⚠ Каждая проверка ниже держит инвариант, названный в README: список путей — единственная
# граница безопасности, лог не несёт пути (в пути ездит номер счёта), проверка апстрима
# включена, forward secrecy предпочтительнее переноса ключа.
set -euo pipefail

cd "$(dirname "$0")/.."

TEMPLATE=nginx.conf.template
ENTRYPOINT=entrypoint.sh

for f in "$TEMPLATE" "$ENTRYPOINT"; do
  [ -r "$f" ] || { echo "FAIL нет файла $f" >&2; exit 1; }
done

TEMPLATE="$TEMPLATE" ENTRYPOINT="$ENTRYPOINT" python3 - <<'PY'
import os
import re
import sys

template = open(os.environ["TEMPLATE"], encoding="utf-8").read()
entrypoint = open(os.environ["ENTRYPOINT"], encoding="utf-8").read()

failures = []


def check(name, ok, detail=""):
    if ok:
        print(f"ok   {name}")
    else:
        print(f"FAIL {name}: {detail}", file=sys.stderr)
        failures.append(name)


# Плейсхолдеры, которые шаблон ждёт от envsubst.
placeholders = set(re.findall(r"\$\{(GW_[A-Z0-9_]+)\}", template))

# Список, реально переданный в envsubst — аргумент SHELL-FORMAT этого вызова.
call = re.search(r"envsubst\s+'([^']+)'", entrypoint)
if not call:
    print("FAIL entrypoint.sh: вызов envsubst с кавычным списком не найден", file=sys.stderr)
    sys.exit(1)
# ⚠ Имена ловим ЛЮБЫЕ, а не только ПРОПИСНЫЕ, и обе формы — `${NAME}` и `$NAME`
#   (envsubst принимает обе). Прежняя регулярка `\$\{([A-Z0-9_]+)\}` пропускала ровно то,
#   ради чего написана проверка 4 ниже: переменные nginx СТРОЧНЫЕ ($status, $uri, $args),
#   так что попади они в SHELL-FORMAT — в allowlist они бы не попали, и проверка не
#   покраснела бы НИКОГДА. Проверено запуском envsubst (nginx:1.27-alpine):
#     envsubst '${status} ${GW_LISTEN}'  →  log_format gw "status= rt=$request_time";
#   nginx такой конфиг принимает и стартует, поле в логе просто исчезает — то есть без
#   этой проверки поломка молчаливая, и найдётся она по пустой колонке в агрегации.
allowlist = set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", call.group(1)))
# Проверки 1 и 2 — про наши собственные переменные; всё, что не GW_, разбирает проверка 4,
# иначе одна и та же чужая переменная краснела бы дважды разными словами.
gw_allowlist = {v for v in allowlist if v.startswith("GW_")}

# 1. Промах оставит в отрендеренном конфиге буквальный `${GW_…}`, и nginx не стартует.
missing = sorted(placeholders - gw_allowlist)
check("каждый плейсхолдер шаблона есть в списке envsubst", not missing, f"нет в списке: {missing}")

# 2. Безвредно в рантайме, но значит, что переменную выкинули из шаблона, а документация
#    оператору всё ещё обещает, что она что-то делает.
unused = sorted(gw_allowlist - placeholders)
check("в списке envsubst нет переменных, которых нет в шаблоне", not unused, f"лишние: {unused}")

# 3. Иначе `set -u` в entrypoint.sh уронит контейнер на неустановленной переменной — с голым
#    "unbound variable" вместо задуманного сообщения.
declared = set(re.findall(r':\s*"\$\{(GW_[A-Z0-9_]+):=', entrypoint))
declared |= set(re.findall(r'\[\[ -n "\$\{(GW_[A-Z0-9_]+):-\}" \]\]', entrypoint))
undeclared = sorted(placeholders - declared)
check("у каждой подставляемой переменной есть дефолт или явная проверка", not undeclared,
      f"без дефолта: {undeclared}")

# 4. envsubst заменяет КАЖДОЕ перечисленное имя. Попади в список рантайм-переменная nginx
#    ($status, $binary_remote_addr, …) — её заменило бы пустой строкой, и формат лога или
#    лимитер тихо сломались бы.
nginx_owned = sorted(allowlist - gw_allowlist)
check("переменные nginx не попали в список envsubst", not nginx_owned, f"чужие: {nginx_owned}")

# 5. Номер счёта ездит в URL (/open-banking/v1.0/accounts/<IBAN>/statements) — путь не должен
#    растекаться в агрегацию логов.
fmt = re.search(r"log_format\s+gw\s+([\s\S]*?);", template)
if not fmt:
    check("формат лога найден", False, "log_format gw не найден")
else:
    body = fmt.group(1)
    # Только целые имена: $request_method и $request_time безопасны (пути в них нет), а
    # оба содержат "$request" подстрокой — простой поиск подстроки отверг бы их.
    leaked = [n for n in ("request", "uri", "args", "request_uri", "document_uri")
              if re.search(rf"\${n}(?![a-z_])", body)]
    check("формат лога не несёт путь запроса", not leaked, f"найдено: {leaked}")

# 6. Шифрованный канал к непроверенному собеседнику — не то, ради чего всё делалось: потеря
#    любой из трёх директив превращает шлюз в нечто, разговаривающее с кем угодно на том IP.
for directive, pattern in (
    ("proxy_ssl_verify on", r"proxy_ssl_verify\s+on;"),
    ("proxy_ssl_trusted_certificate", r"proxy_ssl_trusted_certificate\s+\$\{GW_CA_BUNDLE\};"),
    ("proxy_ssl_name", r"proxy_ssl_name\s+\$\{GW_UPSTREAM_HOST\};"),
):
    check(f"проверка апстрима: {directive}", re.search(pattern, template) is not None, "директива не найдена")

# 7. DHT-BIGN — перенос ключа: компрометация долговременного ключа банка позже расшифрует
#    записанные сессии. DHE-BIGN эфемерен. Навязать порядок мы не можем (сервер вправе выбрать
#    свой), но заявить предпочтение обязаны именно так.
ciphers = re.search(r"proxy_ssl_ciphers\s+([^;]+);", template)
if not ciphers:
    check("шифронаборы найдены", False, "proxy_ssl_ciphers не найден")
else:
    lst = ciphers.group(1).split(":")
    dhe = next((i for i, c in enumerate(lst) if c.strip().startswith("DHE-BIGN")), -1)
    dht = next((i for i, c in enumerate(lst) if c.strip().startswith("DHT-BIGN")), -1)
    check("forward secrecy предлагается раньше переноса ключа",
          dhe >= 0 and dht >= 0 and dhe < dht, f"DHE на {dhe}, DHT на {dht}")

# 8. Шлюз никого не аутентифицирует — список путей И ЕСТЬ граница. `location /`, который
#    проксировал бы вместо отказа, превратил бы его в открытый релей к банку.
#    Комментарии срезаем: они обсуждают location'ы прозой, а утверждаем мы про директивы.
#    Делим по `location`, а не по скобкам: в телах есть `${GW_BURST}`, и скан `[^}]*`
#    остановился бы не на той скобке.
directives = re.sub(r"^\s*#.*$", "", template, flags=re.M)
blocks = re.split(r"\blocation\s+", directives)[1:]
proxied = []
for b in blocks:
    nxt = b.find("location")
    head = b if nxt == -1 else b[:nxt]
    if "proxy_pass" in head:
        proxied.append(re.match(r"(?:=\s+)?(\S+)", b).group(1))
# Маршруты к банку с версии #7 генерирует entrypoint.sh из GW_ALLOW и приносит
# include'ом. В САМОМ шаблоне проксирующих location быть не должно: вернувшийся сюда
# литеральный путь означал бы, что кто-то снова зашил API конкретного банка в образ —
# и, что хуже, обошёл проверку формата, которую генератор делает над GW_ALLOW.
check("в шаблоне нет захардкоженных проксирующих маршрутов", not proxied,
      f"найдены прямо в шаблоне: {sorted(proxied)}")
check("маршруты подключаются include'ом из сгенерированного файла",
      re.search(r"include\s+/tmp/crypto-gw\.routes\.conf;", directives) is not None,
      "include /tmp/crypto-gw.routes.conf; не найден")
# Пропажа этого include НЕ ломает ни сборку, ни старт: nginx поднимется, запросы пойдут, а
# каждая строка лога будет route=none. Оператор потеряет единственный признак того, какая
# ветка allowlist отработала, — и не узнает об этом, потому что всё зелёное.
check("метки маршрутов для лога тоже подключаются",
      re.search(r"include\s+/tmp/crypto-gw\.routes-map\.conf;", directives) is not None,
      "include /tmp/crypto-gw.routes-map.conf; не найден")
check("всё остальное отвергается", re.search(r"location\s+/\s*\{[^}]*return 404;", directives) is not None,
      "location / { … return 404; } не найден")

if failures:
    print(f"\nпровалено проверок: {len(failures)}", file=sys.stderr)
    sys.exit(1)
print("\nвсе проверки конфигурации пройдены")
PY
