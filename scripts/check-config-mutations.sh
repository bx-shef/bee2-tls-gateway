#!/usr/bin/env bash
# Мутационная проверка для scripts/check-config.sh — сторож сторожа.
#
# ЗАЧЕМ. Проверка конфигурации, которая никогда не краснеет, неотличима от проверки,
# которая работает: обе печатают «ok» и обе зелёные в CI. Разница видна только тогда,
# когда что-то ломают — то есть на боевом сервере. Здесь мы ломаем нарочно: каждая
# мутация вносит в `nginx.conf.template` или `entrypoint.sh` ровно ту порчу, против
# которой написана соответствующая проверка, и ОБЯЗАНА покраснеть — причём ИМЕННО своей
# проверкой. Покраснела чужой — значит своя мертва, а её работу случайно делает соседка.
#
# Так был найден мёртвый сторож: проверка «переменные nginx не попали в список envsubst»
# собирала список регуляркой `\$\{([A-Z0-9_]+)\}` — только ПРОПИСНЫЕ имена. Все переменные
# nginx строчные ($status, $uri, $args), так что искомое в список не попадало никогда и
# проверка не могла покраснеть в принципе. Мутации 5a/5b держат её живой.
#
# ⚠ «мутация не применилась» — тоже провал, а не пропуск. Если шаблон отформатировали и
# паттерн перестал совпадать, проверка молча перестала бы что-либо доказывать; лучше
# красный CI и поправленный паттерн.
#
# Дерево должно быть чистым по мутируемым файлам: откат идёт через `git checkout`.
set -euo pipefail

cd "$(dirname "$0")/.."

python3 - <<'PY'
import re
import subprocess
import sys

TPL = "nginx.conf.template"
EP = "entrypoint.sh"
DF = "Dockerfile"
CR = "scripts/check-crypto.sh"

# Всё, что мутируем, обязано откатываться. Забыть файл здесь — значит оставить мутацию
# в рабочем дереве и увести следующего в разбор несуществующей поломки.
MUTATED = (TPL, EP, DF, CR)


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True)


def restore():
    git("checkout", "--", *MUTATED)


def sub(path, pattern, repl):
    """Заменить первое совпадение; False, если паттерн не совпал.

    re.M — чтобы `^`/`$` означали границы СТРОКИ: пины задаются построчно (`ARG NAME=...`),
    и без этого флага такой паттерн молча не совпадёт, а мутация превратится в пропуск.
    """
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    new, count = re.subn(pattern, repl, text, count=1, flags=re.M)
    if count == 0:
        return False
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new)
    return True


def run_checks(script="scripts/check-config.sh"):
    p = subprocess.run(["bash", script], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


results = []


def mutate(name, apply_fn, want, script="scripts/check-config.sh"):
    """want — фрагмент имени проверки, которая ОБЯЗАНА покраснеть на этой мутации.

    script — какой сторож обязан её поймать. Мутация, пойманная ЧУЖИМ сторожем, здесь
    считается провалом: значит свой мёртв, а его работу делает соседний по случайности.
    """
    restore()
    if not apply_fn():
        results.append(("СЛОМ", name, "мутация не применилась: паттерн не совпал с файлом"))
        restore()
        return
    rc, out = run_checks(script)
    fails = [ln for ln in out.splitlines() if ln.startswith("FAIL")]
    if rc == 0:
        results.append(("СЛОМ", name, "ЗЕЛЁНЫЙ — проверка не ловит эту поломку"))
    elif not any(want in ln for ln in fails):
        results.append(("СЛОМ", name, f"красный, но не проверкой «{want}»: {fails}"))
    else:
        results.append(("ok", name, "; ".join(fails)))
    restore()


if git("status", "--porcelain", "--", *MUTATED).stdout.strip():
    sys.exit(f"FAIL мутируемые файлы изменены — откат идёт через git, прерываю")

for script in ("scripts/check-config.sh", "scripts/check-pins.sh",
               "scripts/check-allowlist.sh"):
    rc, out = run_checks(script)
    if rc != 0:
        sys.exit(f"FAIL базовая линия КРАСНАЯ у {script} — чинить его, а не мутации:\n{out}")
results.append(("ok", "базовая линия без мутаций", "зелёная у всех сторожей"))

# --- envsubst: список переменных против плейсхолдеров шаблона ---------------------
mutate("плейсхолдер шаблона отсутствует в списке envsubst",
       lambda: sub(TPL, r"client_max_body_size 64k;", "client_max_body_size ${GW_MAX_BODY};"),
       "каждый плейсхолдер шаблона есть в списке envsubst")

mutate("в списке envsubst переменная, которой нет в шаблоне",
       lambda: sub(EP, r"\$\{GW_ERROR_LOG_LEVEL\}'", "${GW_ERROR_LOG_LEVEL} ${GW_GHOST}'"),
       "нет переменных, которых нет в шаблоне")

mutate("подставляемая переменная без дефолта в entrypoint",
       lambda: (sub(TPL, r"client_max_body_size 64k;", "client_max_body_size ${GW_MAX_BODY};")
                and sub(EP, r"\$\{GW_ERROR_LOG_LEVEL\}'",
                        "${GW_ERROR_LOG_LEVEL} ${GW_MAX_BODY}'")),
       "у каждой подставляемой переменной есть дефолт")

# Обе формы: envsubst понимает и `${name}`, и `$name`.
mutate("переменная nginx ${status} попала в список envsubst",
       lambda: sub(EP, r"envsubst '", "envsubst '${status} "),
       "переменные nginx не попали")

mutate("переменная nginx $uri попала в список envsubst (без скобок)",
       lambda: sub(EP, r"envsubst '", "envsubst '$uri "),
       "переменные nginx не попали")

# --- лог не несёт путь запроса ----------------------------------------------------
mutate("$request_uri добавлен в формат лога",
       lambda: sub(TPL, r"rt=\$request_time", "path=$request_uri rt=$request_time"),
       "формат лога не несёт путь")

# --- собеседник проверяется -------------------------------------------------------
mutate("proxy_ssl_verify выключен",
       lambda: sub(TPL, r"proxy_ssl_verify on;", "proxy_ssl_verify off;"),
       "proxy_ssl_verify on")

mutate("proxy_ssl_trusted_certificate удалён",
       lambda: sub(TPL, r"\n\s*proxy_ssl_trusted_certificate [^;]+;", ""),
       "proxy_ssl_trusted_certificate")

mutate("proxy_ssl_name удалён — имя хоста не сверяется",
       lambda: sub(TPL, r"\n\s*proxy_ssl_name [^;]+;", ""),
       "proxy_ssl_name")

# --- forward secrecy предлагается раньше переноса ключа ---------------------------
mutate("DHT-BIGN переставлен перед DHE-BIGN",
       lambda: sub(TPL, r"proxy_ssl_ciphers [^;]+;",
                   "proxy_ssl_ciphers DHT-BIGN-WITH-BELT-CTR-MAC-HBELT:"
                   "DHE-BIGN-WITH-BELT-CTR-MAC-HBELT;"),
       "forward secrecy")

# --- список путей: единственная граница безопасности ------------------------------
mutate("location / проксирует вместо отказа (открытый релей)",
       lambda: sub(TPL, r"location / \{\n            return 404;",
                   "location / {\n            proxy_pass https://bank$uri;"),
       "нет захардкоженных проксирующих маршрутов")

mutate("проксируемый префикс вне allowlist",
       lambda: sub(TPL, r"        location / \{",
                   "        location /admin/ {\n"
                   "            proxy_pass https://bank$uri;\n"
                   "        }\n\n        location / {"),
       "нет захардкоженных проксирующих маршрутов")

mutate("отказ по умолчанию заменён на 200",
       lambda: sub(TPL, r"location / \{\n            return 404;",
                   "location / {\n            return 200;"),
       "всё остальное отвергается")

# --- пины: согласованность между файлами (сторож — scripts/check-pins.sh) ----------
PINS = "scripts/check-pins.sh"

mutate("check-crypto.sh проверяет ДРУГОЙ коммит bee2evp, чем собирает Dockerfile",
       lambda: sub(CR, r"^BEE2EVP_COMMIT=\S+$",
                   "BEE2EVP_COMMIT=0000000000000000000000000000000000000000"),
       "тот же bee2evp", PINS)

mutate("базовый образ запинен по тегу вместо digest",
       lambda: sub(DF, r"^ARG DEBIAN_IMAGE=\S+$", "ARG DEBIAN_IMAGE=debian:12-slim"),
       "по digest", PINS)

mutate("bee2evp запинен коротким sha",
       lambda: sub(DF, r"^ARG BEE2EVP_COMMIT=\S+$", "ARG BEE2EVP_COMMIT=2ae3c71e"),
       "полным sha коммита", PINS)

mutate("OPENSSL_TAG не похож на тег релиза",
       lambda: sub(DF, r"^ARG OPENSSL_TAG=\S+$", "ARG OPENSSL_TAG=master"),
       "тегом релиза", PINS)

mutate("NGINX_SHA256 обрезан",
       lambda: sub(DF, r"^ARG NGINX_SHA256=\S+$", "ARG NGINX_SHA256=4261dc90"),
       "64 hex-символа", PINS)

mutate("BEE2_COMMIT в check-crypto.sh перестал быть sha",
       lambda: sub(CR, r"^BEE2_COMMIT=\S+$", "BEE2_COMMIT=master"),
       "похож на полный sha", PINS)

# --- allowlist: граница безопасности собирается кодом, значит у кода есть ошибки -----
ALLOW = "scripts/check-allowlist.sh"

# ⚠ Мутация вскрыла, ЧТО именно несёт нагрузку: не запрет скобок, а запрет ПРОБЕЛОВ.
# Директиву nginx без пробела не подставить, поэтому первым срабатывает именно этот тест —
# и `want` назван по нему, а не по красивому «подстановка директив».
mutate("регулярка пути ослаблена — в путь проходят пробелы и скобки",
       lambda: sub(EP, r'\[\[ "\$path" =~ \^/\[A-Za-z0-9\._~/-\]\*\$ \]\]',
                   '[[ "$path" =~ ^/.*$ ]]'),
       "путь с пробелом отвергается", ALLOW)

mutate("снят запрет префикса «/» — открытый релей к банку",
       lambda: sub(EP, r'\[\[ -n "\$exact" \|\| "\$path" != "/" \]\]',
                   '[[ -n "$exact" || "$path" != "///" ]]'),
       "префикс «/» отвергается", ALLOW)

# Запирает дефект, найденный при написании check-allowlist.sh: `:=` подставляет умолчание
# и на ПУСТУЮ строку, поэтому явное «не разрешать ничего» молча возвращало пути банка.
mutate("умолчание GW_ALLOW снова затирает пустую строку (:= вместо -)",
       lambda: sub(EP, r'^GW_ALLOW="\$\{GW_ALLOW-', 'GW_ALLOW="${GW_ALLOW:-'),
       "пустой GW_ALLOW не порождает маршрутов", ALLOW)

mutate("снято требование завершающего / у префикса — матчил бы соседние пути",
       lambda: sub(EP, r'\[\[ -n "\$exact" \|\| "\$path" == \*/ \]\]',
                   '[[ -n "$exact" || "$path" == * ]]'),
       "префикс без завершающего / отвергается", ALLOW)

mutate("снята проверка дубликатов — nginx ушёл бы в цикл перезапусков",
       lambda: sub(EP, r'\*" \$key "\*\) die', '*" NEVERMATCH "*) die'),
       "один путь дважды отвергается", ALLOW)

mutate("include карты маршрутов удалён — весь лог стал бы route=none",
       lambda: sub(TPL, r"\n\s*include /tmp/crypto-gw\.routes-map\.conf;", ""),
       "метки маршрутов для лога тоже подключаются")

restore()

width = max(len(name) for _, name, _ in results)
for status, name, detail in results:
    print(f"{status:4} {name:<{width}}  {detail}")

broken = [r for r in results if r[0] != "ok"]
dirty = git("status", "--porcelain", "--", *MUTATED).stdout.strip()
if dirty:
    print(f"\nFAIL мутации не откатились: {dirty}", file=sys.stderr)
if broken:
    print(f"\nFAIL мёртвых проверок: {len(broken)} из {len(results) - 1}", file=sys.stderr)
if broken or dirty:
    sys.exit(1)
print(f"\nвсе {len(results) - 1} мутаций краснеют своей проверкой")
PY
