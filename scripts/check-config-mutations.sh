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


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True)


def restore():
    git("checkout", "--", TPL, EP)


def sub(path, pattern, repl):
    """Заменить первое совпадение; False, если паттерн не совпал."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    new, count = re.subn(pattern, repl, text, count=1)
    if count == 0:
        return False
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new)
    return True


def run_checks():
    p = subprocess.run(["bash", "scripts/check-config.sh"], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


results = []


def mutate(name, apply_fn, want):
    """want — фрагмент имени проверки, которая ОБЯЗАНА покраснеть на этой мутации."""
    restore()
    if not apply_fn():
        results.append(("СЛОМ", name, "мутация не применилась: паттерн не совпал с файлом"))
        restore()
        return
    rc, out = run_checks()
    fails = [ln for ln in out.splitlines() if ln.startswith("FAIL")]
    if rc == 0:
        results.append(("СЛОМ", name, "ЗЕЛЁНЫЙ — проверка не ловит эту поломку"))
    elif not any(want in ln for ln in fails):
        results.append(("СЛОМ", name, f"красный, но не проверкой «{want}»: {fails}"))
    else:
        results.append(("ok", name, "; ".join(fails)))
    restore()


if git("status", "--porcelain", "--", TPL, EP).stdout.strip():
    sys.exit(f"FAIL {TPL}/{EP} изменены — мутации откатываются через git, прерываю")

rc, out = run_checks()
if rc != 0:
    sys.exit(f"FAIL базовая линия КРАСНАЯ — чинить конфиг, а не мутации:\n{out}")
results.append(("ok", "базовая линия без мутаций", "зелёная"))

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
       "проксируются только известные префиксы")

mutate("проксируемый префикс вне allowlist",
       lambda: sub(TPL, r"        location / \{",
                   "        location /admin/ {\n"
                   "            proxy_pass https://bank$uri;\n"
                   "        }\n\n        location / {"),
       "проксируются только известные префиксы")

mutate("отказ по умолчанию заменён на 200",
       lambda: sub(TPL, r"location / \{\n            return 404;",
                   "location / {\n            return 200;"),
       "всё остальное отвергается")

restore()

width = max(len(name) for _, name, _ in results)
for status, name, detail in results:
    print(f"{status:4} {name:<{width}}  {detail}")

broken = [r for r in results if r[0] != "ok"]
dirty = git("status", "--porcelain", "--", TPL, EP).stdout.strip()
if dirty:
    print(f"\nFAIL мутации не откатились: {dirty}", file=sys.stderr)
if broken:
    print(f"\nFAIL мёртвых проверок: {len(broken)} из {len(results) - 1}", file=sys.stderr)
if broken or dirty:
    sys.exit(1)
print(f"\nвсе {len(results) - 1} мутаций краснеют своей проверкой")
PY
