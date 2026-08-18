#!/usr/bin/env bash
# Пины: сверка того, что записано в РАЗНЫХ местах репозитория, между собой.
#
# ЗАЧЕМ. Образ пинит четыре вещи, и `Dockerfile` — единственный источник правды для них.
# Но значение пина иногда приходится повторить в другом файле, и вот это повторение и
# опасно: при бампе правят `Dockerfile`, а копию забывают. Копия не ломает сборку, она
# ломает СМЫСЛ проверки, которая на ней стоит, — и делает это молча, оставляя CI зелёным.
#
# Конкретный случай, ради которого скрипт написан: `scripts/check-crypto.sh` прогоняет
# контрольные примеры стандартов на bee2, взятом по коммиту, который выписан в нём самом
# отдельной переменной. Разъедется с `Dockerfile` — и зелёный прогон методик перестанет
# что-либо говорить об образе, потому что проверять будет другую версию криптостека.
#
# ⚠ ЧЕГО ЭТОТ СКРИПТ НАМЕРЕННО НЕ ДЕЛАЕТ. Он не сверяет версии, упомянутые в документации
# прозой — КРОМЕ одной таблицы (см. проверку 4 ниже: `PROCESS.md` §6.2 объявляет состав
# изделия как ТЕКУЩИЙ факт, её читает эксперт, и разъехаться ей нельзя). В `PROCESS.md` законно живут исторические упоминания («1.28.0 нёс CVE-…»), и
# проверка «все упоминания версии равны текущему пину» краснела бы на правдивом тексте.
# Проверка, которая врёт про исправный репозиторий, отключается первой — а вместе с ней
# отключается и та её часть, которая была полезной.
#
# Отставание пинов от АПСТРИМА — другая задача и другой механизм: она требует сети,
# поэтому живёт в отдельной джобе (.github/workflows/pins.yml) и не блокирует сборку.
set -euo pipefail

cd "$(dirname "$0")/.."

DOCKERFILE=Dockerfile
CRYPTO=scripts/check-crypto.sh
PROCESS=docs/PROCESS.md

for f in "$DOCKERFILE" "$CRYPTO" "$PROCESS"; do
  [ -r "$f" ] || { echo "FAIL нет файла $f" >&2; exit 1; }
done

DOCKERFILE="$DOCKERFILE" CRYPTO="$CRYPTO" PROCESS="$PROCESS" python3 - <<'PY'
import os
import re
import sys

dockerfile = open(os.environ["DOCKERFILE"], encoding="utf-8").read()
crypto = open(os.environ["CRYPTO"], encoding="utf-8").read()
process = open(os.environ["PROCESS"], encoding="utf-8").read()

failures = []


def check(name, ok, detail=""):
    if ok:
        print(f"ok   {name}")
    else:
        print(f"FAIL {name}: {detail}", file=sys.stderr)
        failures.append(name)


def arg(name, text=dockerfile):
    """Значение `ARG NAME=...` — только строка с присваиванием.

    В Dockerfile то же имя повторяется без значения в каждой стадии, которой аргумент
    нужен; такие строки — не источник правды, и брать их нельзя.
    """
    m = re.search(rf"^ARG\s+{name}=(\S+)\s*$", text, re.M)
    return m.group(1) if m else None


def var(name, text=crypto):
    """Значение `NAME=...` в shell-скрипте, без кавычек."""
    m = re.search(rf"^{name}=[\"']?([^\"'\s]+)[\"']?\s*$", text, re.M)
    return m.group(1) if m else None


# Все четыре пина обязаны быть найдены. Переименуют ARG — скрипт скажет об этом, а не
# начнёт молча сравнивать None с None и печатать «ok».
pins = {n: arg(n) for n in
        ("DEBIAN_IMAGE", "BEE2EVP_COMMIT", "OPENSSL_TAG", "NGINX_VERSION", "NGINX_SHA256")}
missing = sorted(n for n, v in pins.items() if v is None)
check("все пины найдены в Dockerfile", not missing, f"не разобрались: {missing}")
if missing:
    sys.exit(1)

# --- 1. Главное: криптостек, который проверяют методиками, и есть тот, что едет ------
crypto_bee2evp = var("BEE2EVP_COMMIT")
check("BEE2EVP_COMMIT найден в check-crypto.sh", crypto_bee2evp is not None,
      "переменная не разобралась — проверка ниже была бы пустой")

if crypto_bee2evp is not None:
    check("check-crypto.sh проверяет тот же bee2evp, что собирает Dockerfile",
          crypto_bee2evp == pins["BEE2EVP_COMMIT"],
          f"Dockerfile {pins['BEE2EVP_COMMIT']}, check-crypto.sh {crypto_bee2evp}")

# --- 2. Пин bee2 существует и выглядит коммитом --------------------------------------
# Его нельзя сверить с Dockerfile: bee2 приезжает ПОДМОДУЛЕМ внутрь bee2evp, и в
# Dockerfile его sha не выписан. Что он соответствует подмодулю запиненного bee2evp —
# проверяется в джобе pins.yml, где есть сеть. Здесь — только форма.
crypto_bee2 = var("BEE2_COMMIT")
check("BEE2_COMMIT в check-crypto.sh похож на полный sha",
      crypto_bee2 is not None and re.fullmatch(r"[0-9a-f]{40}", crypto_bee2) is not None,
      f"значение: {crypto_bee2}")

# --- 3. Форма самих пинов -------------------------------------------------------------
# Не придирка: `FROM` по тегу вместо digest превращает воспроизводимую сборку крипто в
# лотерею, а пин bee2evp по ТЕГУ (а не коммиту) перестал бы пинить подмодуль.
check("базовый образ пинуется по digest, а не по тегу",
      "@sha256:" in pins["DEBIAN_IMAGE"], f"значение: {pins['DEBIAN_IMAGE']}")
check("bee2evp пинуется полным sha коммита",
      re.fullmatch(r"[0-9a-f]{40}", pins["BEE2EVP_COMMIT"]) is not None,
      f"значение: {pins['BEE2EVP_COMMIT']}")
check("OPENSSL_TAG выглядит тегом релиза openssl-X.Y.Z",
      re.fullmatch(r"openssl-\d+\.\d+\.\d+", pins["OPENSSL_TAG"]) is not None,
      f"значение: {pins['OPENSSL_TAG']}")
check("NGINX_SHA256 — 64 hex-символа",
      re.fullmatch(r"[0-9a-f]{64}", pins["NGINX_SHA256"]) is not None,
      f"значение: {pins['NGINX_SHA256']}")

# --- 4. Таблица состава изделия в PROCESS.md §6.2 ------------------------------------
# Эта таблица — не проза и не история: она объявляет, ИЗ ЧЕГО СОБРАНО ИЗДЕЛИЕ СЕЙЧАС, и
# именно её читает эксперт на анализе документации. Бампнут пин — она молча начнёт врать
# про состав объекта испытаний, и красным это нигде не станет. Сверяем ТОЛЬКО её строки,
# не весь файл: в остальном тексте исторические упоминания версий законны (см. шапку).
tbl = re.search(r"\| Компонент \| Версия / пин \|[\s\S]*?\n\n", process)
check("таблица состава §6.2 найдена в PROCESS.md", tbl is not None,
      "заголовок «| Компонент | Версия / пин |» не найден — проверка ниже была бы пустой")

if tbl is not None:
    table = tbl.group(0)
    # ⚠ Ищем в СВОЕЙ СТРОКЕ таблицы, а не «где-нибудь в таблице». Первая редакция искала
    # вхождение подстроки — и была МЁРТВОЙ: `openssl-3.5.6` совпадал с именем файла патча
    # `openssl-3.5.6.patch` в соседней строке, поэтому подмена версии в строке OpenSSL
    # проверку не роняла. Поймано мутацией при вводе.
    def row(component):
        m = re.search(rf"^\| {component} \|([^|]*)\|", table, re.M)
        return m.group(1) if m else None

    ossl_row = row("OpenSSL")
    check("состав §6.2 называет тот же OpenSSL, что собирает Dockerfile",
          ossl_row is not None and pins["OPENSSL_TAG"] in ossl_row,
          f"в Dockerfile {pins['OPENSSL_TAG']}, в строке таблицы: {ossl_row!r}")

    nginx_row = row("nginx")
    check("состав §6.2 называет ту же версию nginx",
          nginx_row is not None and pins["NGINX_VERSION"] in nginx_row,
          f"в Dockerfile {pins['NGINX_VERSION']}, в строке таблицы: {nginx_row!r}")
    # Коммит bee2evp в таблице сокращён до префикса с многоточием — сверяем префикс.
    m = re.search(r"коммит `([0-9a-f]{6,40})…?`", table)
    check("состав §6.2 называет тот же коммит bee2evp",
          m is not None and pins["BEE2EVP_COMMIT"].startswith(m.group(1)),
          f"в Dockerfile {pins['BEE2EVP_COMMIT']}, в таблице {m.group(1) if m else 'не разобрался'}")

print()
for name, value in pins.items():
    print(f"пин {name:16} = {value}")

if failures:
    print(f"\nпровалено проверок: {len(failures)}", file=sys.stderr)
    sys.exit(1)
print("\nпины согласованы между файлами")
PY
