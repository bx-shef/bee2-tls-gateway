#!/usr/bin/env bash
# Отставание пинов от апстрима: сверка с релизными лентами.
#
# ЗАЧЕМ. Образ пинит четыре вещи, и Dependabot видит из них ОДНУ — `FROM`. Остальные три
# заданы через `ARG` (git-коммит, тег релиза, тарбол с sha256), и ни один бот их не
# отслеживает. То есть три четверти цепочки поставки TLS-терминирующего прокси обновляются
# только тогда, когда человек вспомнит посмотреть.
#
# Частота отказов у подхода «человек вспомнит» здесь измерена и равна двум из двух:
#   - OpenSSL 3.3.1 с истёкшей поддержкой и CVE-2024-6119 — нашли руками;
#   - nginx 1.28.0 с CVE-2026-1642 на ветке, ушедшей в legacy, — нашли руками.
#
# ⚠ ЭТОТ СКРИПТ НЕ БЛОКИРУЕТ СБОРКУ И НЕ ДОЛЖЕН. Сборка шлюза не может начать падать
# оттого, что апстрим что-то опубликовал вчера: это превратило бы чужой релиз в нашу
# аварию. Он ТОЛЬКО сообщает. Решение — за человеком.
#
# ⚠ И НЕ РЕШАЕТ, надо ли обновляться. «Вышла новая версия» и «нам нужно обновиться» —
# разные утверждения: у nginx свежий mainline может быть хуже stable, а у OpenSSL бамп
# невозможен без патча BTLS под новый тег. Скрипт даёт факты, а не вердикт.
#
# Согласованность пинов МЕЖДУ ФАЙЛАМИ — другая задача, она детерминирована, не требует
# сети и потому блокирует: scripts/check-pins.sh.
#
# Коды возврата: 0 — расхождений нет; 10 — есть расхождения; 1 — сам скрипт сломался.
# Именно 10, а не 1: вызывающему надо отличать «нашлось что показать» от «проверка упала».
set -uo pipefail

# `|| exit 1` явно: у скрипта намеренно НЕТ `set -e` (расхождение — это код 10, а не
# аварийный выход), поэтому неудачный cd молча продолжил бы работу не в том каталоге.
cd "$(dirname "$0")/.." || exit 1

python3 - <<'PY'
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request

TIMEOUT = 20


def arg(name):
    """Значение `ARG NAME=...` из Dockerfile — только строка с присваиванием."""
    text = open("Dockerfile", encoding="utf-8").read()
    m = re.search(rf"^ARG\s+{name}=(\S+)\s*$", text, re.M)
    return m.group(1) if m else None


def fetch(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "bee2-tls-gateway-pins"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return r.read().decode("utf-8", "replace")


findings = []   # расхождения — то, ради чего скрипт запускают
notes = []      # то, что проверить не удалось; молчать об этом нельзя


def report(component, ours, theirs, note=""):
    if ours == theirs:
        print(f"ok   {component}: {ours}")
    else:
        print(f"ОТСТАЁТ {component}: у нас {ours}, апстрим {theirs} {note}".rstrip())
        findings.append((component, ours, theirs, note))


def unknown(component, why):
    """Не удалось проверить — это ТРЕТИЙ исход, и он не «ok».

    Молчаливое превращение недоступной сети в зелёный отчёт — ровно тот способ,
    которым сторож перестаёт сторожить, оставаясь зелёным.
    """
    print(f"??   {component}: проверить не удалось — {why}")
    notes.append((component, why))


# --- nginx: stable и mainline с nginx.org --------------------------------------------
ours = arg("NGINX_VERSION")
try:
    html = fetch("https://nginx.org/en/download.html")
    plain = re.sub(r"<[^>]*>", " ", html)
    branches = {}
    for label, key in (("Mainline version", "mainline"), ("Stable version", "stable"),
                       ("Legacy versions", "legacy")):
        m = re.search(rf"{label}(.*?)(?:Mainline version|Stable version|Legacy versions|$)",
                      plain, re.S)
        if m:
            vs = re.findall(r"nginx-(\d+\.\d+\.\d+)", m.group(1))
            if vs:
                branches[key] = vs[0]
    stable = branches.get("stable")
    ours_branch = ".".join(ours.split(".")[:2]) if ours else None
    stable_branch = ".".join(stable.split(".")[:2]) if stable else None
    if stable is None:
        unknown("nginx", "не разобрал страницу загрузок")
    elif ours_branch != stable_branch:
        report("nginx", ours, stable,
               f"— ВЕТКА РАЗНАЯ: наша {ours_branch}, stable {stable_branch}")
    else:
        report("nginx", ours, stable)
except Exception as exc:  # noqa: BLE001 — сеть, причина важна в отчёте
    unknown("nginx", f"{type(exc).__name__}: {exc}")

# --- OpenSSL: последняя в НАШЕЙ ветке -------------------------------------------------
# Сравниваем внутри ветки намеренно: уход на 3.6 требует, чтобы у bee2evp существовал
# btls/patch/<tag>.patch под новый тег, и без него сборка просто не соберётся.
ours = arg("OPENSSL_TAG")
try:
    html = fetch("https://openssl-library.org/source/")
    tags = sorted(set(re.findall(r"openssl-(\d+\.\d+\.\d+)", html)),
                  key=lambda v: [int(x) for x in v.split(".")])
    ours_v = ours.replace("openssl-", "") if ours else ""
    ours_series = ".".join(ours_v.split(".")[:2])
    same = [t for t in tags if t.startswith(ours_series + ".")]
    if not tags:
        unknown("openssl", "не нашёл ни одного тега на странице релизов")
    elif same:
        report("openssl", ours, "openssl-" + same[-1])
        newer_series = [t for t in tags
                        if [int(x) for x in t.split(".")[:2]] > [int(x) for x in ours_series.split(".")]]
        if newer_series:
            print(f"     примечание: есть ветка новее — {newer_series[-1]}; "
                  f"переход возможен только если у bee2evp есть btls/patch под этот тег")
    else:
        unknown("openssl", f"на странице нет релизов ветки {ours_series}")
except Exception as exc:  # noqa: BLE001
    unknown("openssl", f"{type(exc).__name__}: {exc}")

# --- bee2evp: HEAD ветки по умолчанию -------------------------------------------------
# Пин по коммиту не устаревает сам по себе — устаревает наше знание о том, что впереди.
# Поэтому здесь не «отстаём», а «сколько коммитов прошло»: цифра для человека.
ours = arg("BEE2EVP_COMMIT")
try:
    data = json.loads(fetch("https://api.github.com/repos/bcrypto/bee2evp/commits?per_page=1",
                            headers={"User-Agent": "bee2-tls-gateway-pins",
                                     "Accept": "application/vnd.github+json"}))
    head = data[0]["sha"]
    if head == ours:
        print(f"ok   bee2evp: {ours[:12]} — это HEAD")
    else:
        report("bee2evp", ours[:12], head[:12], "— апстрим ушёл вперёд, это НЕ повод бампать")
except Exception as exc:  # noqa: BLE001
    unknown("bee2evp", f"{type(exc).__name__}: {exc}")

print()
if findings:
    print(f"расхождений: {len(findings)}")
if notes:
    print(f"не проверено: {len(notes)} — {', '.join(n[0] for n in notes)}")
if not findings and not notes:
    print("все пины совпадают с апстримом")

# Недоступная сеть — не «всё хорошо». Но и не расхождение: отдельный код, чтобы
# вызывающий мог отличить одно от другого.
sys.exit(10 if findings else 0)
PY
