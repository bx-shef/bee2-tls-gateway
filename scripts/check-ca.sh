#!/usr/bin/env bash
# Связка ГосСУОК: сроки годности и способность подтвердить сертификат банка.
#
# ЗАЧЕМ. Шлюз проверяет банк по смонтированной связке, и сколько эти корни ещё
# действительны, не проверяет ничто. Когда они истекут или банк перевыпустит цепочку,
# `proxy_ssl_verify on` начнёт отклонять рукопожатие — а со стороны потребителя это
# выглядит НЕ как авария, а как «банк перестал присылать выписки». Никого не разбудит,
# ничто не загорится красным, и расхождение всплывёт через недели на сверке.
#
# Тихий отказ хуже громкого, поэтому здесь он превращается в заблаговременное
# предупреждение — за дни, а не за часы.
#
# ДВА ПРИМЕНЕНИЯ, одно и то же:
#   bash scripts/check-ca.sh                 # связка из репозитория
#   bash scripts/check-ca.sh /путь/к/candidate.pem [/путь/к/leaf.pem]
# Второе — проверка КАНДИДАТА до того, как он заменит боевую связку. Тем же механизмом,
# что и стартовый гейт: если кандидат не подтверждает известный сертификат банка, он не
# должен доехать до прода.
#
# ⚠ ЧЕГО ЭТОТ СКРИПТ НЕ ДЕЛАЕТ: не скачивает корни и не подставляет их сам. Подменивший
# ответ nces.by подменит корень доверия — автоматизируем обнаружение, не доверие
# (ca/README.md, раздел «Ротация»).
#
# ⚠ ЧТО УМЕЕТ ОБЫЧНЫЙ OPENSSL, А ЧТО НЕТ — проверено запуском, а не предположено:
#   - даты и субъекты читаются стоковым openssl нормально;
#   - `openssl verify` по этой связке стоковым НЕ РАБОТАЕТ: ключи bign, и он падает с
#     `X509_PUBKEY_get0: decode error`. Разобрать их умеет только пропатченный движок.
# Поэтому проверка цепочки — третий исход «не проверено», а не провал, если под рукой
# стоковый openssl. Путь к патченному задаётся переменной OPENSSL, внутри образа это
# /opt/btls/bin/openssl:
#   docker run --rm -v "$PWD/ca:/ca:ro" --entrypoint bash <образ> \
#     -c 'OPENSSL=/opt/btls/bin/openssl … '
# Ровно на этом различии стоит гейт 3 в Dockerfile: он и есть доказательство, что движок
# читает bign.
#
# Пороги: WARN — предупреждение, CRIT — уже поздно готовиться.
# Коды возврата: 0 — всё в порядке; 10 — есть что показать; 1 — скрипт сломался.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

BUNDLE="${1:-ca/gossuok-bundle.pem}"
LEAF="${2:-ca/bank-leaf-reference.pem}"
WARN_DAYS="${CA_WARN_DAYS:-90}"
CRIT_DAYS="${CA_CRIT_DAYS:-30}"

OPENSSL="${OPENSSL:-openssl}"
command -v "$OPENSSL" >/dev/null || { echo "FAIL не нашёл openssl: $OPENSSL" >&2; exit 1; }
[ -r "$BUNDLE" ] || { echo "FAIL связка не читается: $BUNDLE" >&2; exit 1; }

BUNDLE="$BUNDLE" LEAF="$LEAF" WARN_DAYS="$WARN_DAYS" CRIT_DAYS="$CRIT_DAYS" \
OPENSSL="$OPENSSL" python3 - <<'PY'
import datetime
import os
import re
import subprocess
import sys

bundle = os.environ["BUNDLE"]
leaf = os.environ["LEAF"]
warn_days = int(os.environ["WARN_DAYS"])
openssl = os.environ.get("OPENSSL", "openssl")
crit_days = int(os.environ["CRIT_DAYS"])

now = datetime.datetime.now(datetime.timezone.utc)
problems = []    # то, что требует действия
unchecked = []   # то, что проверить не удалось — не «ok» и не провал


def certs(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                          fh.read(), re.S)


def info(pem):
    """Срок и субъект одного сертификата. Только stdlib + openssl, без сторонних модулей."""
    out = subprocess.run([openssl, "x509", "-noout", "-enddate", "-subject", "-nameopt", "utf8"],
                         input=pem, capture_output=True, text=True)
    if out.returncode != 0:
        return None, None
    end = subj = None
    for line in out.stdout.splitlines():
        if line.startswith("notAfter="):
            end = datetime.datetime.strptime(line[9:].strip(), "%b %d %H:%M:%S %Y %Z") \
                .replace(tzinfo=datetime.timezone.utc)
        elif line.startswith("subject="):
            subj = line[8:].strip()
    return end, subj


def short(subject):
    """CN, если есть, иначе конец строки субъекта — чтобы отчёт читался."""
    if not subject:
        return "(без субъекта)"
    m = re.search(r"CN\s*=\s*([^,/]+)", subject)
    return (m.group(1) if m else subject).strip()[:70]


blocks = certs(bundle)
if not blocks:
    print(f"FAIL в {bundle} нет ни одного сертификата", file=sys.stderr)
    sys.exit(1)

print(f"связка {bundle}: {len(blocks)} сертификат(ов)")
for i, pem in enumerate(blocks, 1):
    end, subj = info(pem)
    if end is None:
        print(f"FAIL  #{i}: не разобрался — openssl не смог прочитать сертификат", file=sys.stderr)
        problems.append(f"сертификат #{i} не разбирается")
        continue
    left = (end - now).days
    if left < 0:
        state, mark = "ИСТЁК", "FAIL"
        problems.append(f"{short(subj)} истёк {-left} дн. назад")
    elif left <= crit_days:
        state, mark = "КРИТИЧНО", "FAIL"
        problems.append(f"{short(subj)} истекает через {left} дн.")
    elif left <= warn_days:
        state, mark = "скоро", "WARN"
        problems.append(f"{short(subj)} истекает через {left} дн.")
    else:
        state, mark = "ok", "ok"
    print(f"{mark:4} #{i} {short(subj)}: до {end:%Y-%m-%d}, осталось {left} дн. [{state}]")

# --- связка действительно подтверждает известный сертификат банка --------------------
# Тот же механизм, что в гейте 3 и в entrypoint.sh. Связка, где лежит только корень,
# проходит любую синтаксическую проверку и потом 502-ит каждый запрос
# («unable to get local issuer certificate») — ловится только настоящим verify.
if os.path.exists(leaf):
    # -no_check_time намеренно: эталон подписывает ничего и служит только МИШЕНЬЮ проверки.
    # Утверждаем, что цепочка смыкается, а не что мишень ещё жива, — иначе проверка
    # начнёт падать в день истечения эталона по причине, к связке не относящейся.
    v = subprocess.run([openssl, "verify", "-no_check_time", "-CAfile", bundle, leaf],
                       capture_output=True, text=True)
    combined = v.stdout + v.stderr
    if v.returncode == 0:
        print(f"ok   связка подтверждает эталонный сертификат банка ({leaf})")
    elif "X509_PUBKEY_get0" in combined or "unable to get certs public key" in combined:
        # НЕ провал связки: это стоковый openssl не умеет читать ключи bign. Отличать
        # обязательно — иначе исправная связка выглядела бы сломанной, и проверку
        # отключили бы первой же, вместе с её полезной частью.
        print(f"??   цепочку проверить не удалось: {openssl} не читает ключи bign "
              f"(X509_PUBKEY_get0 decode error). Нужен патченный движок: "
              f"OPENSSL=/opt/btls/bin/openssl внутри образа")
        unchecked.append("цепочка (нужен патченный openssl)")
    else:
        print(f"FAIL связка НЕ подтверждает {leaf}: {combined.strip()[:300]}", file=sys.stderr)
        problems.append("связка не подтверждает эталонный сертификат банка")

    end, subj = info(open(leaf, encoding="utf-8", errors="replace").read())
    if end is not None:
        left = (end - now).days
        # Эталон — не якорь доверия, и его истечение НЕ ломает прод: гейты сверяют цепочку
        # с `-no_check_time`. Но устаревший эталон перестаёт быть свидетельством, поэтому
        # он тут отдельной строкой и НЕ попадает в problems.
        print(f"     эталон банка {short(subj)}: до {end:%Y-%m-%d}, осталось {left} дн. "
              f"(на прод не влияет, но обновить стоит)")
else:
    print(f"     эталонный сертификат отсутствует ({leaf}) — проверка цепочки пропущена")

print()
if unchecked:
    print(f"не проверено: {', '.join(unchecked)}")
if problems:
    print("требует внимания:")
    for p in problems:
        print(f"  - {p}")
    sys.exit(10)
print(f"сроки в порядке; ближайшее истечение дальше {warn_days} дн.")
PY
