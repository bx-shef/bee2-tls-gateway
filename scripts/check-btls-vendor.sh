#!/usr/bin/env bash
# Проверки вендорённых копий BTLS (#125).
#
# ГЛАВНЫЙ УРОК, ради которого этот файл существует. Документ архитектуры в трёх местах
# утверждал «сверено по тексту патча» — про коды наборов, про неприкосновенность
# extended_master_secret, про путь уничтожения pre_master_secret. Файла в дереве не было,
# сверка была разовой и держалась на памяти того, кто её делал, а следующий бамп
# BEE2EVP_COMMIT обнулил бы её молча. Здесь «сверено» становится утверждением, которое
# краснеет.
#
# ⚠ Граница названа нарочно. ТЕКСТОМ здесь проверяется содержимое вендорённых копий и их
# согласие с нашим конфигом. Что копии совпадают с апстримом — вопрос к сборке, и он
# закрыт побайтным `cmp` в Dockerfile; повторить его тут нечем, сети у job `ci` нет.
set -euo pipefail

VENDOR=vendor/bee2evp
PATCHF="$VENDOR/openssl-3.5.6.patch"
BTLS_H="$VENDOR/btls.h"
BTLS_C="$VENDOR/btls.c"
BELT_TLS="$VENDOR/belt_tls.c"
PROV="$VENDOR/PROVENANCE"

for f in "$PATCHF" "$BTLS_H" "$BTLS_C" "$BELT_TLS" "$PROV" Dockerfile nginx.conf.template; do
  [ -r "$f" ] || { echo "FAIL нет файла $f" >&2; exit 1; }
done

PATCHF="$PATCHF" BTLS_H="$BTLS_H" BTLS_C="$BTLS_C" BELT_TLS="$BELT_TLS" PROV="$PROV" \
  python3 - <<'PY'
import os
import re
import sys

patch = open(os.environ["PATCHF"], encoding="utf-8", errors="replace").read()
btls_h = open(os.environ["BTLS_H"], encoding="utf-8", errors="replace").read()
btls_c = open(os.environ["BTLS_C"], encoding="utf-8", errors="replace").read()
belt_tls = open(os.environ["BELT_TLS"], encoding="utf-8", errors="replace").read()
prov = open(os.environ["PROV"], encoding="utf-8", errors="replace").read()
dockerfile = open("Dockerfile", encoding="utf-8").read()
template = open("nginx.conf.template", encoding="utf-8").read()

failures = []


def check(name, ok, detail=""):
    if ok:
        print(f"ok   {name}")
    else:
        print(f"FAIL {name}" + (f": {detail}" if detail else ""), file=sys.stderr)
        failures.append(name)


# 1. Пин и вендор — одна версия. ⚠ Это ГЛАВНАЯ проверка файла: именно она закрывает то,
#    чего боялась #125 — «следующий бамп пина молча обнулит сверку». Красит CI СРАЗУ, не
#    дожидаясь сборки.
prov_commit = re.search(r"(?m)^commit:\s*([0-9a-f]{40})\s*$", prov)
pin_commit = re.search(r"(?m)^ARG BEE2EVP_COMMIT=([0-9a-f]{40})\s*$", dockerfile)
check("вендор и пин указывают на один коммит bee2evp",
      prov_commit is not None and pin_commit is not None
      and prov_commit.group(1) == pin_commit.group(1),
      f"PROVENANCE={prov_commit.group(1) if prov_commit else None}, "
      f"Dockerfile={pin_commit.group(1) if pin_commit else None}")

# 2. Коды наборов: 0xFF15–0xFF18 объявлены в патче и связаны с именами через btls.h.
#    Утверждение §6.4 было «коды сверены с таблицей патча» — вот эта сверка.
OURS = {
    "0x0300ff15": "BTLS1_TXT_DHE_BIGN_WITH_BELT_CTR_MAC_HBELT",
    "0x0300ff16": "BTLS1_TXT_DHE_BIGN_WITH_BELT_DWP_HBELT",
    "0x0300ff17": "BTLS1_TXT_DHT_BIGN_WITH_BELT_CTR_MAC_HBELT",
    "0x0300ff18": "BTLS1_TXT_DHT_BIGN_WITH_BELT_DWP_HBELT",
}
# Запись таблицы шифров в патче: имя TXT, имя RFC, затем код — подряд, через запятую.
entries = dict(
    (code, macro) for macro, code in
    re.findall(r"\+\s*(BTLS1_TXT_\w+),\s*\n\+\s*BTLS1_RFC_\w+,\s*\n\+\s*(0x0300ff[0-9a-f]{2}),",
               patch)
)
for code, macro in OURS.items():
    check(f"код {code} объявлен в патче и назван {macro.split('BTLS1_TXT_')[1]}",
          entries.get(code) == macro,
          f"в патче под этим кодом: {entries.get(code)}")

# 3. Код → строка набора → то, что изделие реально предлагает. Равенство множеств.
#    Односторонняя проверка пропустила бы набор, предлагаемый конфигом и не существующий
#    в патче, — то есть ровно ошибку, которую нечем заметить до живого рукопожатия.
def macro_value(macro):
    m = re.search(rf"#\s*define\s+{macro}\s*\\\s*\n\s*\"([^\"]+)\"", btls_h)
    return m.group(1) if m else None


from_patch = {macro_value(m) for m in OURS.values()}
tpl_nc = re.sub(r"#.*$", "", template, flags=re.M)
offered = re.search(r"proxy_ssl_ciphers\s+([^;]+);", tpl_nc)
from_conf = set(offered.group(1).split(":")) if offered else set()
check("наборы конфига и наборы патча — одно и то же множество",
      None not in from_patch and from_patch == from_conf,
      f"из патча: {sorted(x for x in from_patch if x)}; из конфига: {sorted(from_conf)}")

# 4. Утверждение §6.6: патч НЕ трогает механизм extended_master_secret и деривацию.
#    Проверяется отсутствием — а отсутствие доказывается только полным текстом, который
#    теперь в дереве и есть.
check("патч не трогает ssl/t1_enc.c (деривация мастер-ключа)",
      "t1_enc.c" not in patch, "файл упомянут в патче — утверждение §6.6 устарело")
ems_marks = [w for w in ("extended_master_secret", "extms", "session_hash", "EXTMS")
             if w in patch]
check("патч не трогает механизм extended_master_secret",
      not ems_marks, f"найдены упоминания: {ems_marks}")

# 5. Якоря §6.5 (A11, #90). Описание дефектов в документе верно ДЛЯ ЭТОЙ версии; починят
#    в апстриме — проверка покраснеет, и это правильно: документ придётся переписать.
#    ⚠ Проверка краснеет на УЛУЧШЕНИЕ апстрима, и это осознанно, а не недосмотр.
cke = re.search(r"int btls_construct_cke_bign_dht\(.*?\n\}", btls_c, re.S)
check("клиентская функция DHT найдена в btls.c", cke is not None)
if cke:
    body = cke.group(0)
    check("§6.5 верен: секрет освобождается без затирания (OPENSSL_free, не clear_free)",
          "OPENSSL_free(pms)" in body and "OPENSSL_clear_free(pms" not in body,
          "апстрим, похоже, починил — перечитать §6.5 и #138")
    ctx_line = re.search(r"pkey_ctx = EVP_PKEY_CTX_new\([^\n]*\n(.*?)if \(!EVP_PKEY_encrypt_init",
                         body, re.S)
    check("§6.5 верен: возврат EVP_PKEY_CTX_new не проверяется",
          ctx_line is not None and "pkey_ctx == NULL" not in ctx_line.group(1),
          "апстрим, похоже, починил — перечитать §6.5 и #138")


# 6. Субпротоколы Record и CCS (критерии 6.4.3 и 6.4.5). Оба метода — АНАЛИЗ ИСХОДНЫХ
#    ТЕКСТОВ, а не чёрный ящик: «эксперт проверяет, что порядковый номер seq_num
#    сбрасывается…», «эксперт проверяет, что после отправки ChangeCipherSpec каждая
#    из сторон поменяет старые параметры на новые». Значит и подтверждать их надо
#    текстом, а подтверждение обязано краснеть при смене пина.
check("патч не трогает слой Record — он стоковый",
      not re.search(r"(?m)^\+\+\+ b/ssl/record/", patch),
      "патч изменяет ssl/record/ — утверждение §6.6 о стоковом Record устарело")
check("патч не трогает субпротокол Change Cipher Spec",
      not re.search(r"change_cipher|\bCCS\b", patch),
      "патч упоминает смену параметров защиты — §6.6 требует перечитать")

# ⚠ Требование 6.4.3 к belt-ctr дословно: синхропосылка — «8 байтовый порядковый номер,
#   дополненный 8 нулевыми байтами». Вот две строки, которые его исполняют. Изменятся —
#   проверка покраснеет, и утверждение §6.6 придётся перечитать, а не унаследовать.
check("belt-ctr-tls строит синхропосылку как требует 6.4.3: seq_num ‖ нули",
      "memCopy(state->iv, state->aad, 8);" in belt_tls
      and "memSetZero(state->iv + 8, 8);" in belt_tls,
      "сборка синхропосылки belt-ctr изменилась")
check("belt-dwp-tls пишет явную синхропосылку и сверяет её с предыдущей",
      "ASSERT(!memEq(state->aad, state->iv + 8, 8));" in belt_tls,
      "исчезла проверка различия явных синхропосылок belt-dwp")

if failures:
    print(f"\nпровалено проверок: {len(failures)}", file=sys.stderr)
    sys.exit(1)
print("\nвендорённые копии BTLS согласованы с пином, конфигом и документом")
PY
