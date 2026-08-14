#!/usr/bin/env bash
# Offline self-check for the chain walk in scripts/by-ca-bundle.sh — no network, no bank.
#
# ЗАЧЕМ. Приём «искать УЦ ПО ХЕШАМ, а не по именам файлов» — это то, ради чего скрипт вообще
# стоило тащить в репозиторий, и одновременно то, что живёт в пути ДОВЕРИЯ: ошибка выбора даёт
# связку, которая проходит любую синтаксическую проверку и потом 502-ит 100% боевых запросов.
# Условия приёмки #48 требуют, чтобы у этого приёма была СВОЯ проверка: «проверка без мутации
# здесь неотличима от декоративной».
#
# ⚠ ПОЧЕМУ ЭТО РАБОТАЕТ БЕЗ БЕЛАРУСИ И БЕЗ bee2. Обход оперирует ТОЛЬКО `subject_hash` и
# `issuer_hash` — это хеши имён, а не подписей, и стоковый OpenSSL считает их на любых
# сертификатах (замер — ca/README.md). Значит цепочку можно построить из обычных RSA-фикстур,
# сгенерированных здесь же, и проверить логику, не имея ни ГосСУОК, ни банка.
#
# ⚠ ЧЕГО ЭТА ПРОВЕРКА НЕ ДЕЛАЕТ. Она не проверяет ни живое рукопожатие, ни то, что настоящие
# корни ГосСУОК подходят к настоящему банку, — это остаётся ручным прогоном по
# ca/README.md § «Как пересобрать». Она отвечает на один вопрос: выбирает ли обход звено по
# хешу, а не по имени файла, и говорит ли он вслух, когда выбор неоднозначен.
#
# Usage: bash scripts/check-bundle-walk.sh
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

WORK="$(mktemp -d "${TMPDIR:-/tmp}/check-bundle-walk.XXXXXXXX")" || exit 1
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
ok()   { printf 'ok   %s\n' "$1"; }
bad()  { printf 'FAIL %s: %s\n' "$1" "${2:-}" >&2; FAILURES=$((FAILURES+1)); }

command -v openssl >/dev/null || { echo "нет openssl" >&2; exit 1; }

# --- фикстуры ---------------------------------------------------------------------------
# Корень «Root CA» → промежуточный «Sub CA» → лист. Имена файлов подобраны ВРАЗРЕЗ с порядком
# цепочки: правильный промежуточный лежит в `z-sub.pem`, а посторонний — в `a-other.pem`.
# Отбор по имени (или «первый попавшийся») взял бы `a-other.pem`; отбор по хешу обязан взять
# `z-sub.pem`. Именно это различие проверка и ловит.
gen() {
  local dir="$1"
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=Walk Test Root CA' \
    -keyout "$dir/root.key" -out "$dir/root.pem" 2>/dev/null || return 1

  openssl req -new -newkey rsa:2048 -nodes -subj '/CN=Walk Test Sub CA' \
    -keyout "$dir/sub.key" -out "$dir/sub.csr" 2>/dev/null || return 1
  openssl x509 -req -in "$dir/sub.csr" -CA "$dir/root.pem" -CAkey "$dir/root.key" \
    -CAcreateserial -days 2 -extfile <(printf 'basicConstraints=CA:TRUE\n') \
    -out "$dir/z-sub.pem" 2>/dev/null || return 1

  openssl req -new -newkey rsa:2048 -nodes -subj '/CN=Walk Test Leaf' \
    -keyout "$dir/leaf.key" -out "$dir/leaf.csr" 2>/dev/null || return 1
  openssl x509 -req -in "$dir/leaf.csr" -CA "$dir/z-sub.pem" -CAkey "$dir/sub.key" \
    -CAcreateserial -days 2 -out "$dir/leaf.pem" 2>/dev/null || return 1

  # Посторонний УЦ с ДРУГИМ именем — он не должен попасть в связку вовсе.
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=Walk Test Other CA' \
    -keyout "$dir/other.key" -out "$dir/a-other.pem" 2>/dev/null || return 1
}

CAND="$WORK/candidates"
mkdir -p "$CAND"
gen "$WORK" || { echo "не удалось сгенерировать фикстуры" >&2; exit 1; }
cp "$WORK/root.pem" "$CAND/m-root.pem"
cp "$WORK/z-sub.pem" "$CAND/z-sub.pem"
cp "$WORK/a-other.pem" "$CAND/a-other.pem"

leaf_issuer_hash="$(openssl x509 -in "$WORK/leaf.pem" -noout -issuer_hash)"
sub_cn="Walk Test Sub CA"
root_cn="Walk Test Root CA"
other_cn="Walk Test Other CA"

run_walk() {
  bash scripts/by-ca-bundle.sh --no-live --out "$1" \
    --candidates-dir "$CAND" --issuer-hash "$leaf_issuer_hash" 2>&1
}

# --- 1. Обход находит звенья по хешу и замыкает цепочку -----------------------------------
OUT1="$WORK/run1"
out="$(run_walk "$OUT1")"
rc=$?
bundle="$OUT1/gossuok-bundle.pem"

if [[ $rc -eq 0 ]]; then
  ok "обход завершился успешно и вернул 0"
else
  bad "обход завершился успешно и вернул 0" "код возврата $rc"
fi

in_bundle() {
  # Сколько сертификатов с таким CN попало в связку.
  local cn="$1" n=0 p
  rm -f "$OUT1"/probe-*.pem
  awk -v d="$OUT1" 'BEGIN{c=0} /BEGIN CERT/{c++} c>0 {print > (d "/probe-" c ".pem")}' "$bundle" 2>/dev/null
  for p in "$OUT1"/probe-*.pem; do
    [[ -s "$p" ]] || continue
    openssl x509 -in "$p" -noout -subject 2>/dev/null | grep -q "$cn" && n=$((n+1))
  done
  echo "$n"
}

if [[ "$(in_bundle "$sub_cn")" -eq 1 ]]; then
  ok "нужный промежуточный попал в связку"
else
  bad "нужный промежуточный попал в связку" "в связке нет '$sub_cn'"
fi

if [[ "$(in_bundle "$root_cn")" -eq 1 ]]; then
  ok "обход поднялся до самоподписанного корня и замкнул цепочку"
else
  bad "обход дошёл до корня" "в связке нет '$root_cn'"
fi

if [[ "$(in_bundle "$other_cn")" -eq 0 ]]; then
  ok "звено выбрано ПО ХЕШУ, а не по имени файла: посторонний УЦ отвергнут"
else
  bad "звено выбрано по хешу, а не по имени файла" "посторонний '$other_cn' попал в связку — отбор идёт не по хешу"
fi

if grep -q 'ветвь замкнута на корне' <<<"$out"; then
  ok "замыкание на самоподписанном корне названо в выводе"
else
  bad "замыкание на корне названо в выводе" "нет строки про самоподписанный корень"
fi

# --- 2. Незамкнутая цепочка краснеет и кодом, и текстом -----------------------------------
# ⚠ Это тот отказ, ради которого проверка и существует: обрезанная связка синтаксически
# безупречна и ломается только на живом рукопожатии, далеко от причины.
CAND_BROKEN="$WORK/candidates-broken"
mkdir -p "$CAND_BROKEN"
cp "$CAND/z-sub.pem" "$CAND_BROKEN/"   # промежуточный есть, корня НЕТ
OUT2="$WORK/run2"
out2="$(bash scripts/by-ca-bundle.sh --no-live --out "$OUT2" \
  --candidates-dir "$CAND_BROKEN" --issuer-hash "$leaf_issuer_hash" 2>&1)"
rc2=$?
if [[ $rc2 -eq 3 ]]; then
  ok "незамкнутая цепочка возвращает 3, а не 0"
else
  bad "незамкнутая цепочка возвращает 3" "код возврата $rc2"
fi
if grep -q 'ЦЕПОЧКА НЕ ЗАМКНУТА' <<<"$out2"; then
  ok "незамкнутая цепочка названа в выводе"
else
  bad "незамкнутая цепочка названа в выводе" "нет предупреждения"
fi

# --- 3. Одинаковый subject_hash у РАЗНЫХ сертификатов — сказано вслух ----------------------
# ⚠ Проверено запуском 14.08.2026: ruc.cer и ruc2.cer у nces.by дают один subject_hash. Сегодня
# это один и тот же сертификат под двумя именами, но при перевыпуске УЦ с прежним именем и
# новым ключом «первый попавшийся» стал бы лотереей в пути доверия.
CAND_DUP="$WORK/candidates-dup"
mkdir -p "$CAND_DUP"
cp "$CAND"/*.pem "$CAND_DUP/"
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$sub_cn" \
  -keyout "$WORK/sub2.key" -out "$WORK/sub2.csr" 2>/dev/null
openssl x509 -req -in "$WORK/sub2.csr" -CA "$WORK/root.pem" -CAkey "$WORK/root.key" \
  -CAcreateserial -days 2 -extfile <(printf 'basicConstraints=CA:TRUE\n') \
  -out "$CAND_DUP/b-sub-regen.pem" 2>/dev/null
OUT3="$WORK/run3"
out3="$(bash scripts/by-ca-bundle.sh --no-live --out "$OUT3" \
  --candidates-dir "$CAND_DUP" --issuer-hash "$leaf_issuer_hash" 2>&1)"
if grep -q 'РАЗНЫЕ сертификаты' <<<"$out3"; then
  ok "неоднозначность (один subject_hash, разные сертификаты) названа вслух"
else
  bad "неоднозначность названа вслух" "скрипт выбрал молча"
fi

# --- 4. Один сертификат под ДВУМЯ именами — дедуп по отпечатку, без ложной тревоги --------
# ⚠ Ровно случай ruc.cer / ruc2.cer у nces.by: побайтово один сертификат, опубликованный
# дважды. Ревью показало, что без этой фикстуры снятие дедупа проходит незамеченным: связка
# остаётся рабочей, но скрипт начинает кричать «РАЗНЫЕ сертификаты» на каждой легитимной
# паре — и обесценивает то самое предупреждение, которому оператор обязан верить.
CAND_TWIN="$WORK/candidates-twin"
mkdir -p "$CAND_TWIN"
cp "$CAND/m-root.pem" "$CAND_TWIN/"
cp "$CAND/z-sub.pem" "$CAND_TWIN/z-sub.pem"
cp "$CAND/z-sub.pem" "$CAND_TWIN/a-sub-copy.pem"   # тот же файл под «ранним» именем
OUT4="$WORK/run4"
out4="$(bash scripts/by-ca-bundle.sh --no-live --out "$OUT4" \
  --candidates-dir "$CAND_TWIN" --issuer-hash "$leaf_issuer_hash" 2>&1)"
rc4=$?
if grep -q 'РАЗНЫЕ сертификаты' <<<"$out4"; then
  bad "дубль под двумя именами не считается разными сертификатами" "ложная тревога: дедуп по отпечатку не сработал"
else
  ok "дубль под двумя именами схлопнут по отпечатку, ложной тревоги нет"
fi
twin_count="$(grep -c 'BEGIN CERTIFICATE' "$OUT4/gossuok-bundle.pem" 2>/dev/null || echo 0)"
if [[ "$twin_count" -eq 2 ]]; then
  ok "дубль попал в связку один раз (2 сертификата: промежуточный и корень)"
else
  bad "дубль попал в связку один раз" "в связке $twin_count сертификатов вместо 2"
fi
if [[ $rc4 -eq 0 ]]; then
  ok "цепочка с дублем замкнута и вернула 0"
else
  bad "цепочка с дублем замкнута" "код возврата $rc4"
fi

# --- 5. Две ветви с РАЗНЫМИ корнями: замкнутой считается только полная цепочка -------------
# ⚠ Самый дорогой случай, и прежняя редакция обхода его проваливала: два сертификата с одним
# subject_hash, подписанные разными корнями, при том что в кандидатах есть корень только
# одной ветви. Обход шёл по первой ветви, упирался в её корень и рапортовал «замкнута» с
# кодом 0 — а связки для той ветви, что реально подписала лист, в ней не было. В бою это
# `unable to get local issuer` и 502.
CAND_FORK="$WORK/candidates-fork"
mkdir -p "$CAND_FORK"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj '/CN=Walk Test Root B' \
  -keyout "$WORK/rootb.key" -out "$WORK/rootb.pem" 2>/dev/null
openssl req -new -newkey rsa:2048 -nodes -subj "/CN=$sub_cn" \
  -keyout "$WORK/subb.key" -out "$WORK/subb.csr" 2>/dev/null
openssl x509 -req -in "$WORK/subb.csr" -CA "$WORK/rootb.pem" -CAkey "$WORK/rootb.key" \
  -CAcreateserial -days 2 -extfile <(printf 'basicConstraints=CA:TRUE\n') \
  -out "$CAND_FORK/z-sub-b.pem" 2>/dev/null
cp "$CAND/z-sub.pem" "$CAND_FORK/a-sub-a.pem"   # ветвь A — её корень в кандидатах ЕСТЬ
cp "$CAND/m-root.pem" "$CAND_FORK/m-root.pem"   # корень ветви B НЕ кладём
OUT5="$WORK/run5"
out5="$(bash scripts/by-ca-bundle.sh --no-live --out "$OUT5" \
  --candidates-dir "$CAND_FORK" --issuer-hash "$leaf_issuer_hash" 2>&1)"
rc5=$?
if [[ $rc5 -eq 3 ]]; then
  ok "ветвь без своего корня не считается замкнутой (код 3)"
else
  bad "ветвь без своего корня не считается замкнутой" "код возврата $rc5 — обход поверил первой ветви"
fi
if grep -q 'ветвь не закрыта' <<<"$out5"; then
  ok "незакрытая ветвь названа вслух"
else
  bad "незакрытая ветвь названа вслух" "скрипт не сказал, какая ветвь оборвалась"
fi

echo
if [[ $FAILURES -eq 0 ]]; then
  echo "обход цепочки: все проверки пройдены"
  exit 0
fi
echo "обход цепочки: провалено $FAILURES" >&2
exit 1
