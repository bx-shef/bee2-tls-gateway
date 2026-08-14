#!/usr/bin/env bash
# Build the ГосСУОК trust bundle that VERIFIES a bank's production server certificate, and
# check the result against the live host. Produces the artefact shipped as ca/gossuok-bundle.pem.
#
# ЗАЧЕМ ОН ЗДЕСЬ. Он производит то, что мы возим в образе. Держать производителя артефакта в
# одном репозитории, а сам артефакт в другом — разрыв, который уже дал битую ссылку в
# ca/README.md ([#48](https://github.com/bx-shef/bee2-tls-gateway/issues/48)).
#
# ⚠ ЭТО НЕ КЛИЕНТСКИЙ СЕРТИФИКАТ И НЕ РАБОТА С КЛЮЧОМ. Ни ключа ГосСУОК, ни носителя, ни
# пароля: здесь только ПУБЛИЧНЫЕ сертификаты удостоверяющих центров, которыми проверяется
# банк. Оговорка сохранена при переносе намеренно — она снимает вопрос «а не нужен ли токен».
#
# ⚠ ЗАПУСКАТЬ ИЗ БЕЛАРУСИ (с деплой-сервера). `nces.by` отдаёт 503 зарубежному трафику,
# порт 9345 из CI недостижим. Свойство задачи, а не репозитория: в CI этот скрипт не поставить.
#
# ⚠ РЕЗУЛЬТАТ НЕ ПОДСТАВЛЯЕТСЯ В ca/ АВТОМАТИЧЕСКИ, и это не забывчивость. Подменивший ответ
# `nces.by` подменит корень доверия; кандидат едет в ca/ руками, после сверки по порядку из
# docs/PROCESS.md §4 «Замена связки ГосСУОК».
#
# Usage: bash scripts/by-ca-bundle.sh [--out DIR] [--host HOST] [--port PORT] [--openssl PATH]
#   --openssl  путь к пропатченному openssl (по умолчанию — собранный bee2evp-probe.sh)
set -uo pipefail

OUT="${TMPDIR:-/tmp}/by-ca"
HOST="apibel.priorbank.by"
PORT="9345"
OSSL=""
PROBE_WORK="${TMPDIR:-/tmp}/bee2evp-probe"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="${2:?--out требует пути}"; shift ;;
    --host) HOST="${2:?--host требует значения}"; shift ;;
    --port) PORT="${2:?--port требует значения}"; shift ;;
    --openssl) OSSL="${2:?--openssl требует пути}"; shift ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
  shift
done

say() { printf '\n=== %s ===\n' "$1"; }

# Пропатченная сборка нужна ТОЛЬКО чтобы поговорить с банком (шаги 1 и 5). Разбор
# сертификатов, хеши и сроки ниже считает и стоковый OpenSSL — см. таблицу замеров в
# ca/README.md § «Что обычным OpenSSL можно, а что нельзя». Поэтому её отсутствие не фатально
# до живой проверки: связку собрать можно, подтвердить её — нет.
if [[ -z "$OSSL" ]]; then
  OSSL="$(find "$PROBE_WORK" -type f -name openssl -perm -u+x 2>/dev/null | grep -E '/local/bin/openssl$' | head -1)"
fi
if [[ -n "$OSSL" && -x "$OSSL" ]]; then
  LIBDIR="$(dirname "$(dirname "$OSSL")")/lib"
  PATCHED=1
else
  OSSL="$(command -v openssl)"; LIBDIR=""; PATCHED=0
fi
ossl() { LD_LIBRARY_PATH="${LIBDIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$OSSL" "$@"; }

# `-nameopt utf8,-esc_msb` — без него OpenSSL печатает кириллицу как \D0\9A, а весь смысл
# вывода в том, чтобы человек ВИДЕЛ, какому УЦ принадлежит файл.
name_of() { ossl x509 -in "$1" -inform "${2:-PEM}" -noout -subject -nameopt utf8,-esc_msb,sep_comma_plus_space 2>/dev/null; }
# Только CN. Резать UTF-8 по байтам (`cut -c1-90`) — получить кракозябры на середине символа;
# измерено на живом прогоне. CN и так короткий, обрезать его незачем.
cn_of() { name_of "$1" "${2:-PEM}" | grep -oE 'CN *= *[^,]+' | head -1 | sed 's/CN *= *//'; }

mkdir -p "$OUT" || { echo "не могу создать $OUT" >&2; exit 1; }

say "1. Сертификат сервера ${HOST}:${PORT} — кто его издатель"
leaf="$OUT/leaf.pem"
if [[ $PATCHED -eq 1 ]]; then
  timeout 40 env LD_LIBRARY_PATH="$LIBDIR" "$OSSL" s_client -connect "${HOST}:${PORT}" \
    -servername "$HOST" -showcerts </dev/null 2>/dev/null \
    | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "$leaf"
fi
if [[ ! -s "$leaf" ]]; then
  echo "не удалось забрать сертификат сервера."
  [[ $PATCHED -eq 0 ]] && echo "  причина: не найден пропатченный openssl — сначала прогоните scripts/bee2evp-probe.sh"
  echo "  (без него дальше можно только собрать связку, но не проверить её)"
else
  echo "  subject: $(ossl x509 -in "$leaf" -noout -subject -nameopt utf8,-esc_msb,sep_comma_plus_space | sed 's/^subject=//')"
  echo "  issuer : $(ossl x509 -in "$leaf" -noout -issuer  -nameopt utf8,-esc_msb,sep_comma_plus_space | sed 's/^issuer=//')"
  want_hash="$(ossl x509 -in "$leaf" -noout -issuer_hash 2>/dev/null)"
  echo "  ищем УЦ с subject_hash = $want_hash"
fi

say "2. Скачиваю кандидатов из ГосСУОК (nces.by)"
# Список кандидатов повторяет то, что тянет TrustFirmware у AvTunProxy (docs/PROCESS.md §2.1):
# ruc* — Республиканский УЦ (промежуточный), kuc* — Корневой УЦ. Поколения сосуществуют,
# поэтому качаем все и выбираем по хешу, а не гадаем, какое из них текущее.
BASE="https://nces.by/wp-content/uploads/certificates/pki"
CANDIDATES=(ruc.cer ruc2.cer ruc3.cer kuc1.cer kuc2.cer)
got=0
for f in "${CANDIDATES[@]}"; do
  printf '  %-10s ' "$f"
  if timeout 60 curl -sS -fL -o "$OUT/$f" "$BASE/$f" 2>/dev/null && [[ -s "$OUT/$f" ]]; then
    # Файлы публикуются в DER; приводим к PEM, чтобы дальше всё было однородно.
    if ossl x509 -inform DER -in "$OUT/$f" -out "$OUT/${f%.cer}.pem" 2>/dev/null \
       || ossl x509 -inform PEM -in "$OUT/$f" -out "$OUT/${f%.cer}.pem" 2>/dev/null; then
      got=$((got+1))
      echo "ok — $(cn_of "$OUT/${f%.cer}.pem")"
    else
      echo "скачан, но это не сертификат"
    fi
  else
    echo "НЕ СКАЧАЛСЯ"
  fi
done
if [[ $got -eq 0 ]]; then
  echo
  echo "Ни один файл не скачался. Если вы ВНЕ Беларуси — так и будет: nces.by отдаёт 503 чужому"
  echo "трафику. Запускайте с деплой-сервера."
  exit 1
fi

say "3. Собираю цепочку: промежуточный (РУЦ) → корень (КУЦ)"
# ⚠ ПРИЁМ, КОТОРЫЙ ОБЯЗАН БЫЛ ПЕРЕЖИТЬ ПЕРЕНОС: идём вверх ПО ХЕШАМ, а не по именам файлов.
# `ruc3.cer` не обязан быть текущим издателем, и ошибка выбора вылезла бы только на живой
# проверке — далеко от причины. Тот же обход отработает, если банк сменит УЦ целиком.
bundle="$OUT/gossuok-bundle.pem"
: > "$bundle"
chain_ok=0
if [[ -n "${want_hash:-}" ]]; then
  cur="$want_hash"
  for _ in 1 2 3 4; do
    found=""
    for p in "$OUT"/*.pem; do
      [[ "$p" == "$leaf" ]] && continue
      [[ "$(ossl x509 -in "$p" -noout -subject_hash 2>/dev/null)" == "$cur" ]] && { found="$p"; break; }
    done
    [[ -z "$found" ]] && { echo "  не нашёл сертификат с subject_hash=$cur среди скачанных"; break; }
    echo "  + $(basename "$found") — $(cn_of "$found")"
    cat "$found" >> "$bundle"
    sub="$(ossl x509 -in "$found" -noout -subject_hash)"
    iss="$(ossl x509 -in "$found" -noout -issuer_hash)"
    [[ "$sub" == "$iss" ]] && { echo "  (самоподписанный — это корень, цепочка замкнута)"; chain_ok=1; break; }
    cur="$iss"
  done
else
  echo "  сертификат сервера не получен — кладу в связку всё скачанное (менее точно, но рабочее)"
  cat "$OUT"/*.pem > "$bundle" 2>/dev/null
fi

say "4. Что вошло в связку и до каких пор оно живёт"
# Разбираем и смотрим КАЖДЫЙ сертификат отдельно. `pkcs7 -print_certs` по связке целиком здесь
# не печатает ничего: ключи на bign (СТБ 34.101.45), и этот путь вывода об них спотыкается.
# Измерено на живой связке, а не предположено.
rm -f "$OUT"/split-*.pem
awk -v d="$OUT" 'BEGIN{c=0} /BEGIN CERT/{c++} c>0 {print > (d "/split-" c ".pem")}' "$bundle" 2>/dev/null
for p in "$OUT"/split-*.pem; do
  [[ -s "$p" ]] || continue
  nd="$(ossl x509 -in "$p" -noout -enddate 2>/dev/null | sed 's/notAfter=//')"
  echo "  $(cn_of "$p")"
  echo "      издатель: $(ossl x509 -in "$p" -noout -issuer -nameopt utf8,-esc_msb,sep_comma_plus_space 2>/dev/null | grep -oE 'CN *= *[^,]+' | sed 's/CN *= *//')"
  echo "      действует до: ${nd:-?}"
done
echo
echo "  файл:   $bundle"
echo "  sha256: $(sha256sum "$bundle" | cut -d' ' -f1)"
echo
# Обход выше кончается либо самоподписанным корнем, либо нехваткой звена — и оба пути
# приходят сюда с одинаковой сводкой «вот ваш файл». Говорим, что именно случилось: обрезанная
# связка проходит любую синтаксическую проверку и потом 502-ит 100% боевых запросов. Без
# пропатченного openssl шаг 5 пропускается, и эта строка — ЕДИНСТВЕННОЕ предупреждение.
if [[ $chain_ok -ne 1 ]]; then
  echo "  ⚠ ЦЕПОЧКА НЕ ЗАМКНУТА: обход не дошёл до самоподписанного корня. Связка СОБРАНА ЧАСТИЧНО —"
  echo "    в ней не хватает звена, и проверка сертификата банка с ней не пройдёт. Вероятная причина:"
  echo "    УЦ опубликовал новый промежуточный сертификат, которого нет в списке CANDIDATES выше."
  echo
fi
# ⚠ ЗДЕСЬ ПРИ ПЕРЕНОСЕ ИСПРАВЛЕНА ОШИБКА ИСХОДНИКА. Он предупреждал, что эти сертификаты
# «не читаются обычным openssl» и любая обвязка обязана быть пропатченной. Это преувеличение,
# и его опровергает собственный код скрипта: шаги 2–4 выше считают имена, хеши и сроки
# стоковым OpenSSL. Замер — ca/README.md: subject/issuer/enddate и *_hash работают, падают
# только `-pubkey` и `verify`. Практическое следствие обратное прежнему: мониторингу сроков
# (scripts/check-ca.sh) патченый стек НЕ нужен, и тащить криптотулчейн в крон не придётся.
echo "  ⚠ Проверить ПОДПИСЬ этой связкой можно только пропатченной сборкой (ключи на bign):"
echo "    'openssl verify' и рукопожатие. Имена, хеши и сроки читает и обычный OpenSSL —"
echo "    таблица замеров в ca/README.md."

say "5. Живая проверка"
if [[ $PATCHED -eq 1 && -s "$bundle" ]]; then
  out="$(timeout 40 env LD_LIBRARY_PATH="$LIBDIR" "$OSSL" s_client -connect "${HOST}:${PORT}" \
    -servername "$HOST" -CAfile "$bundle" </dev/null 2>&1)"
  grep -E "Cipher is|Verify return code" <<<"$out" | sed 's/^/  /'
  if grep -q "Verify return code: 0 (ok)" <<<"$out"; then
    echo
    echo "✅ СЕРТИФИКАТ БАНКА ПРОВЕРЕН. Канал шифруется И собеседник подтверждён."
    echo "   Кандидат: $bundle — сверьте и положите в ca/ РУКАМИ (docs/PROCESS.md §4)."
  else
    echo
    echo "❌ Проверка не прошла. Смотрите строку выше."
    echo "   Если 'unable to get local issuer' — в связке не хватает звена: проверьте раздел 3."
  fi
else
  echo "  пропущено: нет пропатченного openssl (см. scripts/bee2evp-probe.sh) или пустая связка"
fi
