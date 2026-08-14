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
# ⚠ ЖИВАЯ ЧАСТЬ ТРЕБУЕТ ДОСТУПА К БАНКУ (шаги 1 и 5): порт 9345 из CI недостижим. Загрузка
# корней с nces.by исторически отдавала 503 зарубежному трафику, но 14.08.2026 из зарубежной
# песочницы вернула 200 — то есть на геоблокировку полагаться нельзя ни в одну сторону:
# сработает — хорошо, не сработает — запускайте с деплой-сервера.
#
# ⚠ РЕЗУЛЬТАТ НЕ ПОДСТАВЛЯЕТСЯ В ca/ АВТОМАТИЧЕСКИ, и это не забывчивость. Подменивший ответ
# `nces.by` подменит корень доверия; кандидат едет в ca/ руками, после сверки по порядку из
# docs/PROCESS.md §4 «Замена связки ГосСУОК».
#
# Usage: bash scripts/by-ca-bundle.sh [--out DIR] [--host HOST] [--port PORT] [--openssl PATH]
#                                     [--candidates-dir DIR] [--issuer-hash HASH] [--no-live]
#   --openssl          путь к пропатченному openssl (по умолчанию — собранный bee2evp-probe.sh)
#   --candidates-dir   не качать, взять сертификаты УЦ из каталога (офлайн-прогон)
#   --issuer-hash      считать это subject_hash искомого издателя (офлайн-прогон, без банка)
#   --no-live          пропустить шаги, требующие банка
#
# Коды возврата: 0 — связка собрана И (если проверялась) подтверждена; 1 — не собрана;
# 2 — ошибка вызова; 3 — собрана, но цепочка не замкнута или живая проверка не прошла.
set -uo pipefail

OUT=""
HOST="apibel.priorbank.by"
PORT="9345"
DEFAULT_HOST="apibel.priorbank.by"
OSSL=""
OSSL_EXPLICIT=0
CAND_DIR=""
NO_LIVE=0
want_hash=""
PROBE_WORK="${TMPDIR:-/tmp}/bee2evp-probe"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="${2:?--out требует пути}"; shift ;;
    --host) HOST="${2:?--host требует значения}"; shift ;;
    --port) PORT="${2:?--port требует значения}"; shift ;;
    --openssl) OSSL="${2:?--openssl требует пути}"; OSSL_EXPLICIT=1; shift ;;
    --candidates-dir) CAND_DIR="${2:?--candidates-dir требует пути}"; shift ;;
    --issuer-hash) want_hash="${2:?--issuer-hash требует значения}"; shift ;;
    --no-live) NO_LIVE=1 ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
  shift
done

say() { printf '\n=== %s ===\n' "$1"; }

say "0. Предусловия"
# ⚠ БЕЗ ЭТОГО ШАГА ОТСУТСТВИЕ curl ЧИТАЛОСЬ КАК ГЕОБЛОКИРОВКА. Все загрузки падали, счётчик
# оставался нулевым, и скрипт уверенно печатал «вы вне Беларуси» — диагноз, уводящий от
# настоящей причины в противоположную сторону.
missing=""
for c in openssl curl sha256sum awk; do
  command -v "$c" >/dev/null || missing="$missing $c"
done
if [[ -n "$missing" ]]; then
  echo "НЕ ХВАТАЕТ:$missing"
  echo "Debian/Ubuntu:  sudo apt-get install -y openssl curl coreutils gawk"
  exit 1
fi
echo "всё на месте"

if [[ "$HOST" != "$DEFAULT_HOST" ]]; then
  echo "⚠ нестандартный адрес ($HOST) — результат НЕ для ca/, это разведка чужого хоста"
fi

# ⚠ КАТАЛОГ ОДНОРАЗОВЫЙ, А НЕ ФИКСИРОВАННЫЙ. Прежняя редакция писала в /tmp/by-ca и ничего
# оттуда не удаляла. Два следствия, оба находили ревью: (1) leaf.pem от прошлого прогона
# делал проверку `[[ ! -s ]]` ложной, и скрипт печатал ВЧЕРАШНИЙ сертификат так, будто
# только что сходил в банк; (2) фиксированное имя в общем /tmp — это и коллизия двух
# операторов, и symlink, подложенный третьим.
if [[ -z "$OUT" ]]; then
  OUT="$(mktemp -d "${TMPDIR:-/tmp}/by-ca.XXXXXXXX")" || { echo "не могу создать временный каталог" >&2; exit 1; }
else
  mkdir -p "$OUT" || { echo "не могу создать $OUT" >&2; exit 1; }
  # Явно заданный каталог чистим от артефактов прошлого прогона по той же причине.
  rm -f "$OUT"/*.pem "$OUT"/*.cer
fi
chmod 700 "$OUT" 2>/dev/null || true
echo "рабочий каталог: $OUT"

# Пропатченная сборка нужна ТОЛЬКО чтобы поговорить с банком (шаги 1 и 5). Разбор
# сертификатов, хеши и сроки ниже считает и стоковый OpenSSL — см. таблицу замеров в
# ca/README.md § «Что обычным OpenSSL можно, а что нельзя».
if [[ $OSSL_EXPLICIT -eq 1 ]]; then
  # ⚠ Явно заданный путь НЕ молчит при опечатке. Прежде он тихо игнорировался, включался
  # стоковый openssl, и совет «сначала прогоните bee2evp-probe.sh» уводил от причины.
  if [[ ! -x "$OSSL" ]]; then
    echo "--openssl: файл не найден или не исполняем: $OSSL" >&2
    exit 2
  fi
  LIBDIR="$(dirname "$(dirname "$OSSL")")/lib"
  [[ -d "$LIBDIR" ]] || LIBDIR="$(dirname "$(dirname "$OSSL")")"
  PATCHED=1
else
  # ⚠ АВТОПОИСК ОГРАНИЧЕН СВОИМ КАТАЛОГОМ И ПРОВЕРЯЕТ ВЛАДЕЛЬЦА. Мы собираемся ИСПОЛНИТЬ
  # найденное, а путь предсказуем: без проверки владельца любой локальный пользователь мог
  # подложить туда бинарь, печатающий «✅ СЕРТИФИКАТ БАНКА ПРОВЕРЕН».
  found="$(find "$PROBE_WORK" -type f -name openssl -perm -u+x -user "$(id -u)" 2>/dev/null | grep -E '/local/bin/openssl$' | head -1)"
  if [[ -n "$found" ]]; then
    OSSL="$found"
    LIBDIR="$(dirname "$(dirname "$OSSL")")/lib"
    [[ -d "$LIBDIR" ]] || LIBDIR="$(dirname "$(dirname "$OSSL")")"
    PATCHED=1
  else
    OSSL="$(command -v openssl)"; LIBDIR=""; PATCHED=0
  fi
fi
# ⚠ Пустой LIBDIR давал ведущее двоеточие в LD_LIBRARY_PATH, а пустой элемент там означает
# ТЕКУЩИЙ КАТАЛОГ в путях поиска библиотек.
if [[ -n "$LIBDIR" ]]; then
  ossl() { LD_LIBRARY_PATH="${LIBDIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$OSSL" "$@"; }
else
  ossl() { "$OSSL" "$@"; }
fi

# `-nameopt utf8,-esc_msb` — без него OpenSSL печатает кириллицу как \D0\9A, а весь смысл
# вывода в том, чтобы человек ВИДЕЛ, какому УЦ принадлежит файл.
name_of() { ossl x509 -in "$1" -inform "${2:-PEM}" -noout -subject -nameopt utf8,-esc_msb,sep_comma_plus_space 2>/dev/null; }
# Только CN. Резать UTF-8 по байтам (`cut -c1-90`) — получить кракозябры на середине символа;
# измерено на живом прогоне. CN и так короткий, обрезать его незачем.
cn_of() { name_of "$1" "${2:-PEM}" | grep -oE 'CN *= *[^,]+' | head -1 | sed 's/CN *= *//'; }
fp_of() { ossl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//'; }

leaf="$OUT/leaf.pem"
if [[ $NO_LIVE -eq 1 || -n "$want_hash" ]]; then
  say "1. Сертификат сервера — пропущено (офлайн-режим)"
  [[ -n "$want_hash" ]] && echo "  ищем УЦ с subject_hash = $want_hash (задан аргументом)"
else
  say "1. Сертификат сервера ${HOST}:${PORT} — кто его издатель"
  if [[ $PATCHED -eq 1 ]]; then
    timeout 40 env LD_LIBRARY_PATH="${LIBDIR}" "$OSSL" s_client -connect "${HOST}:${PORT}" \
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
fi

if [[ -n "$CAND_DIR" ]]; then
  say "2. Кандидаты из каталога $CAND_DIR (без сети)"
  got=0
  for src in "$CAND_DIR"/*; do
    [[ -f "$src" ]] || continue
    base="$(basename "$src")"
    printf '  %-14s ' "$base"
    if ossl x509 -inform DER -in "$src" -out "$OUT/${base%.*}.pem" 2>/dev/null \
       || ossl x509 -inform PEM -in "$src" -out "$OUT/${base%.*}.pem" 2>/dev/null; then
      got=$((got+1)); echo "ok — $(cn_of "$OUT/${base%.*}.pem")"
    else
      echo "не сертификат — пропущен"
    fi
  done
else
  say "2. Скачиваю кандидатов из ГосСУОК (nces.by)"
  # Список кандидатов повторяет то, что тянет TrustFirmware у AvTunProxy (docs/PROCESS.md §2.1):
  # ruc* — Республиканский УЦ (промежуточный), kuc* — Корневой УЦ. Поколения сосуществуют,
  # поэтому качаем все и выбираем по хешу, а не гадаем, какое из них текущее.
  BASE="https://nces.by/wp-content/uploads/certificates/pki"
  CANDIDATES=(ruc.cer ruc2.cer ruc3.cer kuc1.cer kuc2.cer)
  got=0
  for f in "${CANDIDATES[@]}"; do
    printf '  %-10s ' "$f"
    # ⚠ --proto/--proto-redir ЗАПРЕЩАЮТ УХОД С HTTPS. Мы качаем корень доверия: редирект на
    # http:// (свой или подставленный) отдал бы его по открытому каналу. Стандартный `-L`
    # такого ограничения не несёт. Стдерр curl больше не гасится: `-sS` для того и стоит.
    if timeout 60 curl -sS -fL --proto '=https' --proto-redir '=https' \
         -o "$OUT/$f" "$BASE/$f" && [[ -s "$OUT/$f" ]]; then
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
fi
if [[ $got -eq 0 ]]; then
  echo
  echo "Ни одного сертификата не получено. Если качали с nces.by — возможна геоблокировка"
  echo "(исторически 503 зарубежному трафику); запускайте с деплой-сервера."
  exit 1
fi

say "3. Собираю цепочку: промежуточный (РУЦ) → корень (КУЦ)"
# ⚠ ПРИЁМ, КОТОРЫЙ ОБЯЗАН БЫЛ ПЕРЕЖИТЬ ПЕРЕНОС: идём вверх ПО ХЕШАМ, а не по именам файлов.
# `ruc3.cer` не обязан быть текущим издателем, и ошибка выбора вылезла бы только на живой
# проверке — далеко от причины. Тот же обход отработает, если банк сменит УЦ целиком.
#
# ⚠ НО ХЕШ SUBJECT НЕ УНИКАЛЕН, и это нашло ревью. Проверено запуском 14.08.2026: `ruc.cer` и
# `ruc2.cer` дают ОДИН И ТОТ ЖЕ `subject_hash` (271df61f) — сегодня безобидно, потому что это
# побайтово один сертификат под двумя именами. Станет опасно при перевыпуске УЦ с прежним
# именем и новым ключом: «первый попавшийся с таким subject» — это уже лотерея. Поэтому
# кандидаты с совпавшим хешем СРАВНИВАЮТСЯ ПО ОТПЕЧАТКУ: одинаковые — берём один, разные —
# кладём все и говорим об этом вслух (лишний корень проверке не мешает, а молчаливый выбор
# не того — мешает).
bundle="$OUT/gossuok-bundle.pem"
: > "$bundle"
chain_ok=0
ambiguous=0
if [[ -n "$want_hash" ]]; then
  cur="$want_hash"
  for _ in 1 2 3 4; do
    matches=()
    for p in "$OUT"/*.pem; do
      [[ "$p" == "$leaf" || "$p" == "$bundle" ]] && continue
      [[ "$(ossl x509 -in "$p" -noout -subject_hash 2>/dev/null)" == "$cur" ]] && matches+=("$p")
    done
    [[ ${#matches[@]} -eq 0 ]] && { echo "  не нашёл сертификат с subject_hash=$cur среди кандидатов"; break; }

    uniq_fp=()
    uniq_file=()
    for m in "${matches[@]}"; do
      fp="$(fp_of "$m")"
      dup=0
      for seen in "${uniq_fp[@]:-}"; do [[ "$seen" == "$fp" ]] && dup=1 && break; done
      [[ $dup -eq 0 ]] && { uniq_fp+=("$fp"); uniq_file+=("$m"); }
    done

    if [[ ${#uniq_file[@]} -gt 1 ]]; then
      ambiguous=1
      echo "  ⚠ subject_hash=$cur дали ${#matches[@]} файла, и это РАЗНЫЕ сертификаты:"
      for m in "${uniq_file[@]}"; do echo "      $(basename "$m") — $(cn_of "$m"), до $(ossl x509 -in "$m" -noout -enddate | sed 's/notAfter=//')"; done
      echo "    Кладу в связку все: выбрать молча означало бы угадывать поколение УЦ."
      for m in "${uniq_file[@]}"; do cat "$m" >> "$bundle"; done
    else
      echo "  + $(basename "${uniq_file[0]}") — $(cn_of "${uniq_file[0]}")"
      cat "${uniq_file[0]}" >> "$bundle"
    fi

    first="${uniq_file[0]}"
    sub="$(ossl x509 -in "$first" -noout -subject_hash)"
    iss="$(ossl x509 -in "$first" -noout -issuer_hash)"
    [[ "$sub" == "$iss" ]] && { echo "  (самоподписанный — это корень, цепочка замкнута)"; chain_ok=1; break; }
    cur="$iss"
  done
else
  echo "  издатель неизвестен — кладу в связку всё полученное (менее точно, но рабочее)"
  cat "$OUT"/*.pem > "$bundle" 2>/dev/null
fi

say "4. Что вошло в связку и до каких пор оно живёт"
# Разбираем и смотрим КАЖДЫЙ сертификат отдельно. `pkcs7 -print_certs` по связке целиком здесь
# не печатает ничего: ключи на bign (СТБ 34.101.45), и этот путь вывода об них спотыкается.
# Измерено на живой связке ещё в исходной редакции скрипта, а не предположено.
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
  echo "    УЦ опубликовал новый промежуточный сертификат, которого нет в списке кандидатов."
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

live_ok=-1
say "5. Живая проверка"
if [[ $NO_LIVE -eq 1 ]]; then
  echo "  пропущено: --no-live"
elif [[ $PATCHED -eq 1 && -s "$bundle" ]]; then
  out="$(timeout 40 env LD_LIBRARY_PATH="${LIBDIR}" "$OSSL" s_client -connect "${HOST}:${PORT}" \
    -servername "$HOST" -CAfile "$bundle" </dev/null 2>&1)"
  grep -E "Cipher is|Verify return code" <<<"$out" | sed 's/^/  /'
  if grep -q "Verify return code: 0 (ok)" <<<"$out"; then
    live_ok=1
    echo
    echo "✅ СЕРТИФИКАТ БАНКА ПРОВЕРЕН. Канал шифруется И собеседник подтверждён."
    echo "   Кандидат: $bundle — сверьте и положите в ca/ РУКАМИ (docs/PROCESS.md §4)."
  else
    live_ok=0
    echo
    echo "❌ Проверка не прошла. Смотрите строку выше."
    echo "   Если 'unable to get local issuer' — в связке не хватает звена: проверьте раздел 3."
  fi
else
  echo "  пропущено: нет пропатченного openssl (см. scripts/bee2evp-probe.sh) или пустая связка"
fi

# ⚠ КОД ВОЗВРАТА ГОВОРИТ ТО ЖЕ, ЧТО ТЕКСТ. Прежняя редакция при незамкнутой цепочке и при
# провале живой проверки печатала предупреждение и возвращала 0 — обёртка вида
# `by-ca-bundle.sh && cp … ca/` выкатила бы обрезанную связку в путь доверия.
if [[ $chain_ok -ne 1 || $live_ok -eq 0 ]]; then
  exit 3
fi
[[ $ambiguous -eq 1 ]] && echo "(в связке несколько поколений одного УЦ — см. предупреждение в разделе 3)"
exit 0
