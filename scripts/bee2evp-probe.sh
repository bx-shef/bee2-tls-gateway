#!/usr/bin/env bash
# Probe whether the open BY crypto stack (bee2 + bee2evp) can negotiate STB 34.101.65 with a
# bank's production host — the experiment this whole gateway grew out of.
#
# ЗАЧЕМ ОН ЗДЕСЬ. Это тот самый прогон, которым доказали, что открытая реализация говорит с
# банком и покупать проприетарное СКЗИ не обязательно. Он приехал из
# client-bank-alfa-by ([#48](https://github.com/bx-shef/bee2-tls-gateway/issues/48)); там он
# отвечал на вопрос «а можно ли вообще», здесь — отвечает на вопрос «а не разъехалась ли наша
# сборка с тем, что принимает банк». Второе полезно ровно до тех пор, пока скрипт проверяет
# ТУ ЖЕ версию криптостека, которую мы возим в образе, — отсюда чтение пинов ниже.
#
# ⚠ ЭТО РУЧНОЙ ИНСТРУМЕНТ, И В CI ЕГО НЕ БУДЕТ. Порт 9345 из GitHub Actions недостижим, а
# сборка OpenSSL из исходников занимает минуты. Свойство задачи, а не недоделка: живые факты
# о рукопожатии проверяются с машины, у которой есть доступ к банку.
#
# ⚠ НЕ РАБОТАЕТ С КЛЮЧОМ. Ни ключа ГосСУОК, ни носителя, ни пароля: скрипт только открывает
# соединение и печатает, что ответил сервер.
#
# ⚠ Успех пробы — НЕ разрешение эксплуатировать. Достаточно ли несертифицированной
# реализации по СПР 6.02 — вопрос юридический, и он живёт в docs/CERTIFICATION.md.
#
# Usage: bash scripts/bee2evp-probe.sh [--keep] [--host HOST] [--port PORT] [--cafile PATH]
#   --keep     не напоминать про каталог сборки в конце
#   --cafile   проверять сертификат сервера этой связкой (без него собеседник не проверяется)
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

HOST="apibel.priorbank.by"
PORT="9345"
KEEP=0
CAFILE=""
WORK="${TMPDIR:-/tmp}/bee2evp-probe"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep) KEEP=1 ;;
    --host) HOST="${2:?--host требует значения}"; shift ;;
    --port) PORT="${2:?--port требует значения}"; shift ;;
    --cafile) CAFILE="${2:?--cafile требует пути}"; shift ;;
    *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
  esac
  shift
done
if [[ -n "$CAFILE" && ! -r "$CAFILE" ]]; then
  echo "--cafile: файл не читается: $CAFILE" >&2; exit 2
fi

say() { printf '\n=== %s ===\n' "$1"; }

# ⚠ ПИНЫ ЧИТАЮТСЯ ИЗ Dockerfile, А НЕ ВЫПИСАНЫ ЗДЕСЬ. В прежнем репозитории копия была
# неизбежна — Dockerfile лежал в другом проекте, и шапка скрипта просила «держать в
# согласии» вручную. Здесь просить некого: файл рядом, и копия превратилась бы в третий
# экземпляр значения, который не сторожит ничто (`check-pins.sh` сверяет Dockerfile только
# с check-crypto.sh). Разъехавшийся пин не ломает прогон — он тихо меняет ВОПРОС, на который
# прогон отвечает: проверяли бы одну версию стека, а возили другую.
arg_of() {
  # Только строка с присваиванием: то же имя повторяется в стадиях без значения, и такие
  # строки источником правды не являются.
  sed -n "s/^ARG[[:space:]]\+$1=\(\S\+\)[[:space:]]*$/\1/p" Dockerfile | head -1
}
OPENSSL_TAG="${OPENSSL_TAG:-$(arg_of OPENSSL_TAG)}"
BEE2EVP_COMMIT="${BEE2EVP_COMMIT:-$(arg_of BEE2EVP_COMMIT)}"
if [[ -z "$OPENSSL_TAG" || -z "$BEE2EVP_COMMIT" ]]; then
  echo "не нашёл ARG OPENSSL_TAG / ARG BEE2EVP_COMMIT в Dockerfile — запускайте из репозитория" >&2
  exit 1
fi

say "0. Предусловия"
missing=""
for c in git gcc cmake make python3 openssl; do
  command -v "$c" >/dev/null || missing="$missing $c"
done
if [[ -n "$missing" ]]; then
  echo "НЕ ХВАТАЕТ:$missing"
  echo "Debian/Ubuntu:  sudo apt-get install -y git gcc cmake make python3 openssl"
  exit 1
fi
echo "всё на месте"
echo "пины из Dockerfile: ${OPENSSL_TAG}, bee2evp ${BEE2EVP_COMMIT:0:8}"

# ⚠ КОНТРОЛЬ ИДЁТ ПЕРВЫМ, И БЕЗ НЕГО ПРОБА НИЧЕГО НЕ ДОКАЗЫВАЕТ. Успех патченой сборки на
# хосте, который в тот день отвечал обычным TLS, выглядит точно так же, как успех настоящий.
# А провал без контроля не отличить от «нет сети».
say "1. Контроль: обычный OpenSSL против ${HOST}:${PORT}"
base_out="$(timeout 25 openssl s_client -connect "${HOST}:${PORT}" -servername "$HOST" </dev/null 2>&1)"
if grep -q "unknown cipher returned" <<<"$base_out"; then
  echo "ОЖИДАЕМО: обычный TLS не согласуется (сервер отвечает белорусским шифром)"
elif grep -qE "Cipher is (TLS|ECDHE|AES)" <<<"$base_out"; then
  echo "⚠ НЕОЖИДАННО: обычный OpenSSL СОГЛАСОВАЛ шифр — хост принимает обычный TLS."
  echo "  Тогда СКЗИ для него не нужен вовсе, и эта проверка теряет смысл. Проверьте адрес."
  exit 0
else
  echo "⚠ Ни того, ни другого — вероятно, нет сети до банка. Дальше идти бессмысленно:"
  # ⚠ Ветка «молчаливого» отказа отдельной строкой. Прежняя редакция печатала сюда grep, а
  # при пустом выводе openssl (соединение оборвано, прокси съел ответ) — не печатала НИЧЕГО,
  # и диагноз «нет сети» оставался голословным. Пустой вывод — это тоже факт, и его надо
  # назвать: иначе оператор ищет причину в скрипте, а она снаружи.
  detail="$(grep -m1 -E "connect:|socket|timeout" <<<"$base_out")"
  if [[ -n "$detail" ]]; then
    echo "  $detail"
  elif [[ -n "${base_out//[[:space:]]/}" ]]; then
    while IFS= read -r line; do echo "  $line"; done < <(head -3 <<<"$base_out")
  else
    echo "  (openssl не вывел ничего — соединение оборвалось молча; проверьте маршрут до"
    echo "   ${HOST}:${PORT} и не режет ли исходящий трафик прокси)"
  fi
  exit 1
fi

say "2. Сборка bee2evp + OpenSSL с патчем BTLS (${OPENSSL_TAG})"
if [[ -x "$WORK/bee2evp/build/openssl/apps/openssl" ]]; then
  echo "уже собрано, переиспользую: $WORK"
else
  mkdir -p "$WORK"
  if [[ ! -d "$WORK/bee2evp/.git" ]]; then
    git clone -q https://github.com/bcrypto/bee2evp "$WORK/bee2evp"
    git -C "$WORK/bee2evp" checkout -q "$BEE2EVP_COMMIT" || {
      echo "не удалось перейти на коммит $BEE2EVP_COMMIT — сверьтесь с Dockerfile"; exit 1; }
  fi
  echo "собираю (это долго — сборка OpenSSL из исходников)…"
  ( cd "$WORK/bee2evp" && bash ./scripts/build.sh -s -b "$OPENSSL_TAG" ) \
    > "$WORK/build.log" 2>&1 || { echo "СБОРКА УПАЛА, хвост лога:"; tail -20 "$WORK/build.log"; exit 1; }
  echo "готово"
fi

# Ищем бинарь, а не прописываем путь: раскладка между ревизиями bee2evp менялась.
# Установленная копия (build/local/bin) предпочтительнее внутридеревной (build/openssl/apps) —
# только рядом с первой лежат подходящие библиотеки.
OSSL="$(find "$WORK" -type f -name openssl -perm -u+x 2>/dev/null | grep -E '/local/bin/openssl$' | head -1)"
[[ -n "$OSSL" ]] || OSSL="$(find "$WORK" -type f -name openssl -perm -u+x 2>/dev/null | grep -E '/apps/openssl$' | head -1)"
if [[ -z "$OSSL" ]]; then
  echo "не нашёл собранный openssl под $WORK — смотрите $WORK/build.log"; exit 1
fi

# ⚠ БЕЗ LD_LIBRARY_PATH бинарь молча берёт СИСТЕМНЫЕ libssl/libcrypto и либо падает с
# «version `OPENSSL_3.3.0' not found», либо — хуже — загружает их и не показывает ни одного
# BTLS-набора. Читается это как «bee2evp не поддерживает шифронаборы» и закрывает
# исследование ложноотрицательным результатом. Измерено, а не предположено.
LIBDIR="$(dirname "$(dirname "$OSSL")")/lib"
[[ -d "$LIBDIR" ]] || LIBDIR="$(dirname "$OSSL")"
ossl() { LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$OSSL" "$@"; }
echo "openssl: $OSSL"
echo "библиотеки: $LIBDIR"
ossl version 2>&1 | head -1

say "3. Есть ли шифронаборы СТБ 34.101.65 в сборке"
suites="$(ossl ciphers -v 'ALL:eNULL' 2>/dev/null | grep -iE "BIGN|BELT" || true)"
if [[ -z "$suites" ]]; then
  echo "НЕТ — сборка без BTLS-наборов. Дальше проверять нечего."
  echo "Проверьте, что build.sh применил патч из btls/patch/${OPENSSL_TAG}.patch"
  exit 1
fi
echo "$suites"

say "4. Рукопожатие с ${HOST}:${PORT} через bee2evp"
verify_args=()
[[ -n "$CAFILE" ]] && verify_args=(-CAfile "$CAFILE" -verify_return_error)
probe_out="$(timeout 40 env LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  "$OSSL" s_client -connect "${HOST}:${PORT}" -servername "$HOST" -showcerts \
  "${verify_args[@]}" </dev/null 2>&1)"
grep -iE "Cipher is|Protocol|Verify return code|handshake has read|unknown cipher|alert" <<<"$probe_out" | head -8

# Цепочка, которую реально прислал сервер, плюс АДРЕС, откуда качать издателя. Без этого
# вопрос «какой корень нам нужен» превращается в перебор по nces.by / avest.by / belpost —
# тогда как сам сертификат называет издателя и (через AIA) ссылку на него.
say "5. Цепочка, которую прислал сервер (кто издатель и где его взять)"
chain="$(ossl crl2pkcs7 -nocrl -certfile /dev/stdin <<<"$probe_out" 2>/dev/null \
  | ossl pkcs7 -print_certs -noout 2>/dev/null || true)"
if [[ -n "$chain" ]]; then
  printf '%s\n' "$chain"
else
  grep -E "^ *[0-9]+ s:|^ *i:|^subject=|^issuer=" <<<"$probe_out" | head -10
fi
aia="$(ossl x509 -noout -text <<<"$probe_out" 2>/dev/null \
  | grep -A2 -iE "Authority Information Access|CRL Distribution" | grep -oE "URI:[^ ]+" | sort -u || true)"
if [[ -n "$aia" ]]; then
  echo "--- откуда качать издателя / списки отзыва ---"
  printf '%s\n' "$aia"
else
  echo "(AIA/CRL в сертификате не указаны — издателя искать по имени: nces.by / avest.by)"
fi

say "ВЕРДИКТ"
if grep -qiE "Cipher is (BDH|DHE-BIGN|DHT-BIGN)" <<<"$probe_out"; then
  echo "✅ ШИФР СОГЛАСОВАН. Открытая реализация говорит с сервером банка."
  # Шифрование без аутентификации — не цель: канал приватен, а собеседник не подтверждён.
  # Докладываем это двумя отдельными строками; слепив их, «работает» объявляют на шаг раньше.
  if grep -q "Verify return code: 0 (ok)" <<<"$probe_out"; then
    echo "✅ СЕРТИФИКАТ ПРОВЕРЕН — собеседник подтверждён."
  elif [[ -z "$CAFILE" ]]; then
    echo "⚠ Сертификат НЕ проверялся: связка не передана. Канал шифруется, но собеседник"
    echo "   не подтверждён — от подмены это не защищает. Повторите с --cafile ca/gossuok-bundle.pem,"
    echo "   издателя и адрес для скачивания смотрите в разделе 5 выше."
  else
    echo "❌ СЕРТИФИКАТ НЕ ПРОШЁЛ ПРОВЕРКУ переданной связкой:"
    grep -m1 "Verify return code" <<<"$probe_out"
    echo "   Частая причина — сервер не прислал ПРОМЕЖУТОЧНЫЙ сертификат: его надо добыть"
    echo "   отдельно (адрес — в разделе 5) и положить в связку рядом с корнем."
  fi
elif grep -q "unknown cipher returned" <<<"$probe_out"; then
  echo "❌ НЕ СОГЛАСОВАН — тот же отказ, что и у обычного OpenSSL."
  echo "   Значит патч BTLS не подхватился либо банк использует набор вне реализованных."
  echo "   Полный вывод сохранён: $WORK/probe.log"
else
  echo "⚠ НЕОДНОЗНАЧНО — смотрите $WORK/probe.log целиком."
fi
printf '%s\n' "$probe_out" > "$WORK/probe.log"

[[ $KEEP -eq 1 ]] || echo "(каталог сборки оставлен в $WORK — удалите вручную, если не нужен)"
