#!/usr/bin/env bash
# Прогон тех частей методик испытаний ОАЦ, которые поддаются автоматизации.
#
# Методики (НИИ ППМИ БГУ, 2024) опубликованы открыто, и «Тестирование» —
# второй из трёх этапов испытаний — сводится к контрольным примерам стандартов.
# Их и гоняем: не чтобы заменить испытательную лабораторию, а чтобы к моменту
# подачи заявки красным был только тот этап, который мы физически не можем
# провести у себя (анализ исходных текстов двумя экспертами).
#
# Что чем закрывается — docs/CERTIFICATION.md §10. Ссылки на сами методики —
# там же, в реестре.
#
# Запуск:
#   bash scripts/check-crypto.sh            # прогнать, чем есть
#   bash scripts/check-crypto.sh --build    # собрать bee2cmd и прогнать
#   bash scripts/check-crypto.sh --strict   # пропуск считать провалом
#
# ⚠ Живой прогон против банка сюда не входит и войти не может: нужен боевой
# хост и доступ по договору. Он делается руками, см. docs/PROCESS.md §4.

set -euo pipefail

# Ровно те версии, что собираются в Dockerfile: bee2evp пинуется по коммиту,
# а bee2 приезжает его подмодулем. Проверять надо то, что поедет в продуктив,
# а не свежий master — иначе зелёный прогон ничего не говорит об образе.
BEE2EVP_COMMIT=2ae3c71e8b24b6904367850e5963933236a1539f
BEE2_COMMIT=d9e689a03bb4fa9037e3741d8e3b8365204c5fd6

# Обязательный криптонабор по МИ.10165.10.01 п. 4. Имя в терминах OpenSSL;
# в стандарте он называется TLS_DHE_BIGN_WITH_BELT_CTR_MAC_HBELT.
REQUIRED_SUITE='DHE-BIGN-WITH-BELT-CTR-MAC-HBELT'

# Контрольная характеристика дистрибутива AvTunProxy 5.10.12 для linux64 из
# приложения к сертификату соответствия № BY/112 02.01. ТР027 036.01 00424
# (ОАЦ, 31.03.2022). Значение заверено государственным органом, поэтому
# служит эталоном для нашей реализации belt-хэша: совпало — реализация
# считает то же, что считала испытательная лаборатория.
AVTP_URL='https://avtunproxy.by/download/avtunproxy-latest.linux64.tar.gz'
AVTP_BELT_HASH='40bbf258e0807f9bcd194d2f9c4007da7fe7ef40fcf20ff5f3b33303437fb698'

BUILD=0
STRICT=0
for arg in "$@"; do
  case "$arg" in
    --build)  BUILD=1 ;;
    --strict) STRICT=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "неизвестный аргумент: $arg" >&2; exit 2 ;;
  esac
done

passed=0
failed=0
skipped=0

ok()   { printf 'ok    %s\n'   "$1"; passed=$((passed + 1)); }
bad()  { printf 'FAIL  %s\n'   "$1" >&2; failed=$((failed + 1)); }
skip() { printf 'ПРОП  %s\n'   "$1"; skipped=$((skipped + 1)); }
head2() { printf '\n== %s\n' "$1"; }

# ---- поиск инструментов ----------------------------------------------------
# bee2cmd — эталонная утилита самого bee2: она гоняет контрольные примеры
# стандартов (st alg) и показывает здоровье источников энтропии (es print).
# ⚠ С #19 она ЕСТЬ в образе шлюза (/opt/btls/bin/bee2cmd, попадает на PATH), потому что
# из неё сделан самотест при старте — см. README § «Самотестирование криптостека».
# Поэтому внутри контейнера скрипт находит её сам и `--build` там не нужен; сборка
# нужна только для запуска ВНЕ образа, на машине разработчика.
BEE2_DIR="${BEE2_DIR:-.bee2}"
# Путь абсолютный: git apply запускается с -C внутри клона, относительный туда не доедет.
PATCH_PR77="$(cd "$(dirname "$0")/.." && pwd)/patches/bee2-pr77-jitter-thread.patch"
find_bee2cmd() {
  if [ -n "${BEE2CMD:-}" ] && [ -x "${BEE2CMD}" ]; then
    echo "${BEE2CMD}"; return 0
  fi
  if [ -x "${BEE2_DIR}/build/cmd/bee2cmd" ]; then
    echo "${BEE2_DIR}/build/cmd/bee2cmd"; return 0
  fi
  command -v bee2cmd 2>/dev/null || return 1
}

build_bee2cmd() {
  head2 "Сборка bee2cmd (коммит ${BEE2_COMMIT:0:8}, подмодуль bee2evp ${BEE2EVP_COMMIT:0:8})"
  if ! command -v cmake > /dev/null || ! command -v git > /dev/null; then
    bad "сборка: нужны git и cmake"
    return 1
  fi
  rm -rf "${BEE2_DIR}"
  git clone --quiet https://github.com/agievich/bee2 "${BEE2_DIR}"
  git -C "${BEE2_DIR}" checkout --quiet "${BEE2_COMMIT}"
  # Пин обязателен к проверке: `checkout` молча возьмёт что угодно, если ссылка
  # переехала, а сверять контрольные примеры имеет смысл только с той версией,
  # которая реально собирается в образе.
  if [ "$(git -C "${BEE2_DIR}" rev-parse HEAD)" != "${BEE2_COMMIT}" ]; then
    bad "сборка: bee2 не на ожидаемом коммите"
    return 1
  fi
  # Тот же чужой патч, что накладывает Dockerfile (agievich/bee2 PR #77). Без него
  # локальная сборка отличалась бы от образа, и прогон перестал бы говорить об образе.
  if ! git -C "${BEE2_DIR}" apply "${PATCH_PR77}"; then
    bad "сборка: патч PR #77 не лёг на ${BEE2_COMMIT:0:8}"
    return 1
  fi
  cmake -S "${BEE2_DIR}" -B "${BEE2_DIR}/build" -DCMAKE_BUILD_TYPE=Release > /dev/null
  cmake --build "${BEE2_DIR}/build" --parallel > /dev/null
  ok "bee2cmd собран из ${BEE2_COMMIT:0:8} с патчем PR #77"
}

[ "$BUILD" = 1 ] && build_bee2cmd

BEE2CMD_BIN="$(find_bee2cmd || true)"

# Наш openssl — тот, что собран с bee2evp: либо указан явно, либо лежит по
# известному пути внутри образа. Системный openssl BTLS не знает В ПРИНЦИПЕ
# (ровно этим и объясняется существование проекта), поэтому его отсутствие
# криптонабора — не провал стека, а другой бинарь. Различаем эти случаи:
# провал засчитываем только НАШЕМУ openssl.
OPENSSL_BIN="${GW_OPENSSL:-/opt/btls/bin/openssl}"
OPENSSL_IS_OURS=1
if [ ! -x "$OPENSSL_BIN" ]; then
  OPENSSL_BIN="$(command -v openssl 2>/dev/null || true)"
  OPENSSL_IS_OURS=0
fi

# ---- 1. Контрольные примеры алгоритмов -------------------------------------
# Закрывает этап «Тестирование» сразу четырёх методик: belt (МИ.10131),
# bign (МИ.10145), brng (МИ.10147), bash (МИ.10177). Контрольные примеры
# зашиты в сам bee2 и взяты из приложений к стандартам.
head2 "1. Контрольные примеры алгоритмов — СТБ 34.101.31 / .45 / .47 / .77"
if [ -n "$BEE2CMD_BIN" ]; then
  if "$BEE2CMD_BIN" st alg > /dev/null 2>&1; then
    ok "st alg: контрольные примеры сошлись"
  else
    bad "st alg: контрольные примеры НЕ сошлись"
  fi
else
  skip "нет bee2cmd (запустите с --build или задайте BEE2CMD)"
fi

# ---- 2. Самотестирование ДСЧ -----------------------------------------------
# СТБ 34.101.27 требует самотестирования от СКЗИ как от изделия, а МИ.10147
# проверяет сам генератор. bee2 умеет и то и другое одной командой.
head2 "2. Самотестирование ДСЧ — СТБ 34.101.47, требование самотеста 34.101.27"
if [ -n "$BEE2CMD_BIN" ]; then
  if "$BEE2CMD_BIN" st rng > /dev/null 2>&1; then
    ok "st rng: генератор проходит самотест"
  else
    bad "st rng: генератор НЕ проходит самотест"
  fi
else
  skip "нет bee2cmd"
fi

# ---- 3. Здоровье источников энтропии ---------------------------------------
# Здесь же виден корень issue #8: проверка доступности источника `jitter`
# (`rngJitterIsAvail`) поднимает поток-счётчик, который крутится до конца процесса.
# ⚠ Виноват именно `jitter`, а не `timer` — разделено экспериментом, см. PROCESS.md §5.
# Если физический источник (trng) здоров, добор энтропии от `jitter` не нужен — и это
# проверяемо, а не на словах.
head2 "3. Источники энтропии — СТБ 34.101.47, ДСЧ по 34.101.27"
if [ -n "$BEE2CMD_BIN" ]; then
  es_out="$("$BEE2CMD_BIN" es print 2>&1 || true)"
  printf '%s\n' "$es_out" | sed 's/^/      /'
  if printf '%s' "$es_out" | grep -q 'Health (at least two healthy sources): +'; then
    ok "здоровы минимум два источника"
  else
    bad "здоровых источников меньше двух"
  fi
  if printf '%s' "$es_out" | grep -q 'Health2 (there is a healthy physical source): +'; then
    ok "физический источник (trng) доступен — поток-счётчик от jitter не нужен, см. #8"
  else
    skip "физического источника нет: на этой машине jitter действительно нужен (#8)"
  fi
else
  skip "нет bee2cmd"
fi

# ---- 4. Обязательный криптонабор -------------------------------------------
# МИ.10165.10.01 п. 4: программа ОБЯЗАНА реализовывать
# TLS_DHE_BIGN_WITH_BELT_CTR_MAC_HBELT, остальные семь — по желанию.
head2 "4. Обязательный криптонабор — МИ.10165.10.01 п. 4"
if [ -z "$OPENSSL_BIN" ] || [ ! -x "$OPENSSL_BIN" ]; then
  skip "openssl не найден (задайте GW_OPENSSL)"
elif "$OPENSSL_BIN" ciphers -v 2>/dev/null | grep -q "$REQUIRED_SUITE"; then
  ok "$REQUIRED_SUITE предлагается ($OPENSSL_BIN)"
elif [ "$OPENSSL_IS_OURS" = 1 ]; then
  bad "$REQUIRED_SUITE НЕ предлагается нашим стеком ($OPENSSL_BIN)"
else
  skip "$OPENSSL_BIN — системный openssl без bee2evp, BTLS он не знает; задайте GW_OPENSSL"
fi

# ---- 5. Контрольная характеристика против эталона ОАЦ ----------------------
# Самая ценная проверка: сверяем свой belt-хэш не с самим собой, а со
# значением, заверённым органом по сертификации. Файл 4,6 МБ, поэтому
# качается только по требованию.
head2 "5. Контрольная характеристика — СТБ 34.101.31, эталон из сертификата ОАЦ"
if [ -z "$BEE2CMD_BIN" ]; then
  skip "нет bee2cmd"
elif [ "${CHECK_AVTP:-0}" != 1 ]; then
  skip "сверка с эталоном ОАЦ выключена (CHECK_AVTP=1 включает, качает 4,6 МБ)"
else
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  if curl -sSL -m 300 -o "$tmp/avtp.tar.gz" "$AVTP_URL"; then
    got="$("$BEE2CMD_BIN" bsum "$tmp/avtp.tar.gz" | awk '{print $1}')"
    if [ "$got" = "$AVTP_BELT_HASH" ]; then
      ok "belt-хэш совпал с приложением к сертификату № …ТР027 036.01 00424"
    else
      # Расхождение НЕ означает ошибку реализации: АВЕСТ мог выложить более
      # свежую сборку под тем же именем latest. Сначала проверьте версию.
      bad "belt-хэш разошёлся: получено $got, в сертификате $AVTP_BELT_HASH"
    fi
  else
    skip "дистрибутив AvTunProxy не скачался"
  fi
fi

# ---- итог ------------------------------------------------------------------
head2 "Итог"
printf 'пройдено: %d, провалено: %d, пропущено: %d\n' "$passed" "$failed" "$skipped"

if [ "$failed" -gt 0 ]; then
  echo "есть провалы" >&2
  exit 1
fi
if [ "$STRICT" = 1 ] && [ "$skipped" -gt 0 ]; then
  echo "--strict: пропуски запрещены" >&2
  exit 1
fi
echo "автоматизируемая часть методик пройдена"
