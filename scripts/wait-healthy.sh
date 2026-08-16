#!/bin/bash
# Wait until a docker container reports healthy (shared helper for CI and stand runs).
#
# Использование:
#   bash scripts/wait-healthy.sh [--soft] [--tries N] КОНТЕЙНЕР
#
# Зачем отдельный файл (#62): цикл ожидания жил в ci.yml ПЯТЬЮ inline-копиями плюс
# одной функцией внутри шага — шаги workflow не разделяют функций, и каждый новый
# сценарий копировал цикл заново. Копии уже успели разъехаться: часть шагов после
# цикла проверяла healthy, часть — нет, и таймаут там выглядел как провал ПРОВЕРЯЕМОГО
# поведения, показывая пальцем на TLS или конфиг, которых дело не касалось.
#
# ⚠ Цикл ожидания обязан кончаться проверкой, а не истечением. Поэтому режим по
# умолчанию — ждать и УПАСТЬ с именем контейнера и хвостом его лога, если healthy не
# наступил. Режим --soft только ждёт и всегда выходит нулём: он для сценариев, где
# «не стал healthy» — самостоятельный исход, который шаг утверждает сам, своей
# формулировкой (например: «переменная уронила контейнер, а должна была предупредить»).
# --soft без последующей проверки в вызывающем коде — это дыра, а не мягкость.
set -euo pipefail

soft=0
tries=20
while [ $# -gt 1 ]; do
  case "$1" in
    --soft)  soft=1; shift ;;
    --tries) tries="$2"; shift 2 ;;
    *) echo "wait-healthy.sh: неизвестный аргумент $1" >&2; exit 2 ;;
  esac
done
container="${1:?wait-healthy.sh: имя контейнера обязательно}"

for _ in $(seq 1 "$tries"); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$container" 2>/dev/null)" = healthy ] && exit 0
  sleep 2
done

[ "$soft" = 1 ] && exit 0
echo "FAIL: контейнер $container не стал healthy" >&2
docker logs "$container" 2>&1 | tail -30 >&2
exit 1
