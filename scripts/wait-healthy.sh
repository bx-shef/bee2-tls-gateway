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

# Разбор не зависит от порядка аргументов: `wait-healthy.sh gw-foo --soft` в наивном
# варианте принял бы --soft за имя контейнера и молча ждал бы несуществующий контейнер.
soft=0
tries=20
container=''
while [ $# -gt 0 ]; do
  case "$1" in
    --soft)  soft=1 ;;
    --tries) tries="${2:?wait-healthy.sh: --tries требует числа}"; shift ;;
    --*) echo "wait-healthy.sh: неизвестный флаг $1" >&2; exit 2 ;;
    *)
      [ -z "$container" ] || { echo "wait-healthy.sh: контейнер уже задан ($container), лишний аргумент $1" >&2; exit 2; }
      container="$1" ;;
  esac
  shift
done
[ -n "$container" ] || { echo 'wait-healthy.sh: имя контейнера обязательно' >&2; exit 2; }

for _ in $(seq 1 "$tries"); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$container" 2>/dev/null)" = healthy ] && exit 0
  sleep 2
done

[ "$soft" = 1 ] && exit 0
echo "FAIL: контейнер $container не стал healthy" >&2
# Вывод последних проб healthcheck несущий: процесс, который пишет логи в файлы
# (nginx стенда), оставляет docker logs пустым, и без этой строки отказ выглядел бы
# беспричинным — так и вышло на первом живом прогоне стенда.
docker inspect -f '{{range .State.Health.Log}}probe exit={{.ExitCode}}: {{.Output}}{{end}}' \
  "$container" 2>/dev/null | tail -5 >&2
docker logs "$container" 2>&1 | tail -30 >&2
exit 1
