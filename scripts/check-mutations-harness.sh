#!/usr/bin/env bash
# Сторож мутационного харнесса — проверка того, что он не оставляет мутацию в дереве.
#
# ЗАЧЕМ ЕЩЁ ОДИН УРОВЕНЬ. `check-config-mutations.sh` доказывает, что защиты живы. Но сам
# он ломает рабочее дерево и откатывает — и 13.08.2026 выяснилось, что откат случается
# только в нормальном потоке (#39). Убитый прогон оставил в дереве мутацию, снимавшую
# запрет «//» в пути `GW_ALLOW`, то есть граница безопасности лежала ослабленной, а рядом
# стоял `die` с текстом, утверждавшим обратное. Поймал это не харнесс, а хук.
#
# Ирония в том, что инструмент, вся работа которого — доказывать живость защит, сам умел
# оставить защиту выключенной. Эта проверка закрывает именно ту дыру.
#
# ⚠ Проверяем ЗАПУСКОМ, а не чтением кода: рассуждение «обработчик зарегистрирован, значит
# сработает» и есть то, чем харнесс себя успокаивал до #39.
#
# ⚠ SIGKILL не проверяем — он не перехватывается ничем, и это записано как известное
# ограничение. От него спасает проверка «дерево чистое» на старте прогона и в job `ci`.

set -euo pipefail

cd "$(dirname "$0")/.."

HARNESS=scripts/check-config-mutations.sh
# Тот же список, что в самом харнессе. Расхождение здесь означает, что проверка смотрит
# не на те файлы и молча ничего не доказывает, — поэтому оно сверяется ниже.
MUTATED=(nginx.conf.template entrypoint.sh Dockerfile scripts/check-crypto.sh)

passed=0
failed=0
ok()  { printf 'ok   %s\n' "$1"; passed=$((passed + 1)); }
bad() { printf 'FAIL %s\n' "$1" >&2; failed=$((failed + 1)); }

dirty() { [ -n "$(git status --porcelain -- "${MUTATED[@]}")" ]; }

# Дерево обязано вернуться в исходное состояние, чем бы ни кончилась сама проверка:
# иначе сторож откатов сам оставил бы мутацию.
cleanup() {
  local rc=$?
  if [ -n "${BG_PGID:-}" ]; then
    kill -TERM -- "-${BG_PGID}" 2>/dev/null || true
  fi
  git checkout -- "${MUTATED[@]}" 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT

# Запустить харнесс в СВОЕЙ группе процессов и вернуть её идентификатор.
# Своя группа нужна, чтобы сигнал не прилетел этому скрипту вместе с харнессом.
start_harness() {
  setsid bash "$HARNESS" > /tmp/harness-run.log 2>&1 &
  local pid=$!
  # У setsid-потомка pgid равен его pid; спрашиваем у ps, а не полагаемся на это.
  local pgid
  pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')
  echo "${pgid:-$pid}"
}

# Дождаться, пока харнесс реально применит мутацию (иначе убивать нечего).
wait_dirty() {
  for _ in $(seq 1 300); do
    dirty && return 0
    sleep 0.1
  done
  return 1
}

wait_clean() {
  for _ in $(seq 1 100); do
    dirty || return 0
    sleep 0.1
  done
  return 1
}

echo "== 0. Список мутируемых файлов совпадает с харнессом"
# Если харнесс начнёт мутировать пятый файл, а здесь его не будет, обе проверки ниже
# станут смотреть мимо и молча зеленеть.
if diff <(printf '%s\n' "${MUTATED[@]}" | sort) \
        <(sed -n 's/^MUTATED = (\(.*\))$/\1/p' "$HARNESS" \
          | tr -d ' ' | tr ',' '\n' | sed 's/^\(TPL\)$/nginx.conf.template/;
              s/^\(EP\)$/entrypoint.sh/; s/^\(DF\)$/Dockerfile/;
              s/^\(CR\)$/scripts\/check-crypto.sh/' | sort) > /dev/null; then
  ok "списки совпадают"
else
  bad "список MUTATED в харнессе разошёлся с этим скриптом"
fi

echo
echo "== 1. Прогон, убитый SIGTERM на середине, оставляет дерево чистым"
if dirty; then
  bad "дерево грязное ДО начала — проверка бессмысленна"
else
  BG_PGID=$(start_harness)
  if ! wait_dirty; then
    bad "не дождались мутации: харнесс не начал работу"
  else
    kill -TERM -- "-${BG_PGID}" 2>/dev/null || true
    if wait_clean; then
      ok "после SIGTERM дерево чистое — откат отработал"
    else
      bad "после SIGTERM мутация ОСТАЛАСЬ в дереве: $(git status --porcelain -- "${MUTATED[@]}" | tr '\n' ' ')"
    fi
  fi
  wait 2>/dev/null || true
  BG_PGID=""
fi

git checkout -- "${MUTATED[@]}" 2>/dev/null || true

echo
echo "== 2. Второй прогон при живом первом отказывается стартовать"
BG_PGID=$(start_harness)
if ! wait_dirty; then
  bad "не дождались мутации первого прогона"
else
  set +e
  second_out=$(bash "$HARNESS" 2>&1)
  second_rc=$?
  set -e
  if [ "$second_rc" -eq 0 ]; then
    bad "второй прогон завершился успешно — замка нет"
  elif printf '%s' "$second_out" | grep -q "уже идёт"; then
    ok "второй прогон отказался: $(printf '%s' "$second_out" | grep 'уже идёт' | head -1)"
  else
    # Отказ по грязному дереву тоже даёт ненулевой код, но НЕ доказывает замок:
    # без замка второй прогон мог бы стартовать в окне между проверкой и мутацией.
    bad "второй прогон упал не на замке: $(printf '%s' "$second_out" | head -2 | tr '\n' ' ')"
  fi
fi
kill -TERM -- "-${BG_PGID}" 2>/dev/null || true
wait 2>/dev/null || true
BG_PGID=""
wait_clean || true
git checkout -- "${MUTATED[@]}" 2>/dev/null || true

echo
printf 'пройдено: %d, провалено: %d\n' "$passed" "$failed"
[ "$failed" -eq 0 ] || exit 1
echo "харнесс не оставляет мутаций в дереве"
