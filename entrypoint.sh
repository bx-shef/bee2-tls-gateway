#!/bin/bash
# Crypto gateway entrypoint (#460): validate what can be validated locally, render the
# nginx config, hand over.
#
# Design rule for the checks below: FAIL on states that can only be misconfiguration,
# WARN on states that a legitimate certificate rotation also produces. A gateway that
# refuses to start during a root rotation is an outage we inflicted on ourselves at the
# exact moment we were trying to fix one (#462).
set -euo pipefail

log() { printf '[crypto-gw] %s\n' "$*" >&2; }
die() { printf '[crypto-gw] FATAL: %s\n' "$*" >&2; exit 1; }

: "${GW_LISTEN:=1080}"
: "${GW_UPSTREAM_PORT:=9345}"
: "${GW_CA_BUNDLE:=/etc/crypto-gw/ca/gossuok-bundle.pem}"
: "${GW_KEEPALIVE:=4}"
: "${GW_RATE:=10}"
: "${GW_BURST:=20}"
: "${GW_CONNECT_TIMEOUT:=15s}"
: "${GW_READ_TIMEOUT:=60s}"
# `crit` and not `error`, on purpose. nginx's error_log format is not configurable and
# `[error]`-level lines carry the full request line — measured:
#   request: "POST /open-banking-authorize/v1.0/oauth2/token HTTP/1.1"
# for a statement call that path holds the account number. The same failures are already
# visible in the access log as status=502 with route=, minus the identifier. Raise this
# to `info` for a live run (README.md § "Что попадает в логи"), then put it back.
: "${GW_ERROR_LOG_LEVEL:=crit}"
# See README § "Один поток всегда жжёт процессор". bee2 starts a permanent busy-loop
# thread as an entropy source; niceness is what keeps it out of everyone else's way.
: "${GW_NICE:=19}"

REFERENCE_LEAF=/etc/crypto-gw/ca/bank-leaf-reference.pem
TEMPLATE=/etc/crypto-gw/nginx.conf.template
RENDERED=/tmp/crypto-gw.nginx.conf

[[ -n "${GW_UPSTREAM_HOST:-}" ]] || die 'GW_UPSTREAM_HOST не задан (например apibel.priorbank.by). Без него шлюзу некуда ходить.'

# --- 1. FATAL: the bundle must at least be a bundle -------------------------------
# An empty file, a missing mount and a directory-instead-of-file all reach here, and
# none of them can be a rotation in progress.
[[ -r "$GW_CA_BUNDLE" ]] || die "корни ГосСУОК не читаются: $GW_CA_BUNDLE (проверьте монтирование тома)"
cert_count="$(grep -c 'BEGIN CERTIFICATE' "$GW_CA_BUNDLE" || true)"
[[ "$cert_count" -ge 1 ]] || die "в $GW_CA_BUNDLE нет ни одного сертификата"
log "корни ГосСУОК: $cert_count сертификат(ов) в $GW_CA_BUNDLE"

# --- 2. LOUD, not fatal: does the bundle still verify a known bank certificate? ----
# A mounted bundle that holds only the root passes every syntactic check and then 502s
# every single request ("unable to get local issuer certificate") — this is the check
# that catches it. It legitimately fails after a rotation (new root signs a new leaf,
# our baked reference is the old one), hence a warning rather than a refusal to start.
if [[ -r "$REFERENCE_LEAF" ]]; then
  if openssl verify -no_check_time -CAfile "$GW_CA_BUNDLE" "$REFERENCE_LEAF" >/dev/null 2>&1; then
    log 'проверка цепочки: bundle подтверждает эталонный сертификат банка — OK'
  else
    log '=============================================================================='
    log 'ВНИМАНИЕ: смонтированный bundle НЕ подтверждает эталонный сертификат банка.'
    log 'Либо в bundle не хватает ПРОМЕЖУТОЧНОГО сертификата (самая частая причина —'
    log 'тогда все запросы будут падать 502), либо УЦ сменил корни и эталон устарел'
    log '(тогда это ожидаемо — см. #462). Шлюз стартует, но проверьте до прогона.'
    log '=============================================================================='
  fi
else
  log "эталонный сертификат банка отсутствует ($REFERENCE_LEAF) — проверка цепочки пропущена"
fi

# --- 2b. LOUD, not fatal: сколько связке осталось жить -----------------------------
# Самый неприятный отказ здесь — тихий. Когда корни истекут, `proxy_ssl_verify on`
# начнёт отклонять рукопожатие, и со стороны потребителя это выглядит не как авария, а
# как «банк перестал присылать выписки»: никого не разбудит, ничто не покраснеет, а
# расхождение всплывёт через недели на сверке (#4).
#
# Поэтому предупреждаем ЗАРАНЕЕ и НЕ падаем: истечение корня — повод готовить замену, а
# не повод уронить работающий шлюз. Ротация корней и так делается набором (новый рядом
# со старым), и отказ стартовать в этот момент был бы аварией, устроенной себе самим.
#
# `-checkend` читает только даты и потому работает даже там, где разбор ключа bign
# невозможен, — проверено запуском на этой самой связке.
: "${GW_CA_WARN_DAYS:=90}"
ca_split="$(mktemp -d)"
awk -v d="$ca_split" '/-----BEGIN CERTIFICATE-----/{c++} c>0{print > (d "/cert-" c ".pem")}' \
  "$GW_CA_BUNDLE" 2>/dev/null || true
for cert in "$ca_split"/cert-*.pem; do
  [[ -r "$cert" ]] || continue
  if ! openssl x509 -in "$cert" -noout -checkend $((GW_CA_WARN_DAYS * 86400)) >/dev/null 2>&1; then
    until_date="$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)"
    who="$(openssl x509 -in "$cert" -noout -subject -nameopt utf8 2>/dev/null | sed 's/.*CN *= *//; s/,.*//')"
    log '=============================================================================='
    log "ВНИМАНИЕ: корень связки истекает менее чем через ${GW_CA_WARN_DAYS} дн."
    log "  кто:  ${who:-(субъект не прочитался)}"
    log "  до:   ${until_date:-(дата не прочиталась)}"
    log 'Готовьте замену ЗАРАНЕЕ: новый корень кладётся в связку рядом со старым, старый'
    log 'убирается после перехода — простоя при этом нет. Порядок — PROCESS.md §4.'
    log '=============================================================================='
  fi
done
rm -rf "$ca_split"

# --- 2c. allowlist путей из конфигурации (#7) ---------------------------------------
# Список путей — ЕДИНСТВЕННАЯ граница безопасности шлюза, и раньше он был выписан
# литеральными `location` в шаблоне. Пути одного конкретного банка внутри образа, вся
# посылка которого в том, что он не знает ни про какой банк, — и любой новый эндпоинт
# (например /open-banking-dcr/) требовал правки шаблона и пересборки.
#
# ⚠ ГЛАВНОЕ СВОЙСТВО КОНСТРУКЦИИ: отсюда приходят ТОЛЬКО РАЗРЕШЕНИЯ. Отказ по умолчанию
# (`location / { return 404; }`) и `/healthz` живут в шаблоне структурно, и никакая
# конфигурация их не отменяет. Поэтому пустой список даёт «не разрешено ничего», а не
# «разрешено всё» — это не проверка, которую можно забыть, а форма самой конструкции.
#
# Формат: записи через `;`, в каждой «МЕТОДЫ путь». `=` перед путём — точное совпадение,
# без него — префикс. Синтаксис намеренно повторяет nginx, чтобы не заводить второе
# понятие для того же самого:
#   GW_ALLOW='POST =/open-banking-authorize/v1.0/oauth2/token; GET,POST /open-banking/v1.0/'
# ⚠ `${VAR-...}`, а НЕ `${VAR:=...}`. Разница здесь принципиальная, и она уже стоила
# дефекта: `:=` подставляет значение и на ПУСТУЮ строку, поэтому `GW_ALLOW=''` — явное
# «не разрешать ничего» — молча возвращал бы пути банка обратно. Пойман тестом
# scripts/check-allowlist.sh, не глазами.
#   переменная не задана → умолчание (совместимость с тем, что уже развёрнуто);
#   задана пустой        → НЕ РАЗРЕШЕНО НИЧЕГО, и это законная конфигурация.
GW_ALLOW="${GW_ALLOW-POST =/open-banking-authorize/v1.0/oauth2/token; GET,POST /open-banking/v1.0/}"
[[ "$GW_BURST" =~ ^[0-9]+$ ]] || die "GW_BURST должен быть числом, а не «$GW_BURST»: он уходит в конфиг nginx"
[[ "$GW_RATE" =~ ^[0-9]+$ ]] || die "GW_RATE должен быть числом, а не «$GW_RATE»"

ROUTES=/tmp/crypto-gw.routes.conf

# ⚠ GW_ALLOW — текст от оператора, который становится конфигурацией nginx. Без строгой
# проверки `GW_ALLOW='GET /x { } location / { proxy_pass https://bank; }'` открыл бы релей
# к банку. Поэтому разбор посимвольно строгий, а всё непонятое — фатально: битая
# конфигурация может быть только ошибкой, а ошибка в границе безопасности не то место,
# где стоит угадывать намерение.
ROUTE_MAP=/tmp/crypto-gw.routes-map.conf
: > "$ROUTES"
: > "$ROUTE_MAP"
allow_count=0
seen_paths=""
seen_labels=""
# `set -f` не украшение: `for entry in $GW_ALLOW` разворачивается ЕЩЁ И как glob, и сейчас
# это не стреляет лишь потому, что запись всегда содержит пробел. Граница безопасности не
# должна зависеть от того, что в рабочем каталоге не оказалось файла с подходящим именем.
set -f
saved_ifs="$IFS"
IFS=';'
for entry in $GW_ALLOW; do
  IFS="$saved_ifs"
  entry="$(printf '%s' "$entry" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  [[ -n "$entry" ]] || { IFS=';'; continue; }

  methods="${entry%% *}"
  path="${entry#* }"
  path="$(printf '%s' "$path" | sed 's/^[[:space:]]*//')"

  [[ "$methods" =~ ^[A-Z]+(,[A-Z]+)*$ ]] \
    || die "GW_ALLOW: методы «$methods» не похожи на список вида GET,POST (запись: $entry)"
  for m in ${methods//,/ }; do
    case "$m" in
      GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) ;;
      *) die "GW_ALLOW: неизвестный метод «$m» (запись: $entry)" ;;
    esac
  done

  exact=""
  if [[ "$path" == "="* ]]; then exact="= "; path="${path#=}"; fi
  # Ни пробелов, ни `{}`, ни `;`, ни `$` — только то, из чего состоит путь. Это и есть
  # защита от подстановки директив.
  [[ "$path" =~ ^/[A-Za-z0-9._~/-]*$ ]] \
    || die "GW_ALLOW: путь «$path» содержит недопустимые символы (запись: $entry)"
  # ⚠ nginx НОРМАЛИЗУЕТ путь запроса до сопоставления с location: схлопывает повторные `/`
  # (merge_slashes on по умолчанию) и разрешает сегменты `.` и `..`. Поэтому `location
  # /a/../b/` и `location //a/` — маршруты, в которые не попадёт ни один запрос: сравнение
  # идёт с уже нормализованным путём, а в нём таких последовательностей не бывает.
  # Принять такую запись молча хуже, чем упасть: и GW_ALLOW_DUMP, и `nginx -t` покажут
  # маршрут существующим, а в проде он будет отдавать 404 — оператор пойдёт искать причину
  # в банке. Это не дыра в границе, а ложное свидетельство о ней, и по правилу этого
  # разбора («всё непонятое — фатально») ему здесь не место.
  dot_segment='(^|/)\.\.?(/|$)'
  [[ ! "$path" =~ $dot_segment ]] \
    || die "GW_ALLOW: путь «$path» содержит сегмент «.» или «..» — nginx нормализует путь запроса до сопоставления, и такой маршрут не сработает никогда. Напишите путь в нормализованном виде"
  [[ "$path" != *//* ]] \
    || die "GW_ALLOW: путь «$path» содержит «//» — nginx схлопывает повторные слеши до сопоставления, и такой маршрут не сработает никогда. Уберите лишний слеш"
  # Префикс `/` разрешил бы вообще всё и превратил бы шлюз в открытый релей к банку —
  # ровно то, ради предотвращения чего список и существует.
  [[ -n "$exact" || "$path" != "/" ]] \
    || die 'GW_ALLOW: префикс «/» разрешает всё и превращает шлюз в открытый релей'
  # ⚠ Префикс в nginx — совпадение по НАЧАЛУ СТРОКИ, а не по границе сегмента пути:
  # `location /open-banking` матчит и `/open-banking-admin`, и `/open-bankingXYZ`, и всё это
  # уедет в банк. Оператор такого не имел в виду. Хочешь один путь — пиши `=`, хочешь
  # поддерево — ставь слеш; третьего смысла у префикса без слеша нет.
  [[ -n "$exact" || "$path" == */ ]] \
    || die "GW_ALLOW: префикс «$path» без завершающего / матчит и соседние пути (например ${path}-admin). Допишите / или используйте =$path"

  # `/healthz` живёт в шаблоне структурно; вторая такая же локация — тот же duplicate.
  # ⚠ Сравнением с двумя литералами (`/healthz` и `= /healthz`) этого мало: `/healthz/` и
  # `=/healthz/` — другие строки, они проходили мимо и отдавали ПОДДЕРЕВО пробы живости
  # банку. Саму пробу это не ломало (точное совпадение в шаблоне всегда выигрывает у
  # префикса), но мониторинг, который ходит вариациями пути, начинал получать ответы
  # апстрима. Имя занято целиком — вместе с поддеревом.
  case "$path" in
    /healthz|/healthz/*) die 'GW_ALLOW: /healthz занят шлюзом (проба живости) и не может быть переопределён — включая поддерево /healthz/' ;;
  esac

  # nginx падает с «duplicate location» и уводит контейнер в цикл перезапусков, а
  # GW_ALLOW_DUMP этого не покажет — он выходит раньше nginx -t. Ловим здесь и по-русски.
  # ⚠ Ключ строится БЕЗ пробела после `=`, хотя в конфиг уходит с пробелом. С пробелом он
  # ломался о собственный разделитель: `seen_paths` разделён пробелами, и проверка
  # `case " = /a/ " in *" /a/ "*` давала совпадение — пара `=/a/` + `/a/` объявлялась
  # дубликатом, хотя это два РАЗНЫХ location (точный путь и поддерево). Отказ зависел от
  # порядка записей: точное совпадение первым — ложный FATAL, префикс первым — тишина.
  key="${exact:+=}${path}"
  case " $seen_paths " in
    *" $key "*) die "GW_ALLOW: путь «$key» указан дважды — nginx откажется стартовать (duplicate location). Объедините методы в одну запись: GET,POST $path" ;;
  esac
  seen_paths="$seen_paths $key"

  {
    printf '        location %s%s {\n' "$exact" "$path"
    printf '            limit_except %s { deny all; }\n' "${methods//,/ }"
    printf '            limit_req zone=gw burst=%s nodelay;\n' "$GW_BURST"
    # `$uri$is_args$args`, а не голый `proxy_pass https://bank;`. Голая форма шлёт СЫРОЙ
    # request-target, тогда как location сматчился по УЖЕ НОРМАЛИЗОВАННОМУ пути — и
    # звонящий из этой сети мог бы пройти проверку путём, чьи сырые байты несут `../`
    # для стека банка. Отправляя нормализованный путь, разрыв «проверили одно, отправили
    # другое» закрываем.
    # shellcheck disable=SC2016  # одинарные кавычки НАМЕРЕННО: $uri, $is_args и $args —
    # переменные NGINX, они обязаны попасть в конфиг буквально. Раскройся они здесь, в
    # конфиг уехала бы пустая строка, и proxy_pass отправил бы запрос в корень апстрима.
    printf '            proxy_pass https://bank$uri$is_args$args;\n'
    printf '        }\n\n'
  } >> "$ROUTES"

  # Метка маршрута для лога. ⚠ Это НАСТРОЕННЫЙ путь, а не путь запроса: в запросе ездит
  # номер счёта, и ему в агрегации логов делать нечего. Настроенный префикс постоянен и
  # безопасен, поэтому метка из него — можно.
  label="$(printf '%s' "$path" | tr -c 'A-Za-z0-9' '-' | sed 's/--*/-/g; s/^-//; s/-$//' | cut -c1-40)"
  [[ -n "$label" ]] || label="route${allow_count}"
  # Разные пути могут дать ОДНУ метку: `tr -c` схлопывает `.` и `_` в `-`, а `cut` режет
  # длинные до общего префикса. Молча — значит оператор не отличит два эндпоинта в
  # агрегации, поэтому различаем номером.
  # ⚠ Ровно ОДИН суффикс уникальности не даёт: он сам может совпасть с меткой уже
  # разобранного пути. `GET /abc/; POST /abc-2/; PUT /abc./` давал метку `abc-2` дважды —
  # то есть возвращал ту самую неразличимость, ради которой суффикс и вводился. Поэтому
  # крутим до первой свободной.
  case " $seen_labels " in
    *" $label "*)
      label_base="$label"
      label_n=1
      while :; do
        label="${label_base}-${label_n}"
        case " $seen_labels " in
          *" $label "*) label_n=$((label_n + 1)) ;;
          *) break ;;
        esac
      done
      ;;
  esac
  seen_labels="$seen_labels $label"
  if [[ -n "$exact" ]]; then
    printf '    %s %s;\n' "$path" "$label" >> "$ROUTE_MAP"
  else
    # Префикс — регуляркой, с экранированной точкой: `v1.0` иначе совпал бы с `v1X0`.
    printf '    ~^%s %s;\n' "$(printf '%s' "$path" | sed 's/\./\\./g')" "$label" >> "$ROUTE_MAP"
  fi

  allow_count=$((allow_count + 1))
  IFS=';'
done
IFS="$saved_ifs"
set +f

log "allowlist: разрешено маршрутов — $allow_count (всё остальное 404)"
[[ "$allow_count" -gt 0 ]] || log 'ВНИМАНИЕ: allowlist ПУСТ — наружу не пройдёт ни один запрос, кроме /healthz'

# Выгрузка сгенерированного и выход — без nginx и без запуска. Нужна двум разным людям:
# оператору («что именно получится из моего GW_ALLOW, до выката») и проверке
# scripts/check-allowlist.sh, которая иначе не смогла бы дотянуться до генератора,
# запертого внутри entrypoint. Граница безопасности обязана быть проверяемой снаружи.
# Именно `== 1`: `GW_ALLOW_DUMP=0` — естественный способ написать «выключено», и на
# `-n` он бы сработал как «включено», а контейнер молча никогда не начал бы обслуживать.
if [[ "${GW_ALLOW_DUMP:-}" == 1 ]]; then
  echo "--- routes ---"
  cat "$ROUTES"
  echo "--- route map ---"
  cat "$ROUTE_MAP"
  exit 0
fi

# --- 3. render ---------------------------------------------------------------------
# Explicit allowlist: without it envsubst would also eat nginx's own $status,
# $upstream_status, $binary_remote_addr … and the config would not even parse.
# ⚠ GW_BURST здесь НЕТ намеренно: с версии #7 он подставляется генератором маршрутов
# напрямую в bash, а в шаблоне его плейсхолдера не осталось. Оставь его в списке —
# проверка «в списке envsubst нет переменных, которых нет в шаблоне» покраснеет, и
# правильно сделает: список и шаблон обязаны совпадать.
export GW_LISTEN GW_UPSTREAM_HOST GW_UPSTREAM_PORT GW_CA_BUNDLE GW_KEEPALIVE \
       GW_RATE GW_CONNECT_TIMEOUT GW_READ_TIMEOUT GW_ERROR_LOG_LEVEL
# shellcheck disable=SC2016  # одинарные кавычки НАМЕРЕННО: это SHELL-FORMAT
# для envsubst — список имён, которые он подставит. Раскройся они здесь, envsubst получил бы
# уже подставленные значения и не заменил бы в шаблоне ничего.
envsubst '${GW_LISTEN} ${GW_UPSTREAM_HOST} ${GW_UPSTREAM_PORT} ${GW_CA_BUNDLE} ${GW_KEEPALIVE} ${GW_RATE} ${GW_CONNECT_TIMEOUT} ${GW_READ_TIMEOUT} ${GW_ERROR_LOG_LEVEL}' \
  < "$TEMPLATE" > "$RENDERED"

nginx -t -c "$RENDERED" || die 'nginx отверг конфигурацию (вывод выше)'
log "апстрим: ${GW_UPSTREAM_HOST}:${GW_UPSTREAM_PORT}; слушаю :${GW_LISTEN}; nice=${GW_NICE}"

# `exec` so nginx is PID 1 and receives the stop signal directly instead of waiting out
# Docker's 10s grace and being SIGKILLed. Which signal that is matters: nginx treats TERM
# as a FAST shutdown and QUIT as the graceful one, so the Dockerfile sets
# `STOPSIGNAL SIGQUIT` — without it a routine image update would cut an in-flight bank
# request in half.
exec nice -n "$GW_NICE" nginx -c "$RENDERED"
