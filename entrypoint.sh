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

# --- 3. render ---------------------------------------------------------------------
# Explicit allowlist: without it envsubst would also eat nginx's own $status,
# $upstream_status, $binary_remote_addr … and the config would not even parse.
export GW_LISTEN GW_UPSTREAM_HOST GW_UPSTREAM_PORT GW_CA_BUNDLE GW_KEEPALIVE \
       GW_RATE GW_BURST GW_CONNECT_TIMEOUT GW_READ_TIMEOUT GW_ERROR_LOG_LEVEL
# shellcheck disable=SC2016  # одинарные кавычки НАМЕРЕННО: это SHELL-FORMAT
# для envsubst — список имён, которые он подставит. Раскройся они здесь, envsubst получил бы
# уже подставленные значения и не заменил бы в шаблоне ничего.
envsubst '${GW_LISTEN} ${GW_UPSTREAM_HOST} ${GW_UPSTREAM_PORT} ${GW_CA_BUNDLE} ${GW_KEEPALIVE} ${GW_RATE} ${GW_BURST} ${GW_CONNECT_TIMEOUT} ${GW_READ_TIMEOUT} ${GW_ERROR_LOG_LEVEL}' \
  < "$TEMPLATE" > "$RENDERED"

nginx -t -c "$RENDERED" || die 'nginx отверг конфигурацию (вывод выше)'
log "апстрим: ${GW_UPSTREAM_HOST}:${GW_UPSTREAM_PORT}; слушаю :${GW_LISTEN}; nice=${GW_NICE}"

# `exec` so nginx is PID 1 and receives the stop signal directly instead of waiting out
# Docker's 10s grace and being SIGKILLed. Which signal that is matters: nginx treats TERM
# as a FAST shutdown and QUIT as the graceful one, so the Dockerfile sets
# `STOPSIGNAL SIGQUIT` — without it a routine image update would cut an in-flight bank
# request in half.
exec nice -n "$GW_NICE" nginx -c "$RENDERED"
