#!/bin/bash
# Reference-stand matrix (#82, A6): gateway vs bcrypto/btls servers from МИ.10165.10.01
# Appendix Г — three strength levels × six ports, plus trust negatives.
#
# Что утверждается и почему это несущая проверка:
#   - на портах 8443–8446 (по одному TLS 1.2 криптонабору на порт, 8443 — обязательный
#     0xFF15 DHE-BIGN-WITH-BELT-CTR-MAC-HBELT) шлюз обязан согласовать ИМЕННО набор
#     порта — эхо /check_server возвращает "$ssl_cipher#…" со стороны ЭТАЛОНА, то есть
#     свидетельствует сервер Приложения Г, а не наш же клиент о себе;
#   - на портах 8447–8448 (TLS 1.3-only) согласование обязано НЕ состояться: шлюз
#     говорит только TLS 1.2 — готовый негативный сценарий «несогласуемый набор»;
#   - доверие не наследуется: со штатной связкой ГосСУОК вместо сертификата стенда
#     тот же порт обязан дать 502 с verify-ошибкой в логе — иначе зелёная матрица
#     не отличала бы работающую проверку цепочки от выключенной.
#
# ⚠ Эталон клонируется на ЗАПИНЕННЫЙ коммит из stand/btls.pin: стенд — доказательная
# база экспертизы, и дрейф незапиненного master тихо менял бы то, против чего мы
# «прошли». Внутри Dockerfile эталона bee2evp пина не имеет — этот дрейф не удержать,
# не трогая эталон, поэтому он делается ВИДИМЫМ: скрипт печатает коммит bee2evp,
# с которым стенд реально собрался.
#
# Использование:
#   bash scripts/check-stand.sh [--keep]
#     --keep       не гасить стенд по завершении (для отладки; шлюзы всё равно убираются)
#   Переменные: GW_IMAGE  — образ шлюза (по умолчанию bee2-tls-gateway:ci);
#               BTLS_DIR  — куда клонировать эталон (по умолчанию под /tmp);
#               STAND_CACHE=gha — собирать образы стенда через buildx с кэшем GHA (для CI).
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

GW_IMAGE="${GW_IMAGE:-bee2-tls-gateway:ci}"
BTLS_DIR="${BTLS_DIR:-${TMPDIR:-/tmp}/btls-stand-checkout}"
export BTLS_DIR

keep=0
only=''
while [ $# -gt 0 ]; do
  case "$1" in
    --keep) keep=1 ;;
    # --only УРОВЕНЬ[:ПОРТ][,…] — гонять только названные клетки матрицы (например,
    # `--only 256:8443` или `--only 256,384:8444`). Для итераций по одной клетке —
    # разработка A1 гоняла бы иначе все 18+1 запусков шлюза на каждую пробу патча.
    # Пробы стенда и клетка «чужой корень» при фильтре пропускаются: они — свойство
    # ПОЛНОЙ матрицы, и их отсутствие честно видно в итоговой строке. EMS-проба (#80)
    # гоняется и под фильтром — см. её блок.
    --only) only="${2:?check-stand.sh: --only требует УРОВЕНЬ[:ПОРТ][,…]}"; shift ;;
    *) echo "check-stand.sh: неизвестный аргумент $1" >&2; exit 2 ;;
  esac
  shift
done

# only_match УРОВЕНЬ ПОРТ — попадает ли клетка в фильтр --only (пустой фильтр = все).
only_match() {
  [ -z "$only" ] && return 0
  local tok
  IFS=',' read -ra _toks <<<"$only"
  for tok in "${_toks[@]}"; do
    case "$tok" in
      "$1"|"$1:$2") return 0 ;;
    esac
  done
  return 1
}

log()  { printf '%s\n' "$*"; }
die()  { printf 'FAIL %s\n' "$*" >&2; exit 1; }

compose() { docker compose -f stand/compose.yaml "$@"; }

cleanup() {
  docker ps -aq --filter name='^gw-stand-' | xargs -r docker rm -f >/dev/null 2>&1 || true
  if [ "$keep" = 0 ]; then
    compose down --remove-orphans >/dev/null 2>&1 || true
  else
    log "стенд оставлен (--keep): docker compose -f stand/compose.yaml down — когда закончите"
  fi
}
trap cleanup EXIT

# ---- пин и клон эталона ------------------------------------------------------------
pin=$(tr -d '[:space:]' < stand/btls.pin)
[[ "$pin" =~ ^[0-9a-f]{40}$ ]] || die "stand/btls.pin не похож на sha коммита: '$pin'"

if [ -d "$BTLS_DIR/.git" ] \
   && [ "$(git -C "$BTLS_DIR" rev-parse HEAD 2>/dev/null)" = "$pin" ]; then
  log "эталон уже на пине $pin: $BTLS_DIR"
else
  rm -rf "$BTLS_DIR"
  mkdir -p "$BTLS_DIR"
  git -C "$BTLS_DIR" init -q
  git -C "$BTLS_DIR" remote add origin https://github.com/bcrypto/btls
  # fetch конкретного коммита: master может уехать, пин — нет.
  git -C "$BTLS_DIR" fetch -q --depth 1 origin "$pin"
  git -C "$BTLS_DIR" checkout -q --detach FETCH_HEAD
  [ "$(git -C "$BTLS_DIR" rev-parse HEAD)" = "$pin" ] \
    || die "клон эталона не на пине: $(git -C "$BTLS_DIR" rev-parse HEAD)"
  log "эталон склонирован на пин $pin: $BTLS_DIR"
fi

# ⚠ Эталон сегодня НЕ собирается из собственных источников, и это нашёл первый живой
# прогон CI: zlib.net на корневом URL держит только текущий релиз, старый отдаёт
# HTML-страницей с кодом 200 (12 КБ вместо тарбола), а nginx.sh эталона без set -e
# глотает отказ и доводит сборку до «успеха» БЕЗ nginx вовсе. Правим ровно URL — та же
# версия 1.3.2, постоянный адрес fossils; сама буква эталона в остальном не тронута.
# Отклонение записано в PROCESS.md §5. Патчится только btls256 — 384/512 собираются
# FROM него и nginx.sh не запускают.
sed -i 's|http://zlib.net/zlib-1.3.2.tar.gz|https://zlib.net/fossils/zlib-1.3.2.tar.gz|' \
  "$BTLS_DIR/server/btls256/nginx.sh"
grep -q 'fossils/zlib-1.3.2.tar.gz' "$BTLS_DIR/server/btls256/nginx.sh" \
  || die "патч URL zlib к nginx.sh эталона не применился — сборка добежит до образа без nginx"
log "⚠ nginx.sh эталона: URL zlib заменён на fossils (версия та же, 1.3.2) — PROCESS.md §5"

docker image inspect "$GW_IMAGE" >/dev/null 2>&1 \
  || die "образа шлюза $GW_IMAGE нет — соберите: docker build -t $GW_IMAGE ."

# ---- сборка образов стенда ---------------------------------------------------------
# btls256 строится ПЕРВЫМ: btls384/512 в эталоне — FROM btls/btls256.
build_stand_image() {
  local name="$1"
  if [ "${STAND_CACHE:-}" = gha ]; then
    # Требует прокинутого ACTIONS_RUNTIME_TOKEN (шаг ghaction-github-runtime в ci.yml):
    # сырой buildx из run-шага сам его не достаёт. ignore-error на cache-to несущий:
    # на форк-PR токен read-only, запись в кэш запрещена — без ignore-error провал
    # ЭКСПОРТА валил бы удавшуюся СБОРКУ, и стенд краснел бы у любого внешнего автора.
    docker buildx build --load \
      --cache-from "type=gha,scope=stand-$name" \
      --cache-to "type=gha,mode=max,scope=stand-$name,ignore-error=true" \
      -t "btls/$name" "$BTLS_DIR/server/$name"
  else
    docker build -t "btls/$name" "$BTLS_DIR/server/$name"
  fi
}
log "== сборка эталонных образов (первая — долгая: bee2evp+OpenSSL из исходников) =="
build_stand_image btls256
build_stand_image btls384
build_stand_image btls512

# Сторож честности сборки: nginx.sh эталона глотает отказы (нет set -e), и образ без
# nginx выглядит собравшимся — падение уехало бы в compose up с невнятным
# «no such file or directory». Провал загрузки обязан быть виден ЗДЕСЬ и с причиной.
docker run --rm btls/btls256 test -x /usr/sbin/nginx \
  || die "эталон собрался БЕЗ nginx — источник сборки уехал снова? (nginx.sh глотает отказы загрузок; смотреть wget-строки в логе сборки)"

# Дрейф, который нельзя удержать: bee2evp в Dockerfile эталона клонируется без пина.
bee2evp_sha=$(docker run --rm btls/btls256 git -C /root/bee2evp rev-parse HEAD)
log "эталон собран с bee2evp ${bee2evp_sha} (в Dockerfile эталона пина нет — дрейф виден этой строкой)"

# Сводка в summary джобы — идиома проекта «не искать в логах»: по этим строкам между
# прогонами видно, дрейфанул ли эталон (digest сменился → кэш пересобрался → bee2evp мог
# уехать). Лог CI эфемерен, summary — тоже, но сравнивать два summary глазами дешевле,
# чем грепать два лога. Локально переменная не задана — блок просто пропускается.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo '## Эталонный стенд'
    echo '```'
    echo "btls pin:  $pin"
    echo "bee2evp:   $bee2evp_sha (в эталоне не запинен)"
    for n in btls256 btls384 btls512; do
      printf '%s:   %s\n' "$n" "$(docker inspect --format '{{.Id}}' "btls/$n")"
    done
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
fi

# ---- подъём стенда -----------------------------------------------------------------
compose up -d
for c in stand-echo stand-btls256 stand-btls384 stand-btls512; do
  bash scripts/wait-healthy.sh "$c"
done

# Слой диагностики ДО матрицы: если прямой s_client из нашего же образа не согласует
# обязательный набор со стендом, чинить надо стенд или стек, а не смотреть на 502 шлюза.
# Проба гоняется по ВСЕМ трём уровням: bee2evp у них общий (384/512 — FROM btls256), а
# вот ключ и сертификат у каждого свои — битый PEM уровня всплыл бы иначе глубоко в
# матрице неотличимо от прочих 502.
s_probe() {
  # s_probe СЕТЬ ПОРТ [доп. аргументы s_client...] — -brief подаёт вызывающий: пробе
  # EMS нужен ПОЛНЫЙ вывод (блок SSL-Session), который -brief подавляет.
  local net="$1" port="$2"; shift 2
  docker run --rm --network "$net" --entrypoint /opt/btls/bin/openssl \
    "$GW_IMAGE" s_client -connect "www.example.org:$port" "$@" </dev/null 2>&1 || true
}
if [ -z "$only" ]; then
for s in 256 384 512; do
  probe=$(s_probe "btls-stand_s$s" 8443 -brief -tls1_2 -cipher DHE-BIGN-WITH-BELT-CTR-MAC-HBELT)
  grep -q 'Ciphersuite: DHE-BIGN-WITH-BELT-CTR-MAC-HBELT' <<<"$probe" \
    || { printf '%s\n' "$probe" >&2; die "btls$s не согласовал обязательный набор прямой пробой — матрица бессмысленна"; }
done
log "ok   стенд говорит BTLS на всех трёх уровнях, обязательный набор согласуется"

# TLS 1.3-порты обязаны быть ЖИВЫМИ до того, как матрица истолкует их 502 как
# «несогласуемо»: healthcheck доказывает только «порт слушает», а здесь — «порт говорит
# TLS». Любой TLS-ответ годится — согласование (если наш стек знает их наборы) или
# alert: оба исхода отличают живой TLS 1.3-вход от порта, за которым ничего нет.
for port in 8447 8448; do
  probe=$(s_probe btls-stand_s256 "$port" -brief -tls1_3)
  grep -Eq 'Ciphersuite:|alert|handshake failure|wrong version' <<<"$probe" \
    || { printf '%s\n' "$probe" >&2; die "порт $port не ответил на уровне TLS — 502 матрицы был бы приписан несогласуемости зря"; }
done
log "ok   TLS 1.3-порты живы — их 502 в матрице означает несогласуемость, не мёртвый порт"
else
  log "⚠ фильтр --only $only: пробы стенда и клетка «чужой корень» пропущены — это свойства полной матрицы"
fi

# ---- extended_master_secret (#80, A1) ----------------------------------------------
# ⚠ НЕ под фильтром --only: флаг заведён ради итераций A1, и выключать им саму
# EMS-пробу значило бы дать разработчику зелёный лог без единой проверки того, что он
# правит. Проба дешёвая — два s_client, шлюзы не поднимает.
# Требование ОАЦ от 12.05.2025: RFC 7627 либо иной механизм защиты от Triple Handshake;
# проверяется при испытаниях (CERTIFICATION.md §0.4). Патч BTLS механизм EMS не трогает
# (проверено по openssl-3.5.6.patch: правки extensions — ECC-гейт на BIGN в clnt и гейт
# ETM для BELTCTR в srvr, оба к EMS отношения не имеют; t1_enc.c с session_hash патчем
# не задет), но «не трогает» — не доказательство: здесь оно снимается ЖИВЬЁМ, на
# обязательном наборе против эталона. Два независимых свидетельства:
#   - -tlsextdebug печатает расширения ServerHello: эталон ВЕРНУЛ extension 23 —
#     протокольный факт согласования;
#   - строка сессии «Extended master secret: yes» — итог, вошедший в ключевой материал.
# ems_dump — вывод пробы для диагностики провала БЕЗ строки Master-Key: полный
# s_client печатает master secret сессии, а правило «ключи не логируем... ни в вывод
# CI» написано без исключений «кроме оснастки». Для диагноза EMS он и не нужен.
ems_dump() { grep -v 'Master-Key:' <<<"$1" >&2; }
ems=$(s_probe btls-stand_s256 8443 -tlsextdebug -tls1_2 -cipher DHE-BIGN-WITH-BELT-CTR-MAC-HBELT)
grep -qi 'server extension "extended master secret"' <<<"$ems" \
  || { ems_dump "$ems"; die "эталон не вернул extended_master_secret в ServerHello — RFC 7627 не согласован (блокер испытаний, #80)"; }
grep -q 'Extended master secret: yes' <<<"$ems" \
  || { ems_dump "$ems"; die "сессия без extended master secret — расширение вернулось, но в ключевой материал не вошло (#80)"; }
# Проверка обязана уметь краснеть, и негатив -no_ems сторожит ОБЕ стороны:
#   - строка «no» обязана появиться — иначе грепу «no» не с чем работать;
#   - позитивные паттерны обязаны ИСЧЕЗНУТЬ — иначе ослабленный позитивный греп
#     (скажем, без слова yes) оставался бы зелёным и при отсутствии расширения.
#     Это и есть мутационный негатив для позитивных грепов, а не только для своего.
# -tlsextdebug и здесь несущий: без него строка server extension отсутствовала бы
# тривиально — потому что не печатается, а не потому что расширение не согласовано.
ems_off=$(s_probe btls-stand_s256 8443 -tlsextdebug -no_ems -tls1_2 -cipher DHE-BIGN-WITH-BELT-CTR-MAC-HBELT)
grep -q 'Extended master secret: no' <<<"$ems_off" \
  || { ems_dump "$ems_off"; die "с -no_ems сессия не сказала «no» — проба EMS не отличает наличие от отсутствия"; }
if grep -qi 'server extension "extended master secret"' <<<"$ems_off"; then
  ems_dump "$ems_off"; die "с -no_ems эталон «вернул» расширение — греп ServerHello ослаблен и не отличает наличие от отсутствия"
fi
if grep -q 'Extended master secret: yes' <<<"$ems_off"; then
  ems_dump "$ems_off"; die "с -no_ems сессия «сказала yes» — позитивный греп ослаблен и не отличает наличие от отсутствия"
fi
log "ok   extended_master_secret предлагается и согласуется с эталоном (RFC 7627); проба краснеет, если -no_ems не даёт «no»"

# ---- матрица: три уровня стойкости × шесть портов ----------------------------------
declare -A EXPECT=(
  [8443]='DHE-BIGN-WITH-BELT-CTR-MAC-HBELT'
  [8444]='DHE-BIGN-WITH-BELT-DWP-HBELT'
  [8445]='DHT-BIGN-WITH-BELT-CTR-MAC-HBELT'
  [8446]='DHT-BIGN-WITH-BELT-DWP-HBELT'
)

run_gw() {
  # run_gw ИМЯ СЕТЬ ПОРТ_АПСТРИМА HOST_PORT [доп. аргументы docker run...]
  local name="$1" net="$2" uport="$3" hport="$4"; shift 4
  # --health-interval: у образа 30s — для одиночного контейнера в бою правильно, для
  # девятнадцати последовательных запусков матрицы означало бы ~10 минут чистого ожидания.
  # Остальные health-флаги переопределены В СОГЛАСИИ с wait-healthy.sh (40 секунд):
  # с образными timeout=5s/start-period=15s docker объявил бы unhealthy только к ~55-й
  # секунде — wait-healthy падал бы раньше, чем docker закончил решать, ложным красным.
  docker run -d --name "$name" --network "$net" -p "127.0.0.1:$hport:1080" \
    --health-interval=2s --health-timeout=3s --health-start-period=5s --health-retries=15 \
    -e GW_UPSTREAM_HOST=www.example.org -e GW_UPSTREAM_PORT="$uport" \
    -e GW_ALLOW='GET =/check_server' \
    "$@" "$GW_IMAGE" >/dev/null
  bash scripts/wait-healthy.sh "$name"
}

fails=0
rows=()
hport=17300
for s in 256 384 512; do
  for port in 8443 8444 8445 8446 8447 8448; do
    hport=$((hport + 1))
    only_match "$s" "$port" || continue
    name="gw-stand-$s-$port"
    run_gw "$name" "btls-stand_s$s" "$port" "$hport" \
      -v "$BTLS_DIR/server/btls$s/cert$s.pem:/etc/crypto-gw/ca/gossuok-bundle.pem:ro"
    reply=$(curl -s --max-time 20 -w '\n%{http_code}' "http://127.0.0.1:$hport/check_server" || true)
    code=${reply##*$'\n'}
    body=${reply%$'\n'*}
    if [[ -n "${EXPECT[$port]:-}" ]]; then
      want=${EXPECT[$port]}
      # Якорь `^набор#` несущий: в теле дальше идёт $ssl_ciphers со ВСЕМИ четырьмя
      # именами, и грep без якоря был бы зелёным на любом согласованном наборе.
      if [ "$code" = 200 ] && grep -q "^${want}#" <<<"$body"; then
        verdict="ok   $want"
      else
        verdict="FAIL код=$code ожидалось 200 и набор $want; тело: $(head -c 160 <<<"$body")"
        fails=$((fails + 1))
        docker logs "$name" 2>&1 | tail -15 >&2
      fi
    else
      if [ "$code" = 502 ]; then
        verdict='ok   несогласуемо (порт TLS 1.3-only, шлюз — TLS 1.2)'
      else
        verdict="FAIL код=$code, ожидался 502: TLS 1.3-only порт не должен согласоваться"
        fails=$((fails + 1))
        docker logs "$name" 2>&1 | tail -15 >&2
      fi
    fi
    rows+=("btls$s :$port  $verdict")
    docker rm -f "$name" >/dev/null
  done
done

# ---- доверие не наследуется: штатная связка ГосСУОК против стенда ------------------
# Без этого отрицательного случая матрица выше не стоит ничего: сними кто-нибудь
# `proxy_ssl_verify on` — все 12 положительных клеток остались бы зелёными.
if [ -z "$only" ]; then
hport=$((hport + 1))
# GW_ERROR_LOG_LEVEL=error несущий: умолчание crit НАМЕРЕННО душит [error]-строки nginx
# (там полная строка запроса с идентификаторами — entrypoint.sh об этом прямо), а
# verify-ошибка апстрима пишется ровно на error и на crit в лог не попадает вовсе.
# Здесь это безопасно: оснастка, /check_server, чувствительных данных в запросе нет.
run_gw gw-stand-badtrust btls-stand_s256 8443 "$hport" -e GW_ERROR_LOG_LEVEL=error
bad_code=$(curl -s --max-time 20 -o /dev/null -w '%{http_code}' \
  "http://127.0.0.1:$hport/check_server" || true)
bad_log=$(docker logs gw-stand-badtrust 2>&1)
docker rm -f gw-stand-badtrust >/dev/null
if [ "$bad_code" = 502 ] && grep -q 'certificate verify' <<<"$bad_log"; then
  rows+=("btls256:8443  ok   чужой корень отвергнут (502, verify-ошибка в логе)")
else
  rows+=("btls256:8443  FAIL код=$bad_code — связка ГосСУОК не должна подтверждать стенд")
  fails=$((fails + 1))
  printf '%s\n' "$bad_log" | tail -15 >&2
fi
fi

# ---- итог --------------------------------------------------------------------------
log ""
log "== матрица стенда (эталон btls@${pin:0:12}, bee2evp@${bee2evp_sha:0:12}) =="
for row in "${rows[@]}"; do log "  $row"; done
log ""
if [ "$fails" -gt 0 ]; then
  die "клеток с расхождением: $fails"
fi
if [ -n "$only" ]; then
  # Пустое пересечение — ошибка вызова, а не «всё сошлось»: зелёный на нуле клеток
  # был бы худшим исходом фильтра.
  [ "${#rows[@]}" -gt 0 ] || die "фильтр --only $only не совпал ни с одной клеткой (уровни 256/384/512, порты 8443–8448)"
  log "клетки по фильтру --only $only сходятся (${#rows[@]} шт.); полная матрица НЕ гонялась"
else
  log "все клетки матрицы сходятся: 12 согласований, 6 отказов TLS 1.3, отказ по доверию; EMS согласован"
fi
