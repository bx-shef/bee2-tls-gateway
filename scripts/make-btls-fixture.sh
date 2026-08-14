#!/usr/bin/env bash
# Issue a throwaway BTLS PKI: test CA + server leaf signed by it.
#
# Зачем это существует. Проверок цепочки в шлюзе две, и они идут РАЗНЫМ кодом:
# `openssl verify` в entrypoint.sh §2 (утилита, при старте) и
# `proxy_ssl_trusted_certificate` внутри nginx (библиотека, на каждом соединении).
# Через вторую идёт 100% боевого трафика, и до #58 её не проверяло ничто: живой банк
# из CI недостижим, порт 9345 закрыт наглухо.
#
# Выход — не ждать банка, а поднять BTLS-сервер СВОИМИ силами. Замерено 14.08.2026:
# наш стек это умеет, и рукопожатие идёт на обязательном криптонаборе
# (`Ciphersuite: DHE-BIGN-WITH-BELT-CTR-MAC-HBELT`, `Signature type: bign128`).
#
# ⚠ Что этот PKI доказывает, а что нет. Он доказывает МЕХАНИЗМ: лишний якорь доверия в
# связке не мешает nginx проверить цепочку и договориться. Он НЕ доказывает, что подойдёт
# настоящий новый корень ГосСУОК и что с ним договорится настоящий банк — это остаётся
# ручным прогоном владельца, docs/PROCESS.md §4.
#
# ⚠ Ключи здесь ОДНОРАЗОВЫЕ и живут два дня. Их содержимое не печатается никуда: репозиторий
# публичный, а привычка печатать ключ в лог переносится на непубличные. В `ca/` результат
# не едет и в образ не попадает — scripts/ монтируется, а не копируется (объект испытаний
# от этого не растёт).
#
# Запуск — ВНУТРИ образа, иначе стоковый openssl не знает bign:
#   docker run --rm -v /куда:/pki --entrypoint bash bee2-tls-gateway:ci \
#     /scripts/make-btls-fixture.sh /pki btls-probe-upstream
set -euo pipefail

OUT="${1:?куда класть PKI (каталог)}"
HOST="${2:-btls-probe-upstream}"
# CN УЦ выводится из имени листа: две фикстуры в одном прогоне обязаны быть различимы
# по subject, иначе «два якоря» на глаз читались бы как один и тот же.
CA_CN="btls-test-ca-$HOST"

# Наш openssl, ЖЁСТКИМ путём и без переменной-переключателя. Стоковый не читает ключи
# bign в принципе, поэтому подмена превратила бы проверку в проверку неизвестно чего.
# ⚠ Переменная вида GW_OPENSSL здесь была и убрана осознанно: это не выключатель, а
# способ ПОДДЕЛАТЬ УСПЕХ. Обёртка, зовущая стоковый openssl, выпустила бы RSA-PKI,
# гейт `verify` ниже прошёл бы, nginx договорился бы с не-BTLS сервером — и утверждение
# «шлюз говорит на обязательном криптонаборе» исчезло бы при зелёном CI. Тем же местом
# и по той же причине из entrypoint.sh убран GW_BEE2CMD.
OPENSSL_BIN=/opt/btls/bin/openssl
[ -x "$OPENSSL_BIN" ] || { echo "нет патченного openssl: $OPENSSL_BIN" >&2; exit 1; }

# Причина отказа обязана называть себя — это цель 2 проекта, и глушить stderr у openssl
# значит нарушать её ровно там, где сломается труднее всего: формы команд ниже найдены
# замером и завязаны на версию движка. Без этой обёртки поломка даёт `exit 1` без слов.
# ⚠ stderr этих команд несёт диагностику, а не байты ключа: ни у одной нет `-text`,
# и добавлять его сюда нельзя — репозиторий публичный, вывод CI тоже.
run_ssl() {
  local what="$1"; shift
  local err
  if ! err=$("$OPENSSL_BIN" "$@" 2>&1 >/dev/null); then
    printf 'FAIL: %s\n%s\n' "$what" "$err" >&2
    exit 1
  fi
}

# Единственная форма genpkey, которая работает. Замерено: без `-pkeyopt params:` движок
# отвечает `Error generating bign-pubkey key`, а `req -newkey bign-curve256v1` не знает
# такой формы вовсе. Кто соберётся «упростить» — сначала прогоните, потом упрощайте.
KEYSPEC=(-algorithm bign-pubkey -pkeyopt params:bign-curve256v1)
# Хеш подписи. `belt-hash` — тот, которым подписывается и настоящая цепочка ГосСУОК;
# `sha256` движок тоже принимает, но проверять надо то, что бывает в проде.
MD=belt-hash

mkdir -p "$OUT"

run_ssl "ключ УЦ" genpkey -engine bee2evp "${KEYSPEC[@]}" -out "$OUT/ca.key"
run_ssl "ключ листа" genpkey -engine bee2evp "${KEYSPEC[@]}" -out "$OUT/leaf.key"

run_ssl "самоподписанный УЦ" req -engine bee2evp -x509 -new -key "$OUT/ca.key" -"$MD" \
  -days 2 -subj "/CN=$CA_CN" -out "$OUT/ca.crt"

run_ssl "запрос на лист" req -engine bee2evp -new -key "$OUT/leaf.key" -"$MD" \
  -subj "/CN=$HOST" -out "$OUT/leaf.csr"

# SAN обязателен: `proxy_ssl_verify on` проверяет ИМЯ, а не только цепочку, и по одному
# лишь CN современный OpenSSL имя не сверяет.
run_ssl "подпись листа" x509 -req -in "$OUT/leaf.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -"$MD" -days 2 -CAcreateserial -out "$OUT/leaf.crt" \
  -extfile <(printf 'subjectAltName=DNS:%s\n' "$HOST")

# Гейт: собранная цепочка обязана сходиться ЗДЕСЬ. Иначе проверка ниже по течению
# покраснела бы на рукопожатии, и разбирались бы с nginx вместо разбирательства с PKI.
run_ssl "цепочка сходится сама с собой" verify -CAfile "$OUT/ca.crt" "$OUT/leaf.crt"

# Ключи не должны быть видны никому, кроме владельца, даже одноразовые.
chmod 600 "$OUT/ca.key" "$OUT/leaf.key"
chmod 644 "$OUT/ca.crt" "$OUT/leaf.crt"

echo "BTLS-фикстура готова в $OUT: УЦ $CA_CN, лист $HOST, подпись $MD"
