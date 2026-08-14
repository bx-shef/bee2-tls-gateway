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

# Наш openssl, а не первый по PATH: стоковый не читает ключи bign В ПРИНЦИПЕ, и подмена
# PATH превратила бы эту проверку в проверку неизвестно чего.
OPENSSL_BIN="${GW_OPENSSL:-/opt/btls/bin/openssl}"
[ -x "$OPENSSL_BIN" ] || { echo "нет патченного openssl: $OPENSSL_BIN" >&2; exit 1; }

# Единственная форма genpkey, которая работает. Замерено: без `-pkeyopt params:` движок
# отвечает `Error generating bign-pubkey key`, а `req -newkey bign-curve256v1` не знает
# такой формы вовсе. Кто соберётся «упростить» — сначала прогоните, потом упрощайте.
KEYSPEC=(-algorithm bign-pubkey -pkeyopt params:bign-curve256v1)
# Хеш подписи. `belt-hash` — тот, которым подписывается и настоящая цепочка ГосСУОК;
# `sha256` движок тоже принимает, но проверять надо то, что бывает в проде.
MD=belt-hash

mkdir -p "$OUT"

"$OPENSSL_BIN" genpkey -engine bee2evp "${KEYSPEC[@]}" -out "$OUT/ca.key" 2>/dev/null
"$OPENSSL_BIN" genpkey -engine bee2evp "${KEYSPEC[@]}" -out "$OUT/leaf.key" 2>/dev/null

"$OPENSSL_BIN" req -engine bee2evp -x509 -new -key "$OUT/ca.key" -"$MD" \
  -days 2 -subj '/CN=btls-test-ca' -out "$OUT/ca.crt" 2>/dev/null

"$OPENSSL_BIN" req -engine bee2evp -new -key "$OUT/leaf.key" -"$MD" \
  -subj "/CN=$HOST" -out "$OUT/leaf.csr" 2>/dev/null

# SAN обязателен: `proxy_ssl_verify on` проверяет ИМЯ, а не только цепочку, и по одному
# лишь CN современный OpenSSL имя не сверяет.
"$OPENSSL_BIN" x509 -req -in "$OUT/leaf.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
  -"$MD" -days 2 -CAcreateserial -out "$OUT/leaf.crt" \
  -extfile <(printf 'subjectAltName=DNS:%s\n' "$HOST") 2>/dev/null

# Гейт: собранная цепочка обязана сходиться ЗДЕСЬ. Иначе проверка ниже по течению
# покраснела бы на рукопожатии, и разбирались бы с nginx вместо разбирательства с PKI.
"$OPENSSL_BIN" verify -CAfile "$OUT/ca.crt" "$OUT/leaf.crt" >/dev/null \
  || { echo 'FAIL: выпущенная цепочка не сходится сама с собой' >&2; exit 1; }

# Ключи не должны быть видны никому, кроме владельца, даже одноразовые.
chmod 600 "$OUT/ca.key" "$OUT/leaf.key"
chmod 644 "$OUT/ca.crt" "$OUT/leaf.crt"

echo "BTLS-фикстура готова в $OUT: УЦ btls-test-ca, лист $HOST, подпись $MD"
