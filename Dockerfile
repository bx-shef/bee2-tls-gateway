# syntax=docker/dockerfile:1
#
# Crypto gateway for Priorbank production (#460).
#
# WHAT IT IS. Priorbank's production Open Banking host speaks TLS with Belarusian
# ciphersuites (STB 34.101.65 / BTLS). Node — and every stock TLS stack — aborts at
# ServerHello with "unknown cipher returned". This image is an nginx that terminates
# ordinary plain HTTP on the inside and re-originates the request to the bank over a
# BTLS session, using the OPEN implementation (bee2 + bee2evp, Apache 2.0), so we do
# not depend on the proprietary vendor (#41, #457).
#
# WHY nginx AND NOT A TCP TUNNEL (stunnel/socat). Two reasons, both measured:
#   - a TCP tunnel cannot rewrite the Host header, so the bank would receive
#     `Host: crypto-gw:1080` and reject the request;
#   - the BIGN handshake is expensive, and `keepalive` amortises it across a whole
#     poll (~10 HTTP requests collapse onto one upstream TLS session).
# nginx also closes chain AND hostname verification with one directive
# (`proxy_ssl_verify on`), which stunnel does not — its `verifyChain` alone accepts
# ANY certificate issued by the same CA.
#
# The compiler never reaches the runtime image: OpenSSL, the engine and nginx are all
# built in throwaway stages (that is the point of the issue title).
#
# Build/run: see README.md next to this file.

# ---------------------------------------------------------------------------------
# Pins. Everything that can drift is nailed down here — a "latest" base or a mutable
# git tag turns a reproducible crypto build into a lottery.
# ---------------------------------------------------------------------------------
# debian:12-slim, amd64+arm64 manifest list, pushed 2026-08-05.
ARG DEBIAN_IMAGE=debian:12-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
# bee2evp pinned by COMMIT, not tag: its build script clones bee2 as a submodule, so
# this one sha pins the whole crypto stack (engine + bee2 + the BTLS patch).
ARG BEE2EVP_COMMIT=2ae3c71e8b24b6904367850e5963933236a1539f
# OpenSSL tag the BTLS patch is written against — btls/patch/<tag>.patch must exist.
# ⚠ 3.5 is the LTS branch (supported to 2030). Do NOT drop back to 3.3.1 just because more
# of bee2evp's own CI runs on it: 3.3 left security support on 2026-04-09 and already
# carries CVE-2024-6119 — a crash in the peer-certificate NAME CHECK, which is exactly what
# `proxy_ssl_verify on` + `proxy_ssl_name` make this image do on every request to the bank.
# Verified locally with this pin: engine available, 8 BTLS suites, GosSUOK chain verifies.
ARG OPENSSL_TAG=openssl-3.5.6
# ⚠ Ушли с ветки 1.28 (была 1.28.0) на STABLE 1.30.x, и это не гигиена, а закрытие двух дыр.
#   - CVE-2026-1642, SSL upstream injection: при проксировании на TLS-апстрим атакующий с
#     MITM-позиции со стороны апстрима мог внедрить открытый текст в ответ. Ровно то, чем
#     занят образ. Исправлено в 1.28.2+.
#   - CVE-2026-42533, heap overflow, severity major. Срабатывает в двух случаях: capture-группы
#     в regex у `map` (у нас их нет) ЛИБО не кэшируемая переменная в строковом выражении —
#     а `proxy_pass https://bank$uri$is_args$args` это оно и есть: `$args` и `$is_args`
#     объявлены NGX_HTTP_VAR_NOCACHEABLE. Исправление — bounds-check
#     `ngx_http_script_check_length`, и в 1.30.4 он стоит В ТОМ ЧИСЛЕ в ngx_http_proxy_module.c,
#     то есть ровно на нашем пути. В ветке 1.28 этой функции нет вообще и не будет: ветка
#     legacy, а «Not vulnerable» у advisory перечисляет только 1.31.3+ и 1.30.4+.
# ⚠ Смена минорной версии на платёжном пути: после бампа ОБЯЗАТЕЛЕН живой прогон против
#   банка (README § «Проверено вживую»), сборка и смоук его не заменяют. См. #15.
ARG NGINX_VERSION=1.30.4
# sha256 снят с архива, скачанного с nginx.org, и проверен двумя способами: тем же приёмом
# заново посчитан хеш прежнего пина 1.28.0 и совпал с ним (значит способ верный), а сам
# архив несёт годную подпись сопровождающего (ключ nginx.org/keys/arut.key).
ARG NGINX_SHA256=4261dc90e9e47c1c4041276e9aaa3d48ebe2e664f728e14fa95ae6c67d57a08b

# =================================================================================
# Stage 1 — BTLS: OpenSSL patched with the STB 34.101.65 ciphersuites + bee2evp engine
# =================================================================================
FROM ${DEBIAN_IMAGE} AS btls

ARG BEE2EVP_COMMIT
ARG OPENSSL_TAG
ENV DEBIAN_FRONTEND=noninteractive

# No libssl-dev on purpose: the only OpenSSL headers in this stage must be the ones we
# build ourselves, or nginx below could silently compile against the system's stock
# OpenSSL and come out without a single BTLS suite.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git gcc g++ make cmake perl python3 libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone https://github.com/bcrypto/bee2evp bee2evp \
 && git -C bee2evp checkout --quiet "${BEE2EVP_COMMIT}" \
 && test "$(git -C bee2evp rev-parse HEAD)" = "${BEE2EVP_COMMIT}"

# ⚠ UPSTREAM BUG, worked around here. scripts/source.sh decides the OpenSSL build type
# with `[[ "$build_type" -eq "Debug" ]]` — `-eq` is NUMERIC comparison, and bash coerces
# both strings to 0, so the test is ALWAYS true and OpenSSL is ALWAYS configured with
# `--debug` (-O0, no optimisation). Verified in the build log. For a gateway whose whole
# job is an expensive BIGN handshake that is not cosmetic. Fix the operator, don't touch
# the crypto.
RUN sed -i 's/"\$build_type" -eq "Debug"/"$build_type" == "Debug"/' /src/bee2evp/scripts/source.sh \
 && grep -q '"\$build_type" == "Debug"' /src/bee2evp/scripts/source.sh

# ⚠ ЧУЖОЙ ПАТЧ, принятый до мержа в апстриме — не наша правка криптоядра.
# agievich/bee2 PR #77 чинит их же issue #76: rngJitterIsAvail() (проверка доступности
# источника энтропии `jitter`) сама поднимает поток-счётчик, а закрывается он только
# через utilOnExit — при выходе процесса. rngCreate() опрашивает все источники
# безусловно, поэтому ЛЮБОЙ процесс с bee2 жёг одно ядро всю свою жизнь (#8).
# Замерено: user 5,089 с без патча против 0,064 с с патчем на процессе, который только
# спит пять секунд; st alg и st rng после патча проходят.
# ⚠ Патч висит в апстриме без ревью с 18.06.2026. Смержат — удалить отсюда и сдвинуть
# BEE2EVP_COMMIT на версию с исправлением; своего форка bee2 не заводим.
# Подмодуль инициализируем САМИ до сборки: build.sh делает `git submodule update --init`
# без --force, и на уже выставленном коммите это но-оп, поэтому патч доживает до compile.
COPY patches/bee2-pr77-jitter-thread.patch /src/patches/
RUN cd /src/bee2evp && git submodule update --init \
 && git -C bee2 apply /src/patches/bee2-pr77-jitter-thread.patch \
 && grep -q '_tm_ctr_close_registered' bee2/src/core/rng/rng_timer.c

ENV BEE2EVP_INSTALL_DIR=/opt/btls
# Вторая проверка того же маркера — уже ПОСЛЕ сборки: она доказывает, что build.sh не
# откатил подмодуль и компилировался пропатченный исходник. Без неё патч мог бы тихо
# исчезнуть, а образ собрался бы зелёным с прежним busy-loop.
RUN cd /src/bee2evp && bash scripts/build.sh -s -b "${OPENSSL_TAG}" \
 && grep -q '_tm_ctr_close_registered' bee2/src/core/rng/rng_timer.c

# Gate 1 — the stack is actually a BTLS stack. Without this the image builds fine and
# fails at the first bank request, which is the most expensive place to find out.
# `-O0` in the compile line would mean the sed above stopped working.
RUN set -eu; \
    export LD_LIBRARY_PATH=/opt/btls/lib; \
    /opt/btls/bin/openssl version; \
    /opt/btls/bin/openssl engine -t bee2evp | grep -q 'available'; \
    /opt/btls/bin/openssl ciphers -v 'ALL:eNULL' | grep -q 'DHE-BIGN-WITH-BELT-CTR-MAC-HBELT'; \
    /opt/btls/bin/openssl ciphers -v 'ALL:eNULL' | grep -q 'DHT-BIGN-WITH-BELT-CTR-MAC-HBELT'; \
    echo 'BTLS suites present'

# bee2cmd — эталонная утилита самого bee2: `st alg` гоняет контрольные примеры стандартов
# (СТБ 34.101.31/.45/.47/.77), `st rng` — самотест ДСЧ, `es print` — здоровье источников
# энтропии. Она едет в рантайм-образ и там становится САМОТЕСТОМ ПРИ СТАРТЕ (#18), а не
# просто инструментом: см. README § «Самотестирование криптостека», где эта возможность
# описана как документированная — именно этого требует СТБ 34.101.27, и именно это
# снимает возражение «лишний бинарь увеличивает объект испытаний» (#19).
#
# ⚠ Собирается ИЗ ПОДМОДУЛЯ `/src/bee2evp/bee2`, а не отдельным клоном. Это не экономия
# времени, а инвариант: подмодуль уже выставлен на коммит, соответствующий запиненному
# BEE2EVP_COMMIT, и уже несёт патч PR #77. Отдельный клон пришлось бы пинить вторым
# числом, и он разошёлся бы с образом молча — ровно то, что `scripts/check-pins.sh`
# вынужден сторожить у `check-crypto.sh` (там клон отдельный, потому что скрипт умеет
# работать и вне образа).
#
# Самотест прогоняется ПРЯМО ЗДЕСЬ и падает сборкой: криптостек, который не сходится с
# контрольными примерами стандарта, не должен доехать до рантайма ни при каких условиях.
RUN set -eu; \
    cmake -S /src/bee2evp/bee2 -B /src/bee2-build -DCMAKE_BUILD_TYPE=Release > /dev/null; \
    cmake --build /src/bee2-build --parallel > /dev/null; \
    install -m 0755 /src/bee2-build/cmd/bee2cmd /opt/btls/bin/bee2cmd; \
    /opt/btls/bin/bee2cmd st alg; \
    /opt/btls/bin/bee2cmd st rng; \
    echo 'bee2cmd built from the pinned submodule; st alg and st rng passed'

# Тексты лицензий берём ИЗ ТОГО ЖЕ дерева, которое только что собрали, а не переписываем
# в репозиторий руками: переписанная копия расходится с апстримом молча и ровно тогда,
# когда её придёт читать аудитор. `set -eu` + явный cp делают это гейтом — переедет
# апстрим свой LICENSE.txt, и сборка встанет здесь, а не отдаст образ без атрибуции.
# Пути заданы bee2evp: scripts/source.sh кладёт bee2 в ./bee2, а openssl клонирует в
# ./openssl рядом с ними.
RUN set -eu; \
    mkdir -p /licenses; \
    cp /src/bee2evp/LICENSE.txt         /licenses/bee2evp-LICENSE.txt; \
    cp /src/bee2evp/bee2/LICENSE.txt    /licenses/bee2-LICENSE.txt; \
    cp /src/bee2evp/openssl/LICENSE.txt /licenses/openssl-LICENSE.txt; \
    echo 'licenses collected: bee2evp, bee2, openssl'

# ⚠ whereami — ТРЕТЬЯ СТОРОНА ВНУТРИ bee2, и до #19 её здесь не было по честной причине:
# она компилируется только в `bee2cmd`, а `bee2cmd` в образ не ехал. Теперь едет (самотест
# при старте), значит едет и этот код — и его атрибуция стала обязательной.
# ⚠ Отдельного файла лицензии у него нет: она живёт заголовком в самом исходнике. Поэтому
# вырезаем заголовок ИЗ СОБРАННОГО ДЕРЕВА, а не переписываем руками — то же правило, что и
# выше: переписанная копия расходится с апстримом молча.
RUN set -eu; \
    { echo 'whereami — third-party code inside bee2 (bee2/cmd/core/whereami.c),'; \
      echo 'compiled into the bee2cmd binary that this image ships.'; \
      echo 'Verbatim licence header from the source tree this image was built from:'; \
      echo; \
      sed -n '1,4p' /src/bee2evp/bee2/cmd/core/whereami.c; \
    } > /licenses/whereami-LICENSE.txt; \
    grep -q 'WTFPL' /licenses/whereami-LICENSE.txt; \
    grep -q 'MIT' /licenses/whereami-LICENSE.txt; \
    grep -q 'Gregory Pakosz' /licenses/whereami-LICENSE.txt; \
    echo 'licenses collected: whereami (shipped inside bee2cmd)'

# =================================================================================
# Stage 2 — nginx linked against THAT OpenSSL
# =================================================================================
FROM btls AS nginx-build

ARG NGINX_VERSION
ARG NGINX_SHA256
# Needed by the gate below, which must assert the version we actually pinned rather than
# a literal that drifts the moment OPENSSL_TAG is bumped.
ARG OPENSSL_TAG
ENV DEBIAN_FRONTEND=noninteractive

# PCRE2 is not optional: `return`/`set` live in the rewrite module, which needs it.
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl libpcre2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN curl -fsSLO "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
 && echo "${NGINX_SHA256}  nginx-${NGINX_VERSION}.tar.gz" | sha256sum -c - \
 && tar xzf "nginx-${NGINX_VERSION}.tar.gz"

# Only what a forward proxy to one HTTPS upstream needs. Everything else is surface we
# would have to keep patched for no benefit. Logs go to the container's streams
# (--error-log-path=stderr) so `docker logs` is the whole story.
RUN cd "nginx-${NGINX_VERSION}" && ./configure \
      --prefix=/opt/nginx \
      --sbin-path=/opt/nginx/sbin/nginx \
      --conf-path=/opt/nginx/conf/nginx.conf \
      --pid-path=/tmp/crypto-gw.pid \
      --error-log-path=stderr \
      --http-log-path=/dev/stdout \
      --http-client-body-temp-path=/tmp/nginx-body \
      --http-proxy-temp-path=/tmp/nginx-proxy \
      --with-http_ssl_module \
      --without-http_gzip_module \
      --without-http_auth_basic_module \
      --without-http_autoindex_module \
      --without-http_browser_module \
      --without-http_empty_gif_module \
      --without-http_fastcgi_module \
      --without-http_geo_module \
      --without-http_memcached_module \
      --without-http_referer_module \
      --without-http_scgi_module \
      --without-http_ssi_module \
      --without-http_split_clients_module \
      --without-http_userid_module \
      --without-http_uwsgi_module \
      --without-mail_pop3_module \
      --without-mail_imap_module \
      --without-mail_smtp_module \
      --with-cc-opt="-I/opt/btls/include -O2" \
      --with-ld-opt="-L/opt/btls/lib -Wl,-rpath,/opt/btls/lib" \
 && make -j"$(nproc)" \
 && make install

# Gate 2 — nginx really links OUR OpenSSL. `nginx -V` reporting the version it compiled
# against is not enough (headers and libs can disagree); check the actual DT_NEEDED
# resolution instead.
# The expected version is DERIVED from OPENSSL_TAG (`openssl-3.5.6` → `3.5.6`), not written
# out. A hardcoded literal here is a gate that silently rots into a false failure on the next
# bump — which is exactly what happened on the first bump, so it is not hypothetical.
RUN set -eu; \
    expected="${OPENSSL_TAG#openssl-}"; \
    /opt/nginx/sbin/nginx -V 2>&1 | grep -q "built with OpenSSL ${expected}"; \
    ldd /opt/nginx/sbin/nginx | grep -E 'libssl|libcrypto' | grep -q '/opt/btls/lib'; \
    echo "nginx linked against the patched OpenSSL ${expected}"

# Та же логика, что и для криптостека: лицензия nginx едет из распакованного архива,
# который сейчас собирали. /licenses уже существует — стадия наследует его от `btls`.
RUN set -eu; \
    cp "/src/nginx-${NGINX_VERSION}/LICENSE" /licenses/nginx-LICENSE; \
    echo 'licenses collected: nginx'

# =================================================================================
# Stage 3 — runtime. No compiler, no git, no source.
# =================================================================================
FROM ${DEBIAN_IMAGE} AS crypto-gw

ENV DEBIAN_FRONTEND=noninteractive
# gettext-base = envsubst (renders the config template); libpcre2 = nginx rewrite module.
# Deliberately NO ca-certificates: the bank is verified against the GosSUOK bundle we
# mount, never against the public web PKI, and an unused trust store is just rot.
RUN apt-get update && apt-get install -y --no-install-recommends \
      gettext-base libpcre2-8-0 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin gw

COPY --from=btls /opt/btls/lib/libcrypto.so.3 /opt/btls/lib/libssl.so.3 /opt/btls/lib/libbee2evp.so /opt/btls/lib/
COPY --from=btls /opt/btls/bin/openssl /opt/btls/bin/openssl
# ⚠ ДОКУМЕНТИРОВАННАЯ ВОЗМОЖНОСТЬ, а не инструмент, забытый в образе. bee2cmd здесь ради
# самотеста при старте (entrypoint.sh §0) — требование СТБ 34.101.27 к изделию, и так же
# сделано в сертифицированном AvTunProxy, который печатает `self-test result: OK` в первых
# строках лога. Описана в README § «Самотестирование криптостека»; решение положить её
# именно в рантайм — docs/PROCESS.md §5 и docs/CERTIFICATION.md §6.
COPY --from=btls /opt/btls/bin/bee2cmd /opt/btls/bin/bee2cmd
COPY --from=btls /opt/btls/openssl.cnf /opt/btls/openssl.cnf
COPY --from=nginx-build /opt/nginx /opt/nginx

# The engine is wired in through openssl.cnf (`dynamic_path = /opt/btls/lib/libbee2evp.so`),
# which OpenSSL loads on library init — that is how nginx picks up bign/belt without a
# single nginx directive.
# ⚠ That path is BAKED into openssl.cnf from BEE2EVP_INSTALL_DIR at build time, and the
# copies below must land on exactly the same prefix. Move one without the other and the
# engine simply is not there — no error at startup, just "unknown cipher" at the bank.
# Verified: this exact file set (libcrypto.so.3, libssl.so.3, libbee2evp.so, openssl.cnf)
# is enough — the engine needs nothing else, and only the built-in `default` provider is
# enabled, so lib/ossl-modules is deliberately not copied.
ENV LD_LIBRARY_PATH=/opt/btls/lib \
    OPENSSL_CONF=/opt/btls/openssl.cnf \
    PATH=/opt/btls/bin:/opt/nginx/sbin:/usr/local/bin:/usr/bin:/bin

COPY ca/ /etc/crypto-gw/ca/
COPY nginx.conf.template /etc/crypto-gw/nginx.conf.template
COPY entrypoint.sh healthcheck.sh /usr/local/bin/
RUN chmod 0755 /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh

# Gate 3 — SEMANTIC chain check, and the reason this line exists at all: a bundle that
# holds only the root passes `openssl x509 -subject` and passes `nginx -t`, and then
# 100% of production traffic 502s with "unable to get local issuer certificate". Only
# an actual verify catches it. It doubles as proof that the engine can parse bign keys
# (stock OpenSSL cannot: X509_PUBKEY_get0 decode error).
# `-no_check_time` on purpose (same as entrypoint.sh): the reference leaf signs nothing
# and is only a verification TARGET, so what is being asserted here is that the chain
# links — not that the target is still valid. Without the flag every build of this image
# would start failing on 2027-12-06 when that certificate expires, red-lighting CI on
# unrelated PRs.
# The cipher check is repeated here rather than trusted from the build stage: gates 1 and 2
# ran against the FULL build tree, and what ships is a hand-picked subset of files. Only a
# check over the copied set proves the thing that actually gets deployed still speaks BTLS.
RUN set -eu; \
    /opt/btls/bin/openssl ciphers -v 'ALL:eNULL' | grep -q 'DHE-BIGN-WITH-BELT-CTR-MAC-HBELT'; \
    /opt/btls/bin/openssl verify -no_check_time \
      -CAfile /etc/crypto-gw/ca/gossuok-bundle.pem \
      /etc/crypto-gw/ca/bank-leaf-reference.pem \
    && echo 'BTLS suites present and GosSUOK bundle verifies the reference bank certificate'

# Gate 5 — bee2cmd РАБОТАЕТ в рантайме, а не только в сборочной стадии. Та же логика, что
# у гейта 3 выше: собранное дерево и отобранный набор файлов — разные вещи. Бинарь мог
# слинковаться с библиотекой, которая осталась в стадии `btls`, и тогда самотест при
# старте падал бы у каждого, кто запустил образ, — то есть проба, введённая ради
# надёжности, стала бы причиной отказа. Ловим здесь, при сборке.
RUN set -eu; \
    /opt/btls/bin/bee2cmd st alg; \
    /opt/btls/bin/bee2cmd st rng; \
    echo 'bee2cmd runs in the runtime image; st alg and st rng passed'

# Атрибуция едет ВНУТРИ образа, а не только в репозитории. Apache-2.0 §4 обязывает
# отдать получателю копию лицензии и сохранённые уведомления — а получает он образ,
# в репозиторий он может не заглянуть никогда. bee2evp, bee2 и OpenSSL под Apache-2.0,
# nginx под BSD-2-Clause; что именно и откуда — в NOTICE. См. #6.
COPY --from=nginx-build /licenses/ /usr/share/licenses/
COPY LICENSE NOTICE /usr/share/licenses/
# Не полагаемся на режим файлов в исходном дереве: читать их будет непривилегированный
# `gw`, а гейт ниже исполняется от root и один только root-доступ ничего не доказал бы.
RUN chmod 0644 /usr/share/licenses/*

# Гейт 4 — атрибуция на месте И ЧИТАЕМА. Без него образ собирается и публикуется без
# единого текста лицензии, и обнаруживается это на аудите, а не в CI.
# Почему не только `test -s`: `COPY` несуществующего каталога упал бы сам, пустой файл
# проехал бы, а обрезанный до одной строки проехал бы даже мимо `test -s`. Поэтому у
# каждого файла спрашиваем строку, которой в обрезке уже не будет.
# ⚠ У Apache проверяем И номер версии: обязательства по 2.0 и по 1.1 разные, а `grep
# 'Apache License'` совпал бы с любой.
# ⚠ Файлы кладутся `cp` из локального дерева сборки, не тянутся по сети. Появится здесь
# когда-нибудь `curl` — эти проверки перестанут отличать лицензию от страницы 404, и
# тогда их надо усиливать, а не оставлять как есть.
RUN set -eu; \
    for f in bee2evp-LICENSE.txt bee2-LICENSE.txt openssl-LICENSE.txt nginx-LICENSE \
             whereami-LICENSE.txt LICENSE NOTICE; do \
      test -s "/usr/share/licenses/$f" || { echo "нет или пуст: $f" >&2; exit 1; }; \
    done; \
    for f in bee2evp-LICENSE.txt bee2-LICENSE.txt openssl-LICENSE.txt; do \
      grep -q 'Apache License' "/usr/share/licenses/$f"; \
      grep -q 'Version 2.0' "/usr/share/licenses/$f"; \
    done; \
    grep -q 'Redistribution and use in source and binary forms' /usr/share/licenses/nginx-LICENSE; \
    grep -q 'MIT License' /usr/share/licenses/LICENSE; \
    grep -q 'MODIFICATIONS' /usr/share/licenses/NOTICE; \
    grep -q 'WTFPL' /usr/share/licenses/whereami-LICENSE.txt; \
    grep -q 'Gregory Pakosz' /usr/share/licenses/whereami-LICENSE.txt; \
    echo 'атрибуция на месте: 5 лицензий апстримов + LICENSE + NOTICE'

# Unprivileged. The listen port is >1024 and every writable path is /tmp, so nothing
# here wants root.
USER gw
WORKDIR /tmp

EXPOSE 1080
# nginx signal semantics are the REVERSE of the usual convention: TERM/INT is the FAST
# shutdown (connections dropped mid-request), QUIT is the graceful one. Docker sends TERM
# by default, so without this line every image update or `compose restart` would cut an
# in-flight bank request instead of letting it finish.
STOPSIGNAL SIGQUIT
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/usr/local/bin/healthcheck.sh"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
