#!/bin/bash

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

ORIGINAL_DIR="$(pwd)"
WORKSPACE="$ORIGINAL_DIR/workspace"

SERVER_PID=""
REPO_PID=""
OCSP_PID=""

info() {
    echo -e "${YELLOW}INFO: $1${NC}"
}

ok() {
    echo -e "${GREEN}OK: $1${NC}"
}

fail() {
    echo -e "${RED}FAIL: $1${NC}"
    exit 1
}

cleanup() {
    info "Cleaning up generated files..."

    if [ -n "${SERVER_PID:-}" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi

    if [ -n "${REPO_PID:-}" ]; then
        kill "$REPO_PID" 2>/dev/null || true
    fi

    if [ -n "${OCSP_PID:-}" ]; then
        kill "$OCSP_PID" 2>/dev/null || true
    fi

    cd "$ORIGINAL_DIR" 2>/dev/null || true

    if [ -n "$WORKSPACE" ] && [ "$WORKSPACE" != "/" ] && [ -d "$WORKSPACE" ]; then
        rm -rf "$WORKSPACE"
    fi
}

prepare_workspace() {
    rm -rf "$WORKSPACE"
    mkdir -p "$WORKSPACE"

    export PYTHONPATH="$ORIGINAL_DIR:${PYTHONPATH:-}"

    cd "$WORKSPACE"
}

trap cleanup EXIT
prepare_workspace

info "============================== SPRINT 1 =============================="
info "--- Инициализация БД ---"
python -m micropki db init
[ -f ./pki/micropki.db ] || fail "Файл базы данных не создан."
ok "База данных успешно инициализирована."

info "--- Создание Root CA ---"
mkdir -p ./secrets
mkdir -p ./logs
echo "root_password_123" > ./secrets/root.pass
echo "intermediate_password_456" > ./secrets/intermediate.pass

python3 -m micropki ca init \
    --subject "/CN=Test Root CA" \
    --passphrase-file ./secrets/root.pass \
    --out-dir ./pki \
    --log-file ./logs/test.log

[ -f ./pki/certs/ca.cert.pem ] && [ -f ./pki/private/ca.key.pem ] || fail "Файлы Root CA не созданы."
ok "Root CA успешно создан."

info "--- Проверка Root CA ---"
openssl verify -CAfile ./pki/certs/ca.cert.pem ./pki/certs/ca.cert.pem | grep -q "OK" || fail "Самопроверка Root CA провалена."
CERT_TEXT_ROOT=$(openssl x509 -in ./pki/certs/ca.cert.pem -text -noout)
if ! (echo "$CERT_TEXT_ROOT" | grep "X509v3 Basic Constraints:" | grep -q "critical" && echo "$CERT_TEXT_ROOT" | grep -q "CA:TRUE"); then
    fail "Root CA не имеет критического расширения CA:TRUE."
fi
ok "Root CA прошел базовую проверку."

info "============================== SPRINT 2 =============================="
info "--- Создание Intermediate CA ---"
python3 -m micropki ca issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file ./secrets/root.pass \
    --subject "/CN=Test Intermediate CA" \
    --passphrase-file ./secrets/intermediate.pass \
    --out-dir ./pki \
    --log-file ./logs/test.log

[ -f ./pki/certs/intermediate.cert.pem ] || fail "Сертификат Intermediate CA не создан."
ok "Intermediate CA успешно создан."

info "--- Проверка Intermediate CA ---"

CERT_TEXT_INT=$(openssl x509 -in ./pki/certs/intermediate.cert.pem -text -noout)

echo "$CERT_TEXT_INT" | grep -q "CA:TRUE" || fail "Intermediate не является CA."
echo "$CERT_TEXT_INT" | grep -q "pathlen:0" || fail "Не установлен pathlen=0."
echo "$CERT_TEXT_INT" | grep -q "Certificate Sign" || fail "Отсутствует keyCertSign."
echo "$CERT_TEXT_INT" | grep -q "CRL Sign" || fail "Отсутствует cRLSign."

ok "Intermediate CA прошел базовую проверку."

openssl verify -CAfile ./pki/certs/ca.cert.pem ./pki/certs/intermediate.cert.pem | grep -q "OK" || fail "Проверка Intermediate CA через OpenSSL провалена."
python3 -m micropki ca verify-chain --ca-file ./pki/certs/ca.cert.pem --leaf-cert ./pki/certs/intermediate.cert.pem || fail "Проверка Intermediate CA через micropki провалена."
ok "Проверка цепочки Root -> Intermediate прошла успешно."

info "--- Выпуск серверного сертификата ---"
python3 -m micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template server \
    --subject "/CN=example.com" \
    --san dns:example.com \
    --san dns:www.example.com \
    --san ip:127.0.0.1 \
    --out-dir . \
    --log-file ./logs/test.log

[ -f ./example.com.cert.pem ] && [ -f ./example.com.key.pem ] || fail "Конечный сертификат не создан."
ok "Серверный сертификат для example.com успешно создан."

info "--- Выпуск клиентского сертификата ---"
python3 -m micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template client \
    --subject "/CN=Alice Smith/EMAIL=alice@example.com" \
    --san email:alice@example.com \
    --out-dir ./pki/certs \
    --log-file ./logs/test.log

[ -f ./pki/certs/alice_smith.cert.pem ] || fail "Клиентский сертификат не создан."
ok "Клиентский сертификат успешно создан."

info "--- Проверка клиентского сертификата ---"
openssl verify \
    -CAfile ./pki/certs/ca.cert.pem \
    -untrusted ./pki/certs/intermediate.cert.pem \
    ./pki/certs/alice_smith.cert.pem | grep -q "OK" || fail "Проверка клиентского сертификата провалена."

CERT_TEXT_CLIENT=$(openssl x509 -in ./pki/certs/alice_smith.cert.pem -text -noout)

echo "$CERT_TEXT_CLIENT" | grep -q "CA:FALSE" || fail "Клиентский сертификат ошибочно является CA."
echo "$CERT_TEXT_CLIENT" | grep -q "TLS Web Client Authentication" || fail "Отсутствует EKU Client Authentication."
echo "$CERT_TEXT_CLIENT" | grep -q "email:alice@example.com" || fail "SAN email отсутствует."

ok "Клиентский сертификат прошел проверку."

info "--- Выпуск сертификата подписи кода ---"
python3 -m micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template code_signing \
    --subject "/CN=MicroPKI Code Signer" \
    --out-dir ./pki/certs \
    --log-file ./logs/test.log

[ -f ./pki/certs/micropki_code_signer.cert.pem ] || fail "Сертификат подписи кода не создан."
ok "Сертификат подписи кода успешно создан."

info "--- Проверка сертификата подписи кода ---"
openssl verify \
    -CAfile ./pki/certs/ca.cert.pem \
    -untrusted ./pki/certs/intermediate.cert.pem \
    ./pki/certs/micropki_code_signer.cert.pem | grep -q "OK" || fail "Проверка сертификата подписи кода провалена."

CERT_TEXT_CODE=$(openssl x509 -in ./pki/certs/micropki_code_signer.cert.pem -text -noout)

echo "$CERT_TEXT_CODE" | grep -q "Code Signing" || fail "Отсутствует EKU Code Signing."
echo "$CERT_TEXT_CODE" | grep -q "CA:FALSE" || fail "Code signing сертификат ошибочно является CA."

ok "Сертификат подписи кода прошел проверку."

info "--- Проверка полной цепочки сертификатов ---"
cat ./pki/certs/intermediate.cert.pem ./pki/certs/ca.cert.pem > chain.pem

openssl verify -CAfile ./pki/certs/ca.cert.pem -untrusted ./pki/certs/intermediate.cert.pem ./example.com.cert.pem | grep -q "OK" || fail "Полная проверка цепочки через OpenSSL провалена."
python3 -m micropki ca verify-chain --ca-file ./pki/certs/ca.cert.pem --untrusted ./pki/certs/intermediate.cert.pem --leaf-cert ./example.com.cert.pem || fail "Полная проверка цепочки через micropki провалена."

CERT_TEXT_LEAF=$(openssl x509 -in ./example.com.cert.pem -text -noout)
if ! (echo "$CERT_TEXT_LEAF" | grep "X509v3 Basic Constraints:" | grep -q "critical" && echo "$CERT_TEXT_LEAF" | grep -q "CA:FALSE"); then
    fail "Конечный сертификат не имеет критического расширения CA:FALSE."
fi
echo "$CERT_TEXT_LEAF" | grep -q "DNS:example.com" || fail "В SAN отсутствует DNS:example.com."
echo "$CERT_TEXT_LEAF" | grep -q "IP Address:127.0.0.1" || fail "В SAN отсутствует IP:127.0.0.1."
echo "$CERT_TEXT_LEAF" | grep -q "TLS Web Server Authentication" || fail "Отсутствует EKU 'Server Authentication'."
ok "Проверка полной цепочки и расширений конечного сертификата прошла успешно."

info "--- Запуск сквозного TLS-теста (s_server / s_client) ---"
openssl s_server \
    -accept 8443 \
    -cert ./example.com.cert.pem \
    -key ./example.com.key.pem \
    -CAfile chain.pem \
    -www &
SERVER_PID=$!
sleep 1

echo "Q" | openssl s_client \
    -connect localhost:8443 \
    -CAfile ./pki/certs/ca.cert.pem \
    -brief > /dev/null 2>&1

if [ $? -eq 0 ]; then
    ok "TLS-соединение успешно установлено!"
else
    fail "Не удалось установить TLS-соединение."
fi

kill $SERVER_PID
SERVER_PID=""

: <<'COMMENT'
info "============================== SPRINT 3 =============================="
info "--- Выпуск 5 конечных сертификатов ---"
CERT_SUBJECTS=("server1.example.com" "server2.example.com" "client.user" "another.client" "codesigner.corp")
CERT_TEMPLATES=("server" "server" "client" "client" "code_signing")

for i in {0..4}; do
    subj="/CN=${CERT_SUBJECTS[$i]}"
    template=${CERT_TEMPLATES[$i]}
    info "Выпуск сертификата для ${subj} (шаблон: ${template})"
    python -m micropki ca issue-cert --ca-cert ./pki/certs/intermediate.cert.pem --ca-key ./pki/private/intermediate.key.pem --ca-pass-file ./secrets/intermediate.pass --template ${template} --subject "${subj}" --san "dns:${CERT_SUBJECTS[$i]}" --out-dir ./pki/certs
done
ok "5 сертификатов выпущено."

info "--- Проверка сертификатов через CLI ---"
CERT_COUNT=$(python -m micropki ca list-certs --format csv | wc -l)
[ "$CERT_COUNT" -eq 10 ] || fail "В БД неверное количество сертификатов. Ожидалось 7, найдено $((CERT_COUNT - 1))."
SERIAL_TO_CHECK=$(python -m micropki ca list-certs --format csv | grep server1 | cut -d, -f1)
python -m micropki ca show-cert ${SERIAL_TO_CHECK} | grep -q "BEGIN CERTIFICATE" || fail "ca show-cert не вернул PEM сертификат."
ok "Проверки list-certs и show-cert прошли успешно."

info "--- Запуск и проверка API репозитория ---"
python -m micropki repo serve &
SERVER_PID=$!
sleep 2

info "Проверка /ca/root и /ca/intermediate..."
curl -s http://localhost:8080/ca/root | diff - ./pki/certs/ca.cert.pem || fail "API /ca/root вернул неверный сертификат."
curl -s http://localhost:8080/ca/intermediate | diff - ./pki/certs/intermediate.cert.pem || fail "API /ca/intermediate вернул неверный сертификат."
ok "/ca эндпоинты работают."

info "Проверка /certificate/<serial> для всех выпущенных сертификатов..."
SERIALS=$(python -m micropki ca list-certs --format csv | tail -n +2 | cut -d, -f1)
for SERIAL in $SERIALS; do
    CN=$(python -m micropki ca list-certs --format csv | grep $SERIAL | cut -d, -f2 | cut -d= -f2)
    FILENAME=$(echo "$CN" | tr ' ' '_' | tr '[:upper:]' '[:lower:]').cert.pem
    
    if [ ! -f "./pki/certs/$FILENAME" ]; then continue; fi

    info "  Проверка серийника ${SERIAL} (файл ${FILENAME})"
    curl -s http://localhost:8080/certificate/${SERIAL} | diff - ./pki/certs/${FILENAME} || fail "API /certificate/${SERIAL} вернул неверные данные."
done
ok "Все сертификаты успешно получены через API."

kill $SERVER_PID
SERVER_PID=""

info "============================== SPRINT 4 =============================="

info "--- [TEST-21] Жизненный цикл отзыва ---"
python3 -m micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template server \
    --subject "/CN=to-be-revoked.com" \
    --san dns:to-be-revoked.com \
    --out-dir .

SERIAL_REVOKE=$(python3 -m micropki ca list-certs --format csv | grep "to-be-revoked.com" | cut -d, -f1)
[ -n "$SERIAL_REVOKE" ] || fail "Не удалось найти серийный номер для отзыва."

python3 -m micropki ca list-certs --format csv | grep "$SERIAL_REVOKE" | grep -q "valid" || fail "Начальный статус не valid."

python3 -m micropki ca revoke "$SERIAL_REVOKE" --reason keyCompromise --force
ok "Сертификат $SERIAL_REVOKE отозван."

python3 -m micropki ca list-certs --format csv | grep "$SERIAL_REVOKE" | grep -q "revoked" || fail "Статус в БД не изменился на revoked."

python3 -m micropki ca gen-crl --ca intermediate --next-update 7
[ -f ./pki/crl/intermediate.crl.pem ] || fail "Файл CRL не создан."

CRL_TEXT=$(openssl crl -inform PEM -in ./pki/crl/intermediate.crl.pem -text -noout)
echo "$CRL_TEXT" | grep -q "$SERIAL_REVOKE" || fail "Серийный номер отсутствует в CRL."
echo "$CRL_TEXT" | grep -q "Key Compromise" || fail "Причина отзыва в CRL указана неверно."
ok "CRL содержит информацию об отозванном сертификате."

info "--- [TEST-22] Проверка подписи CRL ---"
openssl crl -in ./pki/crl/intermediate.crl.pem -inform PEM -CAfile ./pki/certs/intermediate.cert.pem -noout 2>&1 | grep -q "verify OK" || fail "Подпись CRL невалидна."
ok "Подпись CRL подтверждена."

info "--- [TEST-23] Проверка увеличения номера CRL ---"
NUM1=$(openssl crl -in ./pki/crl/intermediate.crl.pem -text -noout | grep "CRL Number" -A 1 | tr -d '[:space:]' | cut -d':' -f2)
python3 -m micropki ca gen-crl --ca intermediate --next-update 7
NUM2=$(openssl crl -in ./pki/crl/intermediate.crl.pem -text -noout | grep "CRL Number" -A 1 | tr -d '[:space:]' | cut -d':' -f2)

if [ "$NUM2" -le "$NUM1" ]; then
    fail "Номер CRL не увеличился (было $NUM1, стало $NUM2)."
fi
ok "Номер CRL успешно инкрементирован ($NUM1 -> $NUM2)."

info "--- [TEST-24/25] Негативные тесты отзыва ---"
set +e
python3 -m micropki ca revoke "DEADC0DE" --reason keyCompromise --force 2>&1
RET=$?
set -e
[ $RET -ne 0 ] || fail "Отзыв несуществующего сертификата должен возвращать ошибку."
ok "Тест на несуществующий серийник пройден."

python3 -m micropki ca revoke "$SERIAL_REVOKE" --reason keyCompromise --force 2>&1 | grep -q "already revoked" || fail "Должно быть предупреждение об уже отозванном статусе."
ok "Тест на повторный отзыв пройден."

info "--- [TEST-26] Тест распространения CRL через API ---"
python3 -m micropki repo serve &
SERVER_PID=$!
sleep 2

curl -s http://localhost:8080/crl?ca=intermediate > downloaded.crl.pem
diff downloaded.crl.pem ./pki/crl/intermediate.crl.pem || fail "CRL полученный по HTTP отличается от локального."
curl -s -I http://localhost:8080/crl?ca=intermediate 2>&1 | grep -q "application/pkix-crl" || fail "Неверный Content-Type для CRL."

kill $SERVER_PID
SERVER_PID=""
rm downloaded.crl.pem to-be-revoked.com.cert.pem to-be-revoked.com.key.pem
ok "API успешно отдает файлы CRL."
COMMENT
info "============================== SPRINT 5 =============================="

info "--- [TEST-28] Выпуск и проверка сертификата OCSP-ответчика ---"
python3 -m micropki ca issue-ocsp-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --subject "/CN=OCSP Responder" \
    --key-type rsa \
    --key-size 2048 \
    --out-dir ./pki/certs \
    --db-path ./pki/micropki.db

[ -f ./pki/certs/ocsp.cert.pem ] || fail "Сертификат OCSP не создан."
[ -f ./pki/certs/ocsp.key.pem ] || fail "Ключ OCSP не создан."

CERT_TEXT_OCSP=$(openssl x509 -in ./pki/certs/ocsp.cert.pem -text -noout)
echo "$CERT_TEXT_OCSP" | grep -q "OCSP Signing" || fail "Отсутствует расширение EKU OCSPSigning."
echo "$CERT_TEXT_OCSP" | grep -A 1 "Key Usage" | grep -q "Digital Signature" || fail "Отсутствует Key Usage Digital Signature."
ok "Сертификат OCSP-ответчика корректен."

info "--- Запуск OCSP-ответчика ---"
python3 -m micropki ocsp serve \
    --port 8081 \
    --db-path ./pki/micropki.db \
    --responder-cert ./pki/certs/ocsp.cert.pem \
    --responder-key ./pki/certs/ocsp.key.pem \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --cache-ttl 60 &
OCSP_PID=$!
sleep 2

info "--- [TEST-29/32] OCSP запрос: GOOD статус и Nonce ---"
python3 -m micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template server \
    --subject "/CN=ocsp-test-good.com" \
    --san dns:ocsp-test-good.com \
    --out-dir .

openssl ocsp -issuer ./pki/certs/intermediate.cert.pem \
             -cert ocsp-test-good.com.cert.pem \
             -url http://127.0.0.1:8081/ocsp \
             -VAfile ./pki/certs/ocsp.cert.pem \
             -nonce -respout resp_good.der > ocsp_res.txt 2>&1

grep -q "ocsp-test-good.com.cert.pem: good" ocsp_res.txt || fail "Неверный статус OCSP (ожидался good)."
grep -q "Response verify OK" ocsp_res.txt || fail "Подпись OCSP ответа невалидна."
ok "Статус GOOD и подпись подтверждены."

info "--- [TEST-30] OCSP запрос: REVOKED статус ---"
SERIAL_OCSP_REVOKE=$(python3 -m micropki ca list-certs --format csv | grep "ocsp-test-good.com" | cut -d, -f1)
python3 -m micropki ca revoke "$SERIAL_OCSP_REVOKE" --reason keyCompromise --force

openssl ocsp -issuer ./pki/certs/intermediate.cert.pem \
             -cert ocsp-test-good.com.cert.pem \
             -url http://127.0.0.1:8081/ocsp \
             -VAfile ./pki/certs/ocsp.cert.pem > ocsp_res.txt 2>&1

grep -q "ocsp-test-good.com.cert.pem: revoked" ocsp_res.txt || fail "Неверный статус OCSP (ожидался revoked)."
grep -q "Reason: keyCompromise" ocsp_res.txt || fail "В ответе OCSP отсутствует причина отзыва."
ok "Статус REVOKED и причина подтверждены."

info "--- [TEST-31] OCSP запрос: UNKNOWN статус (через unauthorized) ---"
openssl genrsa -out unknown.key 2048
openssl req -new -key unknown.key -out unknown.csr -subj "/CN=unknown.com"
openssl x509 -req -in unknown.csr -signkey unknown.key -out unknown.cert.pem -days 1 > /dev/null 2>&1

set +e
openssl ocsp -issuer ./pki/certs/intermediate.cert.pem \
             -cert unknown.cert.pem \
             -url http://127.0.0.1:8081/ocsp \
             -VAfile ./pki/certs/ocsp.cert.pem > ocsp_res.txt 2>&1
OCSP_UNKNOWN_RET=$?
set -e

grep -q "Responder Error: unauthorized" ocsp_res.txt || {
    cat ocsp_res.txt
    fail "Сервер не вернул unauthorized на неизвестный сертификат."
}

ok "Статус UNKNOWN (unauthorized) подтвержден."

info "--- [TEST-34] Негативный тест: Malformed Request ---"
set +e
curl -s -X POST --data "not-a-request" -H "Content-Type: application/ocsp-request" http://127.0.0.1:8081/ocsp > malformed_res.bin
openssl ocsp -respin malformed_res.bin -text -noverify 2>&1 | grep -i "malformedRequest" || fail "Сервер не вернул malformedRequest на мусорные данные."
set -e
ok "Тест на некорректный запрос пройден."

kill -9 $OCSP_PID 2>/dev/null || true
OCSP_PID=""
sleep 1
ok "OCSP functionality verified."

info "============================== SPRINT 6 =============================="
info "--- [TEST-38] Тест генерации CSR ---"
python3 -m micropki client gen-csr \
    --subject "/CN=client-app.com" \
    --san dns:client-app.com \
    --san dns:api.client-app.com \
    --out-key ./client.key.pem \
    --out-csr ./client.csr.pem

[ -f ./client.csr.pem ] || fail "CSR не создан."
[ -f ./client.key.pem ] || fail "Ключ не создан."

KEY_PERMS=$(stat -c "%a" ./client.key.pem)
if [ "$KEY_PERMS" != "600" ]; then
    if [[ $(pwd) == /mnt/* ]]; then
        info "Предупреждение: Права на ключ $KEY_PERMS (ожидалось 600). Это ожидаемо для /mnt/ дисков в WSL. Пропускаем..."
    else
        fail "Неверные права на закрытый ключ: $KEY_PERMS (ожидалось 600)."
    fi
fi

openssl req -in ./client.csr.pem -text -noout | grep -q "CN = client-app.com" || fail "В CSR неверный Subject."
openssl req -in ./client.csr.pem -text -noout | grep -q "DNS:client-app.com" || fail "В CSR отсутствуют SAN."
openssl req -in ./client.csr.pem -noout -verify || fail "Подпись CSR невалидна."
ok "Генерация CSR прошла успешно."

info "--- [TEST-39/48] Тест запроса сертификата через API ---"
python3 -m micropki repo serve --port 8080 &
REPO_PID=$!
sleep 2

python3 -m micropki client request-cert \
    --csr ./client.csr.pem \
    --template server \
    --ca-url http://localhost:8080 \
    --out-cert ./client.cert.pem

[ -f ./client.cert.pem ] || fail "Сертификат не получен от API."
CERT_TEXT_API=$(openssl x509 -in ./client.cert.pem -text -noout)
echo "$CERT_TEXT_API" | grep -q "CN = client-app.com" || fail "В полученном сертификате неверный Subject."
echo "$CERT_TEXT_API" | grep -q "DNS:client-app.com" || fail "В полученном сертификате отсутствуют SAN."

kill $REPO_PID
ok "Выпуск сертификата через API выполнен."

info "--- [TEST-40/46] Проверка цепочки (Успех и отсутствие Intermediate) ---"
set +e
python3 -m micropki client validate \
    --cert ./client.cert.pem \
    --trusted ./pki/certs/ca.cert.pem 2>&1 | grep -q "Issuer not found"
RET=$?
set -e
[ $RET -eq 0 ] || fail "Валидация должна была упасть без промежуточного сертификата."

python3 -m micropki client validate \
    --cert ./client.cert.pem \
    --untrusted ./pki/certs/intermediate.cert.pem \
    --trusted ./pki/certs/ca.cert.pem \
    --mode chain
ok "Валидация цепочки работает корректно."

info "--- [TEST-41] Проверка просроченного сертификата ---"
set +e
python3 -m micropki client validate \
    --cert ./client.cert.pem \
    --untrusted ./pki/certs/intermediate.cert.pem \
    --trusted ./pki/certs/ca.cert.pem \
    --validation-time "2040-01-01T00:00:00" 2>&1 | grep -q "Expired"
RET=$?
set -e
[ $RET -eq 0 ] || fail "Валидатор не распознал просроченный сертификат."
ok "Проверка по времени работает."

info "--- [TEST-43/44/45] Логика переключения OCSP -> CRL ---"
SERIAL_CLIENT=$(python3 -m micropki ca list-certs --format csv | grep "client-app.com" | cut -d, -f1)
python3 -m micropki ca revoke "$SERIAL_CLIENT" --reason keyCompromise --force
python3 -m micropki ca gen-crl --ca intermediate --ca-pass-file ./secrets/intermediate.pass

python3 -m micropki repo serve --port 8080 &
REPO_PID=$!
sleep 2

info "Проверка переключения (OCSP недоступен, CRL должен найти отзыв)..."
python3 -m micropki client check-status \
    --cert ./client.cert.pem \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --crl http://localhost:8080/crl?ca=intermediate \
    --ocsp-url http://localhost:8081/ocsp 2>&1 | grep -q "revoked" || fail "Логика переключения на CRL не сработала."

python3 -m micropki ocsp serve --port 8081 \
    --responder-cert ./pki/certs/ocsp.cert.pem \
    --responder-key ./pki/certs/ocsp.key.pem \
    --ca-cert ./pki/certs/intermediate.cert.pem &
OCSP_PID=$!
sleep 2

info "Проверка приоритета OCSP..."
python3 -m micropki client check-status \
    --cert ./client.cert.pem \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ocsp-url http://localhost:8081/ocsp 2>&1 | grep -q "OCSP" || fail "OCSP не был использован при наличии."

kill $REPO_PID
kill $OCSP_PID
ok "Логика приоритетов отзыва проверена."

info "--- [TEST-49] Негативный тест: Невалидная подпись CSR ---"
sed -i '/^-/! s/a/b/' ./client.csr.pem
python3 -m micropki repo serve --port 8080 &
REPO_PID=$!
sleep 2

set +e
python3 -m micropki client request-cert \
    --csr ./client.csr.pem \
    --template server \
    --ca-url http://localhost:8080 2>&1 | grep -q "Error 400"
RET=$?
set -e
[ $RET -eq 0 ] || fail "CA должен был отклонить битый CSR."

kill $REPO_PID
ok "Тест битого CSR пройден."

kill -9 $REPO_PID 2>/dev/null || true
kill -9 $OCSP_PID 2>/dev/null || true
REPO_PID=""
OCSP_PID=""


echo ""
echo -e "${GREEN}========================================="
echo -e "    Тесты пройдены    "
echo -e "=========================================${NC}"