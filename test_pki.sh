#!/bin/bash

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m'

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
    rm -rf ./pki ./secrets ./logs chain.pem example.com.cert.pem example.com.key.pem
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
    fi
}

trap cleanup EXIT

info "--- [СПРИНТ 1] Создание Root CA ---"
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

info "--- [СПРИНТ 1] Проверка Root CA ---"
openssl verify -CAfile ./pki/certs/ca.cert.pem ./pki/certs/ca.cert.pem | grep -q "OK" || fail "Самопроверка Root CA провалена."
CERT_TEXT_ROOT=$(openssl x509 -in ./pki/certs/ca.cert.pem -text -noout)
if ! (echo "$CERT_TEXT_ROOT" | grep "X509v3 Basic Constraints:" | grep -q "critical" && echo "$CERT_TEXT_ROOT" | grep -q "CA:TRUE"); then
    fail "Root CA не имеет критического расширения CA:TRUE."
fi
ok "Root CA прошел базовую проверку."

info "--- [СПРИНТ 2] Создание Intermediate CA ---"
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

info "--- [СПРИНТ 2] Проверка Intermediate CA ---"

CERT_TEXT_INT=$(openssl x509 -in ./pki/certs/intermediate.cert.pem -text -noout)

echo "$CERT_TEXT_INT" | grep -q "CA:TRUE" || fail "Intermediate не является CA."
echo "$CERT_TEXT_INT" | grep -q "pathlen:0" || fail "Не установлен pathlen=0."
echo "$CERT_TEXT_INT" | grep -q "Certificate Sign" || fail "Отсутствует keyCertSign."
echo "$CERT_TEXT_INT" | grep -q "CRL Sign" || fail "Отсутствует cRLSign."

ok "Intermediate CA прошел базовую проверку."

openssl verify -CAfile ./pki/certs/ca.cert.pem ./pki/certs/intermediate.cert.pem | grep -q "OK" || fail "Проверка Intermediate CA через OpenSSL провалена."
python3 -m micropki ca verify-chain --ca-file ./pki/certs/ca.cert.pem --leaf-cert ./pki/certs/intermediate.cert.pem || fail "Проверка Intermediate CA через micropki провалена."
ok "Проверка цепочки Root -> Intermediate прошла успешно."

info "--- [СПРИНТ 2] Выпуск серверного сертификата ---"
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

info "--- [СПРИНТ 2] Выпуск клиентского сертификата ---"
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

info "--- [СПРИНТ 2] Проверка клиентского сертификата ---"
openssl verify \
    -CAfile ./pki/certs/ca.cert.pem \
    -untrusted ./pki/certs/intermediate.cert.pem \
    ./pki/certs/alice_smith.cert.pem | grep -q "OK" || fail "Проверка клиентского сертификата провалена."

CERT_TEXT_CLIENT=$(openssl x509 -in ./pki/certs/alice_smith.cert.pem -text -noout)

echo "$CERT_TEXT_CLIENT" | grep -q "CA:FALSE" || fail "Клиентский сертификат ошибочно является CA."
echo "$CERT_TEXT_CLIENT" | grep -q "TLS Web Client Authentication" || fail "Отсутствует EKU Client Authentication."
echo "$CERT_TEXT_CLIENT" | grep -q "email:alice@example.com" || fail "SAN email отсутствует."

ok "Клиентский сертификат прошел проверку."

info "--- [СПРИНТ 2] Выпуск сертификата подписи кода ---"
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

info "--- [СПРИНТ 2] Проверка сертификата подписи кода ---"
openssl verify \
    -CAfile ./pki/certs/ca.cert.pem \
    -untrusted ./pki/certs/intermediate.cert.pem \
    ./pki/certs/micropki_code_signer.cert.pem | grep -q "OK" || fail "Проверка сертификата подписи кода провалена."

CERT_TEXT_CODE=$(openssl x509 -in ./pki/certs/micropki_code_signer.cert.pem -text -noout)

echo "$CERT_TEXT_CODE" | grep -q "Code Signing" || fail "Отсутствует EKU Code Signing."
echo "$CERT_TEXT_CODE" | grep -q "CA:FALSE" || fail "Code signing сертификат ошибочно является CA."

ok "Сертификат подписи кода прошел проверку."

info "--- [СПРИНТ 2] Проверка полной цепочки сертификатов ---"
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

info "--- [СПРИНТ 2] Запуск сквозного TLS-теста (s_server / s_client) ---"
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

echo ""
echo -e "${GREEN}========================================="
echo -e "    Тесты пройдены    "
echo -e "=========================================${NC}"