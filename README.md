## Использование
Создание парольных фраз
```shell
# Инициализация парольной фразы для корневого УЦ
echo -n "MySecure_Passphrase_RootCA" >> secrets/root.pass

# Инициализация парольной фразы для промежуточного УЦ
echo -n "MySecure_Passphrase_IntermediateCA" >> secrets/intermediate.pass
```

Инициализация БД

```shell
micropki db init --db-path ./pki/micropki.db
# Вывод: База данных инициализирована: pki\micropki.db

# миграция при изменении таблиц

micropki db init
```

Инициализация корневого CA (RSA-4096)

```shell
micropki ca init \
    --subject "/CN=Demo Root CA/O=MicroPKI/C=RU" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/root.pass \
    --out-dir pki \
    --validity-days 3650
```

Инициализация корневого CA (ECC P-384)

```shell
micropki ca init \
    --subject "CN=ECC Root CA,O=MicroPKI" \
    --key-type ecc \
    --key-size 384 \
    --passphrase-file secrets/ca.pass \
    --out-dir pki
```

Создание промежуточного CA

```shell
micropki ca issue-intermediate \
    --root-cert pki/certs/ca.cert.pem \
    --root-key pki/private/ca.key.pem \
    --root-pass-file secrets/root.pass \
    --subject "CN=MicroPKI Intermediate CA,O=MicroPKI" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file secrets/intermediate.pass \
    --out-dir pki \
    --validity-days 1825 \
    --pathlen 0
```

Выпуск серверного сертификата

```shell
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=example.com,O=MicroPKI" \
    --san dns:example.com \
    --san dns:www.example.com \
    --san ip:192.168.1.10 \
    --out-dir pki/certs \
    --validity-days 365
    
# или с записью в БД

micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template server \
    --subject "CN=example.com, O=MicroPKI" \
    --san dns:example.com --san dns:www.example.com --san ip:192.168.1.10 \
    --db-path pki/micropki.db
```

Выпуск клиентского сертификата

```shell
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template client \
    --subject "CN=Alice Smith" \
    --san email:alice@example.com \
    --out-dir pki/certs
    
# или с записью в БД

micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template client \
    --subject "CN=Alice Smith" \
    --san email:alice@example.com \
    --db-path pki/micropki.db
```

Выпуск сертификата подписи кода

```shell
micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=MicroPKI Code Signer" \
    --out-dir pki/certs
    
# или с записью в БД

micropki ca issue-cert \
    --ca-cert pki/certs/intermediate.cert.pem \
    --ca-key pki/private/intermediate.key.pem \
    --ca-pass-file secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=MicroPKI Code Signer" \
    --db-path pki/micropki.db
```

Просмотр сертификатов

```shell
# Список всех
micropki ca list-certs

# Только действительные
micropki ca list-certs --status valid

# В формате (table/json/csv)
micropki ca list-certs --format json

# Конкретный сертификат
micropki ca show-cert 69C41A28D533E208
```

Отзыв сертификата

```shell
# Посмотреть список сертификатов чтобы найти серийный номер
micropki ca list-certs

# Отозвать с подтверждением
micropki ca revoke <SERIAL_NUMBER> --reason keyCompromise

# Отозвать без подтверждения
micropki ca revoke <SERIAL_NUMBER> --reason superseded --force
```

Допустимые причины отзыва: `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL`, `privilegeWithdrawn`, `aACompromise`

Генерация CRL

```shell
# Ручная регенерация CRL промежуточного УЦ
micropki ca gen-crl --ca intermediate --next-update 14
#Генерация CRL корневого УЦ и сохранение в пользовательское расположение
micropki ca gen-crl --ca root --out-file ./backup/root.crl.pem
```

Получение CRL через HTTP

```shell
# Запуск сервера в фоне или отдельном терминале
micropki repo serve

# В другом терминале (cmd):
curl http://localhost:8080/crl --output ca.crl.pem

# С указанием параметра
curl http://localhost:8080/crl?ca=root --output root.crl.pem

# или

curl http://localhost:8080/crl?ca=intermediate --output intermediate.crl.pem
```

HTTP-сервер

```shell
# Запуск
micropki repo serve

# или 

micropki repo serve --host 127.0.0.1 --port 8080

# В другом терминале:

# Получить корневой CA
curl http://localhost:8080/ca/root

# Получить промежуточный CA
curl http://localhost:8080/ca/intermediate

# Получить сертификат по серийному номеру
curl http://localhost:8080/certificate/69C41A28D533E208

# CRL
curl http://localhost:8080/crl
curl http://localhost:8080/crl?ca=root
curl http://localhost:8080/crl?ca=intermediate

# Некорректный серийный номер
curl http://localhost:8080/certificate/XYZ
```

## Проверка и верификация

### Проверка цепочки сертификатов
  ```
  micropki ca verify-chain \
  --ca-file ./pki/certs/ca.cert.pem \
  --untrusted ./pki/certs/intermediate.cert.pem \
  --leaf-cert ./pki/certs/example.com.cert.pem
  ```
### Проверка через OpenSSL
-   Просмотр CRL:  
    `openssl crl -inform PEM -in ./pki/crl/intermediate.crl.pem -text -noout`
-   Валидация сертификата с цепочкой:  
    `openssl verify -CAfile ./pki/certs/ca.cert.pem -untrusted ./pki/certs/intermediate.cert.pem cert.pem`

## Тестирование
1.  Модульные тесты: ``python -m pytest``
2.  Интеграционный тест:  
    Запуск всех команд по выполненным спринтам:
  ```
  chmod +x test_pki.sh
  ./test_pki.sh
  ``` 
3.  Нагрузочный тест:  
    Проверка уникальности серийных номеров и работы БД под нагрузкой: ``python highload_test.py``
