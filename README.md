## Quick start
1. Перейдите к корневой директории: `cd PKI`
2. Установите зависимости: `pip install -r requirements.txt`
3. Создайте отдельную папку, в ней - файл с паролем (для примера *secrets/pass.txt*)
4. Выполните команду: ``python -m micropki.cli ca init --subject "/CN=My Root CA" --passphrase-file ./secrets/pass.txt --out-dir ./pki``
5. В консоли будет лог следующего вида:
```2026-02-25 21:47:27,183 - INFO - === Starting Root CA initialization ===
2026-02-25 21:47:27,184 - INFO - Generating RSA key (4096 bits)
2026-02-25 21:47:27,759 - INFO - Creating self-signed X.509v3 certificate
2026-02-25 21:47:27,808 - INFO - Saving encrypted private key (PKCS#8)
2026-02-25 21:47:27,814 - INFO - Saving certificate (PEM)
2026-02-25 21:47:27,815 - INFO - Generating policy.txt
2026-02-25 21:47:27,816 - INFO - SUCCESS: Root CA successfully created in ./pki
2026-02-25 21:47:27,816 - INFO -    Private key: ./pki\private\ca.key.pem
2026-02-25 21:47:27,816 - INFO -    Certificate: ./pki\certs\ca.cert.pem
2026-02-25 21:47:27,817 - INFO -    Policy File: ./pki\policy.txt
```
6. Проверка по openssl:
* Просмотр содержимого сертификата: `openssl x509 -in pki/certs/ca.cert.pem -text -noout`
  
  *(Ищите строку CA:TRUE в разделе Basic Constraints)*
* Проверка закрытого ключа (потребует ввод пароля): ``openssl rsa -in pki/private/ca.key.pem -check``

## Тестирование
1. Установите модуль pytest: ``pip install pytest``
2. В корне проекта выполните: ``python -m pytest``
