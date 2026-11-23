# cspcombine

Единая утилита для работы с контейнерами **ViPNet** и **КриптоПро CSP**.
Объединяет два отдельных проекта (`vipnet` и `cp-extract`) в одну программу
на чистом Python — **без сторонних зависимостей**, только стандартная
библиотека.

Что умеет:

* `export` — извлечь закрытый ключ в PEM из контейнера ViPNet (файл ITCS/PKEY)
  или КриптоПро (каталог `header.key`/`primary.key`/`masks.key`, tar- или
  zip-архив такого каталога);
* `create` — создать контейнер по JSON-спецификации; всё, что не указано,
  генерируется автоматически (ключ, PIN, серийный номер, даты, соль и т.д.);
* `inspect` — показать параметры контейнера без извлечения ключа;
* `selftest` — проверить встроенные ГОСТ-алгоритмы и round-trip.

Созданные контейнеры КриптоПро 2001/2012-256 проходят штатную проверку
`csptest -check=15` установленного КриптоПро CSP.

Исходные проекты не изменялись: код скопирован и переработан в этом каталоге.

> Инструмент предназначен для восстановления и миграции собственных ключей.
> Используйте его только с контейнерами, к которым у вас есть законный доступ.

---

## Быстрый старт

```bash
cd /path/to/cspcombine
chmod +x cspcombine

# чтобы команда была доступна как cspcombine:
ln -sf "$PWD/cspcombine" ~/.local/bin/cspcombine
# (симлинк уже создан в ~/.local/bin/cspcombine)
```

После этого можно писать просто `cspcombine ...` из любого каталога.

Требуется Python 3.9+ (проверено на 3.10).

---

## export

### ViPNet

```bash
./cspcombine export -container ./loskutova_2025 -pin 12345678 > ./private_key.pem
```

### КриптоПро

Каталог контейнера:

```bash
./cspcombine export -container ./kriptoprocontainer -pin 12345678 > ./private_key.pem
```

Архив (tar/zip), полученный, например, через `cspcombine create`:

```bash
./cspcombine export -container ./container.tar -pin 12345678 > ./private_key.pem
./cspcombine export -container ./container.zip -pin 12345678 > ./private_key.pem
```

Сертификат из контейнера КриптоПро:

```bash
./cspcombine export -container ./kriptoprocontainer -pin 12345678 --cert > ./cert.pem
```

Проверка PIN:

* в ViPNet-контейнере есть MAC, поэтому неверный PIN сразу даёт ошибку;
* в КриптоПро проверяется штатный verifier из поля `header [2]`
  (MAC от 16 нулевых байт на ключе, выведенном из PIN и отпечатка открытого
  ключа), поэтому неверный PIN также даёт ошибку;
* если в контейнере есть сертификат, дополнительно сверяется открытый ключ;
* отключить проверки можно флагом `--no-verify`.

Если PIN не указан и терминал интерактивный, для ViPNet PIN будет запрошен.
Пустой PIN для контейнера без пароля задаётся явно:

```bash
./cspcombine export -container ./pynopass.000 -pin ""
```

Провайдер определяется автоматически; при необходимости его можно указать
явно:

```bash
./cspcombine export -container ... --provider vipnet
./cspcombine export -container ... --provider cryptopro
```

---

## create

```bash
./cspcombine create ./json_schema > ./container
```

Поведение вывода:

| Провайдер | stdout / `-o` | Результат |
|---|---|---|
| ViPNet | `-o файл` или `>` | один бинарный файл ITCS |
| КриптоПро | `>` (без `-o`) | tar-архив с файлами контейнера |
| КриптоПро | `-o КАТАЛОГ` | каталог с `header.key`, `primary.key`, ... |
| КриптоПро | `-o файл.zip` / `-o файл.tar` | zip/tar-архив |

Примеры:

```bash
# ViPNet в файл
./cspcombine create examples/vipnet.json -o ./new_vipnet_container

# КриптоПро в каталог
./cspcombine create examples/cryptopro.json -o ./new_cp_container

# КриптоПро в stdout (tar)
./cspcombine create examples/cryptopro.json > ./new_cp_container.tar
# при необходимости распаковать в каталог:
mkdir -p ./new_cp_container && tar xf ./new_cp_container.tar -C ./new_cp_container

# Дополнительно сохранить сам закрытый ключ в PEM
./cspcombine create examples/vipnet.json -o ./cont --key-out ./key.pem
```

Сгенерированный PIN и параметры выводятся в **stderr**, поэтому не мешают
перенаправлению бинарного контейнера в stdout.

### Минимальная спецификация

```json
{
  "provider": "vipnet",
  "pin": "12345678",
  "valid_until": "2030-12-31"
}
```

Всё остальное будет сгенерировано: закрытый ключ, серийный номер, соль, IV,
`KeyUID`, дата начала действия (сейчас) и т.д.

Если не указывать и `pin`, программа сгенерирует случайный 8-значный PIN и
напечатает его в stderr. Если нужно создать контейнер без пароля:

```json
{
  "provider": "cryptopro",
  "pin": ""
}
```

### Поля спецификации

Формальное описание полей лежит в `examples/spec.schema.json` (JSON Schema).
Поддерживаются как «плоские» поля, так и вложенные варианты из старых
проектов (`key.private_key`, `protection.pin`, `container.version` и т.п.).

| Поле | По умолчанию | Описание |
|---|---|---|
| `provider` | `vipnet` | `vipnet` или `cryptopro` |
| `private_key` | генерируется | PEM PKCS#8, путь к PEM или hex-скаляр |
| `pin` | генерируется | PIN; `""` — без пароля |
| `algorithm` | `2012-256` | `2001`, `2012-256`, `2012-512` |
| `curve` / `curve_oid` | зависит от провайдера | OID именованной кривой |
| `digest` / `digest_oid` | по алгоритму | OID хэша |
| `key_algorithm_oid` / `sign_oid` | по алгоритму | OID алгоритма подписи |
| `valid_from` / `not_before` | сейчас | дата начала действия |
| `valid_until` / `not_after` / `expires` | +1 год | дата окончания |
| `container_name` | `cspcombine` | имя контейнера (КриптоПро `name.key`) |
| `iterations` | `2000` | итерации PBKDF2 (ViPNet) |
| `key_length` | `32` | длина ключа PBKDF2 (ViPNet) |
| `salt`, `iv` | `auto` | hex или `auto` (ViPNet) |
| `version` | `16` | версия заголовка контейнера ViPNet |
| `entry_version` | `3` | версия записи ViPNet |
| `header` | пусто | hex-заголовок ViPNet |
| `serial_number` | `auto` | 16 байт hex или `auto` (ViPNet) |
| `key_uid` | `auto` | 32 байта hex или `auto` (ViPNet) |
| `native_profile` | `false` | добавить нативный профиль ViPNet |
| `key_class`, `key_type`, `flags` | `1`, `43590`, `1` | параметры `keyInfo` (ViPNet) |
| `defence.key_class` | `1024` | параметры `defenceInfo` (ViPNet) |
| `defence.key_type` | `32826` | параметры `defenceInfo` (ViPNet) |
| `defence.flags` | `0` | флаги `defenceInfo` (ViPNet) |
| `certificate` / `certificate_der` | нет | PEM, hex или путь к DER-сертификату (КриптоПро); при создании проверяется соответствие закрытому ключу |
| `key_usage` | `sign` | `sign` или `exchange` (КриптоПро); совмещённый контейнер не поддерживается |
| `extension_oid` | по `key_usage` | явный OID расширения срока действия (КриптоПро) |
| `backup_key` | `true` | создавать `masks2.key`/`primary2.key` (КриптоПро) |

Даты принимаются в форматах `YYYY-MM-DD`, ISO 8601, с `Z` или смещением.
Для `valid_until`, заданного только датой, используется конец дня (23:59:59Z).

### Совместимость

* **ViPNet**: создание ITCS-контейнеров проверено round-trip'ом с этим же
  инструментом и повторяет профиль, который использовался в исходном
  `build_vipnet.py`. Поддерживаются оба варианта маскирования (`key_class 0`
  и `key_class 1`), 256- и 512-битные кривые.
* **КриптоПро**: создаётся полноценная файловая раскладка контейнера
  (`header.key`, `masks.key`, `primary.key`, `masks2.key`, `primary2.key`,
  `name.key`) со всеми штатными проверочными значениями:
  * `hmacKeyContainerContent` — GOST 28147-MAC заголовка;
  * `hmacPassword` — verifier PIN-кода;
  * `hmacRandom` в `masks.key`/`masks2.key`;
  * `primaryFP` — отпечаток открытого ключа.

  Контейнеры **2001** и **2012-256** (кривые CryptoPro-A/XchA и TC26-256,
  с PIN и без PIN, ключи `sign` и `exchange`) проверены штатным
  `csptest -check=15`: проверки header, подписи, приватного и открытого
  ключа и импорта проходят. Совмещённый контейнер `sign+exchange` пока не
  поддерживается — создавайте два отдельных контейнера.
  Контейнеры **2012-512** формируются, но данный установленный CSP отказался
  создавать 512-битный тестовый ключ, поэтому этот профиль считается
  экспериментальным.

Проверить готовый контейнер штатным CSP можно скриптом:

```bash
tools/check_with_csp.sh ./container [pin]
```

Скрипт временно копирует контейнер в key store текущего пользователя под
коротким 8-символьным именем, запускает `csptest -check=15` и удаляет копию.

При ручном размещении контейнера в key store КриптоПро каталог должен иметь
короткое имя (не длиннее 8 символов, например `xxxxxxxx.000`), иначе CSP его
не увидит. Имя внутри `name.key` при этом может быть любым.

---

## inspect

```bash
./cspcombine inspect -container ./container
./cspcombine inspect --json -container ./container
```

Показывает провайдера, имя контейнера, алгоритм, кривую, срок действия,
наличие PIN/сертификата, `KeyUID`, salt, итерации и т.п. Закрытый ключ не
извлекается и не печатается.

---

## selftest

```bash
./cspcombine selftest
```

Проверяет контрольные значения Streebog-256/512 и полный цикл
«создать → извлечь» для обоих провайдеров.

---

## CI/CD и релизы

В репозитории два workflow:

* `.github/workflows/ci.yml` — тесты на Linux и Windows, Python 3.8 и 3.12;
* `.github/workflows/release.yml` — сборка и публикация релиза.

Релиз запускается по тегу `v*` или вручную:

```bash
git tag v1.1.0
git push origin v1.1.0
```

Либо через GitHub Actions → Release → Run workflow, указав тег.

В релиз попадают:

| Артефакт | Описание |
|---|---|
| `cspcombine-<tag>-linux-x86_64.tar.gz` | Linux x86_64, один исполняемый файл |
| `cspcombine-<tag>-windows10-x86_64.zip` | Windows 10/11 x86_64, один `.exe` |
| `cspcombine-<tag>-windows7-x86_64.zip` | Windows 7 SP1 x86_64, один `.exe` |
| `cspcombine-<tag>-source.tar.gz` / `.zip` | исходники |
| `SHA256SUMS` | контрольные суммы |

Особенности сборок:

* Linux-бинарник собирается на Ubuntu 22.04 (glibc 2.35+). Для старых
  дистрибутивов используйте source-архив или соберите PyInstaller локально.
* Windows 10/11 собирается на Python 3.12 и PyInstaller 6.x.
* Windows 7 собирается на Python 3.8.10 и PyInstaller 4.10 — последняя
  комбинация, рассчитанная на Win7. Нужен Windows 7 SP1 и обновление
  Universal C Runtime (KB2999226), как и для самого Python 3.8.
* Совмещённый `sign+exchange` контейнер не поддерживается.

## Тесты

```bash
python3 -m unittest discover -s tests -v
```

Тесты с реальными контейнерами включаются переменной окружения:

```bash
CSPCOMBINE_REAL_TESTS=1 \
CSPCOMBINE_REAL_VIPNET=/path/to/vipnet-container \
CSPCOMBINE_REAL_CRYPTOPRO=/path/to/cryptopro-container \
python3 -m unittest discover -s tests -v
```

Интеграционная проверка созданного контейнера штатным КриптоПро:

```bash
tools/check_with_csp.sh ./container [pin]
```

---

## Производительность

PBKDF2/КDF по ГОСТ с 2000 итерациями реализованы на чистом Python, поэтому
`create`/`export` с PIN занимают несколько секунд (обычно 5–15 секунд в
зависимости от алгоритма и машины). Для тестовых контейнеров ViPNet можно
уменьшить `iterations` в спецификации; для КриптоПро число итераций
фиксировано форматом и равно 2000 (2 при пустом PIN).

---

## Структура проекта

```
cspcombine                  # исполняемый файл (CLI)
cspcombine_lib/
  cli.py                    # команды и разбор аргументов
  schema.py                 # JSON-спецификация, значения по умолчанию
  keys.py                   # PEM, даты, разбор/генерация ключей
  gost.py                   # ГОСТ 28147-89, 34.11-94, Streebog, PBKDF2, EC
  der.py                    # ASN.1/DER и PEM
  curves.py                 # именованные кривые и OID
  vipnet.py                 # чтение/извлечение/создание ViPNet
  cryptopro.py              # чтение/извлечение/создание КриптоПро
  streebog_tables.py        # таблицы Streebog (скопированы из vipnet)
examples/                   # примеры JSON и JSON Schema
tools/check_with_csp.sh     # проверка контейнера штатным csptest
.github/workflows/          # CI и сборка релизов
tests/                      # unit-тесты
```

---

## Безопасность

* Инструмент работает локально и не отправляет данные в сеть.
* Сгенерированный PIN печатается в stderr — сохраните его, иначе доступ к
  контейнеру будет потерян.
* Закрытые ключи в PEM и контейнеры следует хранить с правами `0600`.
* Не используйте реальные ключи в тестовых примерах и логах.
