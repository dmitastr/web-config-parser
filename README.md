# web-config-parser

Инструмент для поиска потенциально опасных настроек в конфигурационных файлах
веб-приложений (JSON/YAML): открытые секреты, небезопасный bind-адрес,
включённый debug-режим, отключённая проверка TLS, устаревшие криптоалгоритмы.

Доступен в двух режимах: как CLI-утилита и как HTTP-сервер.

## Структура проекта

```
.
├── main.go                 # точка входа CLI
├── cmd/
│   └── server/
│       └── main.go         # точка входа HTTP-сервера
├── internal/
│   ├── app/                # загрузка конфигов (файл/stdin/директория) и запуск анализа
│   ├── analyzers/           # набор проверок (host, secrets, debug mode, TLS, алгоритмы)
│   ├── server/              # HTTP-хендлеры и обвязка над http.Server
│   ├── logging/             # инициализация логгера
│   └── models/               # структуры результатов анализа (Result, Finding)
└── go.mod
```

## Установка

```bash
go build -o bin/configapp ./
go build -o bin/configapp-server ./cmd/server
```

## CLI

```bash
# файл
./bin/configapp config.json

# stdin
cat config.yaml | ./bin/configapp --stdin --format yaml

# рекурсивно по директории
./bin/configapp --dir ./configs
```

| Флаг | Описание |
|---|---|
| `--stdin` | читать конфиг из стандартного ввода вместо файла |
| `-f, --format` | формат при чтении из stdin: `json`/`yaml` (обязателен вместе с `--stdin`) |
| `-d, --dir` | путь к директории для рекурсивного обхода конфигов |
| `-s, --silent` | не завершать процесс с ненулевым кодом при найденных проблемах |

Код завершения: `0` — проблем не найдено, `1` — найдены findings или ошибки обработки.

## HTTP-сервер

```bash
./bin/configapp-server --port 8080
```

```bash
curl -X POST 'http://localhost:8080/validate?format=json' \
     --data-binary @config.json
```

Формат также можно передать заголовком `X-Config-Format` вместо query-параметра.
Ответ — JSON-массив результатов анализа.

`GET /healthz` — проверка живости сервиса.

### Конфигурация сервера

Каждый флаг можно задать через переменную окружения; флаг имеет приоритет.

| Флаг | Env | По умолчанию |
|---|---|---|
| `--host` | `SERVER_HOST` | `127.0.0.1` |
| `--port` | `SERVER_PORT` | `8080` |
| `--read-timeout` | `SERVER_READ_TIMEOUT` | `5s` |
| `--write-timeout` | `SERVER_WRITE_TIMEOUT` | `10s` |
| `--idle-timeout` | `SERVER_IDLE_TIMEOUT` | `60s` |
| `--shutdown-timeout` | `SERVER_SHUTDOWN_TIMEOUT` | `10s` |
| `--max-body-bytes` | `SERVER_MAX_BODY_BYTES` | `5242880` (5 MiB) |
| `--log-level` | `SERVER_LOG_LEVEL` | `info` |

Сервер поддерживает graceful shutdown по `SIGINT`/`SIGTERM`.

## Проверки (analyzers)

| Анализатор | Что ищет |
|---|---|
| `HostAnalyzer` | бинды на все интерфейсы (`0.0.0.0`) без ограничений |
| `PlaintextSecretAnalyzer` | пароли/токены/ключи в открытом виде вместо плейсхолдеров окружения |
| `DebugModeAnalyzer` | включённый debug-режим, verbose-логирование, открытые debug-эндпоинты |
| `TLSDisableAnalyzer` | отключённую проверку TLS-сертификата (`insecure_skip_verify` и аналоги) |
| `OldCipherAlgoAnalyzer` | устаревшие/небезопасные алгоритмы (MD5, SHA1, RC4, TLS1.0/1.1, JWT alg=none и т.д.) |

Работает на произвольной JSON/YAML-структуре — без привязки к заранее известной схеме конфига.