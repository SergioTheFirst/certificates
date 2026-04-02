# AGENTS.md — Инструкции для ИИ-агентов

## Контекст проекта

**NetCertGuardian** — Python-утилита для Windows-администраторов.
Сканирует локальную сеть, собирает информацию о личных сертификатах (LocalMachine\My) на каждом компьютере через WMI/DCOM (impacket), генерирует HTML-отчёт и CSV.

Запускается по расписанию (Windows Task Scheduler). Не демон. После работы завершается.

---

## Структура репозитория

```
net_cert_scanner/
├── __main__.py      # точка входа, exit codes, оркестрация
├── models.py        # dataclasses: CertInfo, HostInfo, ScanError, ScanResult
├── config.py        # Pydantic-модель конфига, загрузка/создание config.yaml
├── discovery.py     # обнаружение живых хостов по TCP:445
├── collector.py     # WMI-подключение (impacket), выполнение PowerShell
├── analyzer.py      # классификация сертификатов (expired/expiring/ok)
├── reports.py       # сохранение CSV, JSON, error log, summary
├── html_report.py   # генерация self-contained cert-status.html
└── rotation.py      # ротация папок reports/

tests/
├── test_models.py
├── test_config.py
├── test_analyzer.py
├── test_rotation.py
└── test_reports.py
```

---

## Правила для агентов

### Что МОЖНО делать без подтверждения
- Читать любые файлы проекта
- Запускать тесты: `make test`
- Запускать линтер: `make lint`
- Коммитить в ветку `claude/code-review-logic-fvbC8`

### Что ТРЕБУЕТ подтверждения пользователя
- Изменение принципов в `CONSTITUTION.md`
- Добавление новых внешних зависимостей
- Любые операции с файлами вне репозитория
- Push в ветку `main`
- Создание Pull Request

### Запрещено
- Хранить пароли в логах, HTML, CSV
- Добавлять sleep/polling-петли в production-код (только в collector.py для ожидания output-файла — это исключение)
- Делать программу демоном
- Игнорировать ошибки сети (все фиксировать в ScanError)

---

## Ключевые технические решения

### Discovery
- **Основной метод**: TCP connect на порт 445, timeout 2 сек, параллельно 50 workers
- **Fallback**: ICMP ping (ненадёжен из-за Windows Firewall, использовать только как опцию)
- ARP-scan через scapy — ускорение, не основа (scapy опционален)

### Collection
Pipeline на каждый живой хост (в порядке приоритета):
1. **WMIExecutor** (impacket DCOM/WMI) — основной
2. **SmbExecExecutor** (impacket DCE/RPC сервис) — fallback
3. Если всё провалилось → `ScanError(ip, method, reason)`

PowerShell-скрипт выполняется **одним вызовом** и возвращает JSON:
```json
{"hostname": "PC001", "mac": "AA:BB:...", "certs": [...]}
```

Команда кодируется в Base64 (-EncodedCommand) для избежания проблем с экранированием.

### HTML
- Данные вшиты как `const SCAN_DATA = {...};` — **не читает файлы с диска**
- Без CDN, без интернета — весь CSS/JS inline
- Canvas API для гистограммы

---

## Работа с CONTINUITY.md

При каждой сессии:
1. Прочитать `CONTINUITY.md` — понять, на чём остановились
2. После работы — обновить `CONTINUITY.md` с актуальным состоянием
3. Обновить `CHANGELOG.md` если были изменения

---

## Команды разработки

```bash
# Установка зависимостей
make install

# Запуск тестов
make test

# Линтер + типизация
make lint

# Запуск программы (Windows)
python -m net_cert_scanner

# Создать дефолтный конфиг
python -m net_cert_scanner  # при отсутствии config.yaml
```

---

## Версионирование

- `CHANGELOG.md` — все изменения
- Коммиты: `feat:`, `fix:`, `refactor:`, `test:`, `docs:` префиксы
- Ветка разработки: `claude/code-review-logic-fvbC8`
