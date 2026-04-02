# CHANGELOG

Все значимые изменения проекта документируются здесь.
Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/).

---

## [Unreleased]

### Added
- Полная реализация NetCertGuardian v0.1.0
- `net_cert_scanner/models.py` — dataclasses: CertInfo, HostInfo, ScanError, ScanResult
- `net_cert_scanner/config.py` — Pydantic v2 конфиг с автосозданием config.yaml
- `net_cert_scanner/discovery.py` — TCP:445 discovery, параллельное сканирование
- `net_cert_scanner/collector.py` — WMI execution через impacket (DCOM), Base64-encoded PS команды
- `net_cert_scanner/analyzer.py` — классификация сертификатов (expired/expiring/ok)
- `net_cert_scanner/reports.py` — CSV, JSON, error log, summary.json
- `net_cert_scanner/html_report.py` — self-contained HTML с embedded данными, сортировкой, фильтрацией, гистограммой
- `net_cert_scanner/rotation.py` — ротация по количеству и возрасту папок
- `net_cert_scanner/__main__.py` — оркестрация, exit codes 0/1
- `tests/` — unit-тесты для models, config, analyzer, rotation, reports
- CI pipeline: `.github/workflows/ci.yml`
- `Makefile` — install, test, lint, run
- `CONSTITUTION.md` — принципы проекта
- `AGENTS.md` — инструкции для ИИ-агентов
- `CONTINUITY.md` — контекст сессии

### Architecture decisions
- Discovery: TCP:445 как основной метод (надёжнее ICMP в Windows-сетях)
- Collection: impacket WMI (wmiexec-паттерн) — единственный вызов на хост
- PowerShell команды кодируются в Base64 (EncodedCommand) — нет проблем с экранированием
- HTML: данные вшиты как JS-переменная, не читаются из файла (обход file:// CORS)
- Идентификатор хоста: hostname (из ответа машины), MAC как дополнение

---

## [0.0.1] — 2026-04-02

### Added
- Инициализация репозитория
- README.md
