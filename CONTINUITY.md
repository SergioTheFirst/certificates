# CONTINUITY.md — Контекст сессии

## Текущее состояние проекта

**Дата последнего обновления**: 2026-04-02  
**Ветка**: `claude/code-review-logic-fvbC8`  
**Версия**: 0.1.0 (в разработке)

---

## Что реализовано

- [x] CONSTITUTION.md, AGENTS.md, CHANGELOG.md, CONTINUITY.md
- [x] requirements.txt, requirements-dev.txt, Makefile
- [x] .github/workflows/ci.yml
- [x] config.yaml.example
- [x] net_cert_scanner/models.py
- [x] net_cert_scanner/config.py
- [x] net_cert_scanner/discovery.py
- [x] net_cert_scanner/collector.py
- [x] net_cert_scanner/analyzer.py
- [x] net_cert_scanner/reports.py
- [x] net_cert_scanner/html_report.py
- [x] net_cert_scanner/rotation.py
- [x] net_cert_scanner/__main__.py
- [x] tests/test_models.py
- [x] tests/test_config.py
- [x] tests/test_analyzer.py
- [x] tests/test_rotation.py
- [x] tests/test_reports.py

---

## Ключевые решения, принятые в ходе сессии

### Discovery
TCP connect на порт 445 (SMB) — не ICMP ping. Причина: Windows Firewall по умолчанию блокирует ICMP на рабочих станциях Win10/11.

### Collection
impacket WMI (DCOM) — не PsExec.exe. Причина: нет внешних бинарников, меньше шума для антивируса, полноценный Python API. Команды кодируются в Base64 (-EncodedCommand) чтобы избежать проблем с экранированием кавычек в PowerShell.

### Remote Registry
Отказались как от основного метода — служба Disabled по умолчанию на Win10/11. WMI оставлен основным, smbexec — fallback.

### HTML
Данные вшиваются как `const SCAN_DATA = {...}` в момент генерации. Не читают файлы из файловой системы (file:// блокирует CORS). Весь CSS и JS — inline.

### MAC как ID хоста
MAC ненадёжен в DHCP-сетях и на VM. Используется hostname как основной идентификатор, MAC — дополнительное поле.

---

## Известные ограничения

1. **WMI может быть заблокирован антивирусом** — fallback через smbexec, если оба не работают — ошибка.
2. **Программа работает только под Windows** — impacket для WMI требует Windows на стороне источника данных (или Linux с правильным NTLM). Тесты без сети — кросс-платформенные.
3. **Сертификаты только из LocalMachine\My** — конфигурируется через `certificates.store` в config.yaml.
4. **Нет поддержки Kerberos** — только NTLM. Для Kerberos нужна дополнительная настройка impacket.

---

## Что делать дальше (backlog)

- [ ] Поддержка CurrentUser\My (пользовательские сертификаты)
- [ ] Уведомления по email (SMTP в конфиге)
- [ ] Поддержка Windows Credential Manager для хранения пароля
- [ ] Сравнение с предыдущим сканом (новые/исчезнувшие проблемы)
- [ ] Экспорт в Excel (openpyxl)
- [ ] Поддержка сканирования из Linux (полностью через impacket)

---

## Команды для продолжения работы

```bash
# Запустить тесты
make test

# Проверить линтер
make lint

# Запустить программу (нужен config.yaml)
python -m net_cert_scanner
```
