# wazuh-soc-lab

![CI](https://github.com/RemigayloYegor/wazuh-soc-lab/actions/workflows/ci.yml/badge.svg)

SOC-лаборатория на **Wazuh 4.x**: SIEM с агентами Windows и Linux, 7 собственных правил
детектирования с разметкой **MITRE ATT&CK**, Python-детектор сканирования портов, учёт
узлов через Wazuh API и генератор отчётов по алертам.

```
            ┌─────────────┐
  Kali ────▶│ win10-agent │──(Sysmon)──┐
 (атаки)    └─────────────┘            │        ┌──────────────────┐
            ┌─────────────┐            ├──────▶ │  wazuh-manager   │──▶ Dashboard
  Kali ────▶│ ubuntu-agent│──(UFW+     │        │  local_rules.xml │    (Threat Hunting)
 (атаки)    └─────────────┘  soclab)───┘        └──────────────────┘
```

## Что в репозитории

| Путь | Назначение |
|---|---|
| [rules/local_rules.xml](rules/local_rules.xml) | 7 правил детектирования (ID 100100–100106) |
| [soclab/portscan.py](soclab/portscan.py) | детектор скана портов (скользящее окно по источнику) |
| [soclab/alerts_report.py](soclab/alerts_report.py) | разбор `alerts.json` → Markdown-отчёт |
| [soclab/inventory.py](soclab/inventory.py) | учёт агентов через Wazuh API → CSV |
| [config/](config/) | Sysmon, фрагменты `ossec.conf`, systemd-юнит |
| [scripts/](scripts/) | деплой правил, установка Sysmon, безопасные симуляции атак |
| [docs/](docs/) | сценарии атак с MITRE, шаблон отчёта об инциденте |

## Правила детектирования

| ID | Детект | Платформа | MITRE | Уровень |
|---|---|---|---|---|
| 100100 | SSH-брутфорс (8+ неудач / 120с с одного IP) | Linux | T1110.001 | 10 |
| 100101 | PowerShell с `-EncodedCommand` | Windows | T1059.001, T1027 | 12 |
| 100102 | Командная строка в стиле Mimikatz | Windows | T1003.001 | 14 |
| 100103 | Доступ к памяти LSASS (Sysmon 10) | Windows | T1003.001 | 13 |
| 100104 | Запись в ключ автозапуска Run/RunOnce | Windows | T1547.001 | 10 |
| 100105 | Создание задачи через `schtasks /create` | Windows | T1053.005 | 9 |
| 100106 | Скан портов (от Python-детектора) | Linux | T1046 | 10 |

## Python-инструменты

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

# Детектор сканирования: лог файрвола -> JSON-алерты для Wazuh
soclab portscan /var/log/ufw.log -o /var/log/soclab/portscan.json

# Отчёт по алертам Wazuh
soclab report /var/ossec/logs/alerts/alerts.json -o report.md --min-level 8

# Учёт агентов через API (пароль из переменной WAZUH_API_PASSWORD)
soclab agents --url https://192.168.56.10:55000 -k -o agents.csv
```

## Развёртывание лаборатории (кратко)

1. **Менеджер** — `wazuh-docker` (single-node), требует Docker:
   ```bash
   git clone https://github.com/wazuh/wazuh-docker -b v4.14.0
   cd wazuh-docker/single-node
   docker compose up -d
   ```
2. **Правила** — `scripts/deploy-rules.sh` копирует `local_rules.xml`, проверяет
   (`wazuh-analysisd -t`) и перезапускает менеджер.
3. **Агент Windows** — установить агент, затем `scripts/install-sysmon.ps1`,
   подключить журналы фрагментом `config/agent-windows.ossec.conf`.
4. **Агент Linux** — установить агент, включить UFW-логи и детектор
   (`config/agent-linux.ossec.conf`, `config/soclab-portscan.service`).
5. **Проверка** — безопасные симуляции из `scripts/attack-sim/`, затем алерты в
   Dashboard по фильтру `rule.groups: soclab`.

## Тесты

```powershell
ruff check .
pytest -q
```

54 теста. Покрывают детектор скана (вертикальный/горизонтальный, окно, повторные алерты),
разбор отчётов, пагинацию Wazuh API и CLI. Правила `local_rules.xml` проверяются офлайн:
тест разбирает XML и прогоняет регулярки каждого правила на образцах событий Sysmon и sshd
(позитивные и негативные случаи). Это не заменяет `wazuh-logtest` на менеджере, но ловит
опечатки в правилах до деплоя.

> **Важно:** скрипты в `scripts/attack-sim/` предназначены только для собственных ВМ в
> изолированной сети лаборатории.

## Дальнейшие шаги

- Active Response: автоблок IP брутфорсера через iptables
- Интеграция с VirusTotal/AbuseIPDB для обогащения алертов
- Экспорт правил в формат Sigma
