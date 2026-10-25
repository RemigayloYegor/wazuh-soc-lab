# Доводка агентов до enrollment

Менеджер Wazuh развёрнут и работает (правила проверены, детект на реальной атаке подтверждён).
Осталось подключить к нему отдельные агенты Linux и Windows. Эти шаги требуют доступа к
консоли ВМ (headless-автоматизация упёрлась в отключённую парольную аутентификацию sshd и
неподнявшиеся Guest Additions на свежеустановленной Ubuntu).

Параметры стенда:
- Менеджер Wazuh: **10.10.10.4** (SSH-проброс `127.0.0.1:2210`, логин `wazuh-user` / `wazuh`).
- Дашборд: `https://127.0.0.1:2443`, логин `admin` / `admin`.
- Сеть лаборатории: NAT-network `soclab`, 10.10.10.0/24.

## Агент Linux (Ubuntu, 10.10.10.5)

Войти в консоль ВМ `ubuntu-agent` (логин `analyst` / `analyst`) и выполнить:

```bash
# 1. Разрешить парольный SSH (чтобы можно было управлять по сети)
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart ssh

# 2. Установить агент Wazuh и подключить к менеджеру
curl -sO https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.3-1_amd64.deb
sudo WAZUH_MANAGER="10.10.10.4" WAZUH_AGENT_NAME="ubuntu-agent" dpkg -i ./wazuh-agent_4.14.3-1_amd64.deb
sudo systemctl enable --now wazuh-agent

# 3. Инструменты для контролируемых атак и детектор скана портов
sudo apt-get update && sudo apt-get install -y nmap hydra python3 ufw
sudo ufw enable && sudo ufw logging on   # для правила 100106
```

## Агент Windows (Windows Server 2022)

ISO уже скачан: `D:\SOCLab\iso\ws2022-eval.iso`. Создать ВМ, поставить ОС, затем:

```powershell
# Агент Wazuh
msiexec /i wazuh-agent-4.14.3-1.msi /q WAZUH_MANAGER="10.10.10.4" WAZUH_AGENT_NAME="win-agent"
net start WazuhSvc
# Sysmon с конфигом лаборатории
.\scripts\install-sysmon.ps1
```

## Проверка после enrollment

```bash
# на менеджере — список агентов
sudo /var/ossec/bin/agent_control -l
```

Затем прогнать `scripts/attack-sim/` и собрать алерты правил 100101–100106.
