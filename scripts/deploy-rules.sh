#!/usr/bin/env bash
# Копирует local_rules.xml в контейнер менеджера Wazuh (wazuh-docker single-node),
# проверяет конфигурацию и перезапускает менеджер.
set -euo pipefail

CONTAINER="${WAZUH_MANAGER_CONTAINER:-single-node-wazuh.manager-1}"
RULES="$(dirname "$0")/../rules/local_rules.xml"

docker cp "$RULES" "$CONTAINER:/var/ossec/etc/rules/local_rules.xml"
docker exec "$CONTAINER" chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
# Проверка синтаксиса правил до перезапуска: при ошибке менеджер не поднимется
docker exec "$CONTAINER" /var/ossec/bin/wazuh-analysisd -t
docker exec "$CONTAINER" /var/ossec/bin/wazuh-control restart
echo "Правила загружены в $CONTAINER"
