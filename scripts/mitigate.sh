#!/usr/bin/env bash
# Пример скрипта реагирования.
# Аргумент 1: строка IP через запятую (ip1,ip2,ip3)
IPS="$1"
echo "[mitigate] got IPs: $IPS"

# Ниже пример: просто печать. В реальной системе:
# - можно добавлять в ipset
# - можно вызывать iptables/nftables
# - можно отправлять команды на роутер/балансировщик
# ipset add ddos_blacklist <ip> timeout 600

exit 0
