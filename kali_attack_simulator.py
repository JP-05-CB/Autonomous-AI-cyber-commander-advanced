#!/usr/bin/env python3
"""
kali_attack_simulator.py — 20-Second Sustained Telemetry Simulator (v5.2)
Includes Multi-IP Source Spoofing, Distributed Botnet Swarms & 16 Total Attack Scenarios!

What Is New in v5.2:
  1. Multi-IP Spoofing & Botnet Swarm Testing (`--attack new` or `--spoof-ips`):
     - Tests whether Cyber Commander can detect and block attacks when the attacker
       continuously spoofs/rotates their source IP address every second (or attacks from
       a multi-IP botnet swarm simultaneously).
     - Demonstrates how Cyber Commander's IP-agnostic Behavioral Fingerprint (`AttackMemoryDB`)
       learns the attack pattern on Wave #1 (from Spoofed IP #1) and blocks Waves #2..#20
       (from Spoofed IPs #2..#20) in <0.5 ms via the Attack Memory Fast-Path!
  2. 6 Brand-New Simulated Scenarios (#11 to #16):
     - [11] `ipspoof`   : Multi-IP Source Spoofing SYN/TCP Flood (20 rotating spoofed IPs)
     - [12] `botnet`    : Distributed Multi-IP Botnet HTTP Layer-7 Swarm (3 concurrent bot IPs/wave)
     - [13] `udp_amp`   : Spoofed UDP Reflection / DNS & NTP Amplification Flood (12x amplification)
     - [14] `arpspoof`  : Layer-2 ARP Cache Poisoning & MITM Spoofing Simulation
     - [15] `land_frag` : Spoofed LAND & Overlapping IP Fragmentation Header Exploit
     - [16] `c2_swarm`  : Multi-Host SMB Lateral Worm & C2 Botnet Beaconing Simulation
  3. Works seamlessly with `target_effect_monitor.py` (UDP:9090) and `cyber_commander.py` (UDP:53530 / TCP:8080).

Usage Examples:
  # Run ONLY the 6 new Multi-IP Spoofing & Botnet scenarios (20s each):
  python3 kali_attack_simulator.py --target 192.168.56.105 --attack new

  # Run the Multi-IP Source Spoofing scenario specifically:
  python3 kali_attack_simulator.py --target 192.168.56.105 --attack ipspoof

  # Run ANY attack with rotating spoofed source IPs enabled:
  python3 kali_attack_simulator.py --target 192.168.56.105 --attack sqli --spoof-ips

  # Run all 16 scenarios (10 original + 6 new multi-IP spoofing scenarios):
  python3 kali_attack_simulator.py --target 192.168.56.105 --attack all

  # Launch interactive menu:
  python3 kali_attack_simulator.py --target 192.168.56.105 --interactive
"""

import os
import sys
import time
import json
import socket
import argparse
from typing import Dict, Any, Tuple, List

BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
AMBER = "\033[33m"
RED = "\033[31m"
RESET = "\033[0m"

ACTION_BY_ATTACK: Dict[str, str] = {
    "SQL_INJECTION": "WAF_AND_FIREWALL_SQLI_DROP",
    "XSS_AND_WEB_INJECTION": "WAF_AND_FIREWALL_RCE_DROP",
    "PATH_TRAVERSAL_LFI": "WAF_AND_FIREWALL_LFI_DROP",
    "SLOW_HTTP": "FIREWALL_CONN_LIMIT_AND_DROP",
    "BRUTE_FORCE": "FIREWALL_AUTH_DROP",
    "ICMP_PING_FLOOD": "FIREWALL_ICMP_ECHO_DROP",
    "DNS_TUNNELING": "FIREWALL_DNS_BLOCK",
    "PORT_SCAN": "FIREWALL_SCAN_DROP",
    "SYN_FLOOD_DDOS": "XDP_EARLY_SYN_DROP",
    "HTTP_L7_FLOOD": "WAF_AND_FIREWALL_HTTP_FLOOD_DROP",
    "UDP_AMPLIFICATION_DDOS": "XDP_AMP_REFLECTION_DROP",
    "ARP_MITM_SPOOFING": "L2_ARP_GUARD_AND_IP_DROP",
    "LAND_AND_IP_FRAGMENT_ATTACK": "XDP_MALFORMED_FRAGMENT_DROP",
    "SMB_RANSOMWARE_WORM": "FIREWALL_SMB_LATERAL_CONTAINMENT",
    "C2_BOTNET_BEACONING": "FIREWALL_C2_EGRESS_AND_INGRESS_DROP",
    "ZERO_DAY_ANOMALY": "XDP_AND_FIREWALL_DROP",
}


def get_local_kali_ip(target_ip: str) -> str:
    """Detects the Kali IP address; if run on the same host as target_ip, uses 10.10.14.99."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect((target_ip, 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127.") and ip != target_ip:
            return ip
    except Exception:
        pass
    return "10.10.14.99"


def generate_spoofed_ips_for_wave(subnet_prefix: str, wave: int, count: int = 1) -> List[str]:
    """
    Generates deterministic, realistic spoofed source IPs for each wave so you can
    clearly verify each spoofed IP in Cyber Commander's terminal and Attack History.
    """
    ips: List[str] = []
    for i in range(count):
        host_octet = ((wave - 1) * count + i + 101) % 250
        if host_octet < 2:
            host_octet += 2
        ips.append(f"{subnet_prefix}.{host_octet}")
    return ips


def send_telemetry_to_commander(target_ip: str, http_port: int, udp_port: int, frame: Dict[str, Any]) -> bool:
    """
    Delivers the telemetry wave to Cyber Commander via UDP:53530 AND TCP:8080.
    Returns True if Cyber Commander actively replied that it intercepted/blocked the wave.
    """
    commander_replied = False

    # 1. Send via UDP:53530 (and check for instant ack from Cyber Commander)
    s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_udp.settimeout(0.15)
    try:
        payload = ("KALI_UDP_FRAME:" + json.dumps(frame) + "\n").encode("utf-8")
        s_udp.sendto(payload, (target_ip, udp_port))
        try:
            ack_raw, _ = s_udp.recvfrom(2048)
            if b"BLOCKED_BY_CYBER_COMMANDER" in ack_raw:
                commander_replied = True
        except Exception:
            pass
    except Exception:
        pass
    finally:
        s_udp.close()

    # 2. Also send via TCP:8080 (`KALI_SIM_FRAME:`) for 100% compatibility
    if not commander_replied:
        s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_tcp.settimeout(0.20)
        try:
            s_tcp.connect((target_ip, http_port))
            tcp_payload = ("KALI_SIM_FRAME:" + json.dumps(frame) + "\n").encode("utf-8")
            s_tcp.sendall(tcp_payload)
            resp = s_tcp.recv(512)
            if b"CYBER_COMMANDER" in resp or b"403 Forbidden" in resp:
                commander_replied = True
        except Exception:
            pass
        finally:
            s_tcp.close()

    return commander_replied


def query_target_effect_monitor(
    target_ip: str,
    effect_port: int,
    src_ip: str,
    attack_type: str,
    wave: int,
    elapsed_sec: int,
    duration_sec: int,
    commander_replied: bool,
) -> Dict[str, Any]:
    """
    Sends the current simulation wave to `target_effect_monitor.py` (UDP port 9090)
    and receives back the live simulated impact metrics on the target system.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.30)
    req = {
        "src_ip": src_ip,
        "attack_type": attack_type,
        "wave": wave,
        "elapsed_sec": elapsed_sec,
        "duration_sec": duration_sec,
    }
    try:
        raw = ("SIM_EFFECT_FRAME:" + json.dumps(req) + "\n").encode("utf-8")
        s.sendto(raw, (target_ip, effect_port))
        resp_data, _ = s.recvfrom(4096)
        return json.loads(resp_data.decode("utf-8", errors="ignore"))
    except Exception:
        if commander_replied:
            return {
                "ip_blocked": True,
                "mitigation_action": ACTION_BY_ATTACK.get(attack_type, "FIREWALL_DROP"),
                "cpu_pct": 6,
                "latency_ms": 3,
            }
        return {}
    finally:
        s.close()


def format_target_effect_line(
    effect_resp: Dict[str, Any],
    wave: int,
    default_cpu: int,
    default_lat: int,
    default_state: str,
    spoof_label: str = "",
) -> str:
    prefix = f"{AMBER}{spoof_label}{RESET} | " if spoof_label else ""
    if effect_resp:
        if effect_resp.get("ip_blocked"):
            act = effect_resp.get("mitigation_action", "FIREWALL_DROP")
            cpu = effect_resp.get("cpu_pct", 6)
            lat = effect_resp.get("latency_ms", 3)
            return f"{prefix}{GREEN}[STOPPED BY CYBER COMMANDER: {act}] CPU: {cpu}% | Latency: {lat}ms (HEALTHY){RESET}"
        else:
            cpu = effect_resp.get("cpu_pct", default_cpu)
            lat = effect_resp.get("latency_ms", default_lat)
            st = effect_resp.get("service_state", default_state)
            return f"{prefix}{RED}[TARGET EFFECT ACTIVE] CPU: {cpu}% | Latency: {lat}ms | {st[:28]}{RESET}"
    return f"{prefix}{RED}[TARGET EFFECT ACTIVE] CPU: {default_cpu}% | Latency: {default_lat}ms | {default_state[:28]}{RESET}"


def run_sustained_20s_attack(
    idx: int,
    total_attacks: int,
    title: str,
    attack_code: str,
    wave_fn,
    duration_sec: int = 20,
) -> None:
    print(f"\n{DIM}" + "-" * 104 + f"{RESET}")
    print(f"{BOLD}{AMBER}[Simulated Attack #{idx}/{total_attacks}] Running {duration_sec}-Second Sustained Scenario:{RESET} {BOLD}{CYAN}{title}{RESET}")
    print(f"{DIM}" + "-" * 104 + f"{RESET}")

    t_start = time.time()
    wave_num = 0
    total_packets_sent = 0
    unique_ips_seen = set()

    while True:
        elapsed = time.time() - t_start
        if elapsed >= duration_sec:
            break

        wave_num += 1
        t_wave = time.time()
        effect_str, pkts_in_wave, ips_in_wave = wave_fn(wave_num, int(elapsed) + 1, duration_sec)
        total_packets_sent += pkts_in_wave
        unique_ips_seen.update(ips_in_wave)

        now_elapsed = min(duration_sec, int(time.time() - t_start) + 1)
        bar_len = 14
        filled = int((now_elapsed / duration_sec) * bar_len)
        bar = "█" * filled + "░" * (bar_len - filled)

        print(
            f"  [{bar}] {BOLD}{now_elapsed:02d}s/{duration_sec:02d}s{RESET} | "
            f"Wave #{wave_num:02d} | Pkts:{BOLD}{total_packets_sent:<4}{RESET} | {effect_str}",
            flush=True,
        )

        spent = time.time() - t_wave
        rem = max(0.0, min(1.0 - spent, duration_sec - (time.time() - t_start)))
        if rem > 0:
            time.sleep(rem)

    total_actual_sec = time.time() - t_start
    print(
        f"  {BOLD}{GREEN}[✓ Completed {total_actual_sec:.1f}s Sustained {attack_code} Simulation]{RESET} "
        f"Waves: {wave_num} | Unique Source IPs Tested: {BOLD}{len(unique_ips_seen)}{RESET} | Total Simulated Packets: {total_packets_sent}"
    )


def run_kali_attacks(
    target_ip: str,
    http_port: int = 8080,
    ssh_port: int = 2222,
    udp_port: int = 53530,
    effect_port: int = 9090,
    kali_ip: str = "",
    selected: str = "all",
    duration_per_attack: int = 20,
    force_spoof_ips: bool = False,
):
    if not kali_ip:
        kali_ip = get_local_kali_ip(target_ip)

    print(f"{DIM}" + "=" * 104 + f"{RESET}")
    print(f"{BOLD}{CYAN}  KALI LINUX 20-SECOND SUSTAINED SIMULATOR (v5.2 — MULTI-IP SPOOFING & BOTNET EDITION) -> {target_ip}{RESET}")
    print(f"  Primary Source IP      : {BOLD}{AMBER}{kali_ip}{RESET} (Multi-IP Spoofing Rotation: {'ENABLED FOR ALL' if force_spoof_ips else 'ACTIVE ON SCENARIOS #11-#16'})")
    print(f"  Duration Per Scenario  : {BOLD}{GREEN}{duration_per_attack} seconds (Continuous 1-Second Telemetry Waves){RESET}")
    print(f"  Target Ports           : UDP/{udp_port} & TCP/{http_port} (Cyber Commander) | UDP/{effect_port} (Target Effect Monitor)")
    print(f"{DIM}" + "=" * 104 + f"{RESET}")

    # Each tuple:
    # (short_key, title, attack_code, base_frame, def_cpu, def_lat, def_state, pkts_per_wave, spoof_subnet_or_None, ips_per_wave)
    scenarios = [
        # --- ORIGINAL 10 SCENARIOS (#1 to #10) ---
        (
            "sqli",
            "SQL Injection (Database Query Anomaly Simulation)",
            "SQL_INJECTION",
            {
                "attack_type": "SQL_INJECTION",
                "attack_hint": "SQL_INJECTION",
                "dst_port": http_port,
                "protocol": "TCP",
                "packets_per_sec": 45.0,
                "bytes_per_pkt": 640.0,
                "conn_rate_per_sec": 12.0,
                "l7_payload_sig_score": 9.5,
            },
            84,
            1850,
            "DATABASE ALERT — UNAUTHORIZED QUERY",
            15,
            None,
            1,
        ),
        (
            "rce",
            "Web Script & Command Injection Simulation",
            "XSS_AND_WEB_INJECTION",
            {
                "attack_type": "XSS_AND_WEB_INJECTION",
                "attack_hint": "XSS_AND_WEB_INJECTION",
                "dst_port": http_port,
                "protocol": "TCP",
                "packets_per_sec": 38.0,
                "bytes_per_pkt": 590.0,
                "conn_rate_per_sec": 10.0,
                "l7_payload_sig_score": 9.6,
            },
            89,
            2120,
            "APPLICATION WORKER STALL",
            12,
            None,
            1,
        ),
        (
            "lfi",
            "Directory Path Traversal (LFI Simulation)",
            "PATH_TRAVERSAL_LFI",
            {
                "attack_type": "PATH_TRAVERSAL_LFI",
                "attack_hint": "PATH_TRAVERSAL_LFI",
                "dst_port": http_port,
                "protocol": "TCP",
                "packets_per_sec": 32.0,
                "bytes_per_pkt": 420.0,
                "conn_rate_per_sec": 9.0,
                "l7_payload_sig_score": 9.1,
            },
            78,
            1490,
            "RESTRICTED FILE PATH PROBE",
            10,
            None,
            1,
        ),
        (
            "slowloris",
            "Slow HTTP (Slowloris Socket Exhaustion Simulation)",
            "SLOW_HTTP",
            {
                "attack_type": "SLOW_HTTP",
                "dst_port": http_port,
                "concurrent_conns": 80.0,
                "avg_conn_duration_sec": 42.0,
                "request_completion_ratio": 0.08,
                "bytes_per_pkt": 72.0,
                "packets_per_sec": 42.0,
            },
            92,
            3420,
            "HTTP 503 SOCKET POOL EXHAUSTED",
            25,
            None,
            1,
        ),
        (
            "bruteforce",
            "SSH / Login Password Brute-Force Simulation",
            "BRUTE_FORCE",
            {
                "attack_type": "BRUTE_FORCE",
                "dst_port": ssh_port,
                "auth_failures_per_min": 55.0,
                "unique_usernames_tried": 14.0,
                "packets_per_sec": 35.0,
            },
            86,
            1980,
            "AUTH QUEUE SATURATED",
            18,
            None,
            1,
        ),
        (
            "icmp",
            "ICMP Ping Flood (Bandwidth Saturation Simulation)",
            "ICMP_PING_FLOOD",
            {
                "attack_type": "ICMP_PING_FLOOD",
                "attack_hint": "ICMP_PING_FLOOD",
                "dst_port": 0,
                "protocol": "ICMP",
                "packets_per_sec": 1350.0,
                "icmp_pps": 1300.0,
                "bytes_per_pkt": 1472.0,
                "payload_byte_entropy": 2.6,
            },
            95,
            2890,
            "NETWORK PACKET QUEUE OVERFLOW",
            65,
            None,
            1,
        ),
        (
            "dns",
            "DNS Tunneling (Covert Exfiltration Simulation)",
            "DNS_TUNNELING",
            {
                "attack_type": "DNS_TUNNELING",
                "dst_port": 53,
                "query_name": "a9f8k7m6x5p4q3z2w1e0r9t8y7u6i5o4p3a2s1d0f9g8h7j6k5l4.sim-tunnel.example",
                "dns_qps": 45.0,
                "packets_per_sec": 55.0,
            },
            81,
            1640,
            "DNS HIGH-ENTROPY STREAM",
            45,
            None,
            1,
        ),
        (
            "portscan",
            "Network Port Scanning (85-Port Sweep Simulation)",
            "PORT_SCAN",
            {
                "attack_type": "PORT_SCAN",
                "dst_port": 0,
                "unique_dst_ports": 85.0,
                "conn_rate_per_sec": 120.0,
                "syn_to_ack_ratio": 9.5,
                "avg_conn_duration_sec": 0.03,
                "packets_per_sec": 175.0,
            },
            83,
            1720,
            "85 PORTS PROBED",
            40,
            None,
            1,
        ),
        (
            "synflood",
            "TCP SYN Flood (Handshake Backlog Simulation)",
            "SYN_FLOOD_DDOS",
            {
                "attack_type": "SYN_FLOOD_DDOS",
                "attack_hint": "SYN_FLOOD_DDOS",
                "dst_port": 80,
                "protocol": "TCP",
                "packets_per_sec": 2500.0,
                "bytes_per_pkt": 56.0,
                "conn_rate_per_sec": 2100.0,
                "concurrent_conns": 550.0,
                "syn_to_ack_ratio": 42.0,
                "request_completion_ratio": 0.01,
                "payload_byte_entropy": 1.8,
            },
            97,
            3850,
            "SYN_RECV BACKLOG FULL",
            120,
            None,
            1,
        ),
        (
            "zeroday",
            "Novel Zero-Day Polymorphic High-Entropy Flood Simulation",
            "ZERO_DAY_ANOMALY",
            {
                "attack_type": "ZERO_DAY_ANOMALY",
                "attack_hint": "ZERO_DAY_ANOMALY",
                "dst_port": udp_port,
                "protocol": "UDP",
                "packets_per_sec": 1950.0,
                "bytes_per_pkt": 1350.0,
                "conn_rate_per_sec": 450.0,
                "concurrent_conns": 220.0,
                "request_completion_ratio": 0.05,
                "unique_dst_ports": 8.0,
                "syn_to_ack_ratio": 16.0,
                "payload_byte_entropy": 7.85,
            },
            96,
            3560,
            "ZERO-DAY ENTROPY OVERLOAD",
            90,
            None,
            1,
        ),

        # --- NEW MULTI-IP SPOOFING & BOTNET SCENARIOS (#11 to #16) ---
        (
            "ipspoof",
            "Multi-IP Source Spoofing SYN Flood (20 Rotating Spoofed IPs: 10.10.99.101..120)",
            "SYN_FLOOD_DDOS",
            {
                "attack_type": "SYN_FLOOD_DDOS",
                "attack_hint": "SYN_FLOOD_DDOS",
                "dst_port": 80,
                "protocol": "TCP",
                "packets_per_sec": 2600.0,
                "bytes_per_pkt": 56.0,
                "conn_rate_per_sec": 2200.0,
                "concurrent_conns": 560.0,
                "syn_to_ack_ratio": 45.0,
                "request_completion_ratio": 0.01,
                "payload_byte_entropy": 1.8,
            },
            98,
            3920,
            "SPOOFED MULTI-IP SYN_RECV EXHAUSTION",
            140,
            "10.10.99",
            1,
        ),
        (
            "botnet",
            "Distributed Botnet Swarm HTTP L7 Flood (3 Concurrent Bot IPs/Wave: 172.16.88.x)",
            "HTTP_L7_FLOOD",
            {
                "attack_type": "HTTP_L7_FLOOD",
                "attack_hint": "HTTP_L7_FLOOD",
                "dst_port": http_port,
                "protocol": "TCP",
                "packets_per_sec": 850.0,
                "bytes_per_pkt": 512.0,
                "conn_rate_per_sec": 320.0,
                "concurrent_conns": 240.0,
                "request_completion_ratio": 0.85,
                "payload_byte_entropy": 4.8,
            },
            94,
            3180,
            "BOTNET L7 HTTP WORKER OVERLOAD",
            95,
            "172.16.88",
            3,
        ),
        (
            "udp_amp",
            "Spoofed UDP Reflection / DNS & NTP Amplification DDoS (Reflector IPs: 198.51.100.x)",
            "UDP_AMPLIFICATION_DDOS",
            {
                "attack_type": "UDP_AMPLIFICATION_DDOS",
                "attack_hint": "UDP_AMPLIFICATION_DDOS",
                "dst_port": 53,
                "protocol": "UDP",
                "packets_per_sec": 1800.0,
                "bytes_per_pkt": 1420.0,
                "udp_amplification_ratio": 12.5,
                "payload_byte_entropy": 5.4,
            },
            95,
            3340,
            "AMPLIFIED UDP BANDWIDTH SATURATION",
            110,
            "198.51.100",
            2,
        ),
        (
            "arpspoof",
            "Layer-2 ARP Cache Poisoning & Man-in-the-Middle Spoofing (Rotating LAN IPs: 192.168.56.2xx)",
            "ARP_MITM_SPOOFING",
            {
                "attack_type": "ARP_MITM_SPOOFING",
                "attack_hint": "ARP_MITM_SPOOFING",
                "dst_port": 0,
                "protocol": "ARP",
                "packets_per_sec": 120.0,
                "bytes_per_pkt": 64.0,
                "malformed_header_score": 9.5,
                "arp_conflict": True,
            },
            88,
            2450,
            "ARP CACHE POISONED — MITM INTERCEPT",
            30,
            "192.168.56",
            1,
        ),
        (
            "land_frag",
            "Spoofed LAND & Overlapping IP Fragmentation Exploit (Rotating Spoof IPs: 10.20.30.x)",
            "LAND_AND_IP_FRAGMENT_ATTACK",
            {
                "attack_type": "LAND_AND_IP_FRAGMENT_ATTACK",
                "attack_hint": "LAND_AND_IP_FRAGMENT_ATTACK",
                "dst_port": 80,
                "protocol": "TCP",
                "packets_per_sec": 620.0,
                "bytes_per_pkt": 1480.0,
                "malformed_header_score": 9.8,
            },
            93,
            3100,
            "IP FRAGMENT REASSEMBLY BUFFER STALL",
            55,
            "10.20.30",
            2,
        ),
        (
            "c2_swarm",
            "Multi-Host SMB Ransomware Worm & C2 Beaconing Swarm (Compromised IPs: 10.10.50.x)",
            "SMB_RANSOMWARE_WORM",
            {
                "attack_type": "SMB_RANSOMWARE_WORM",
                "attack_hint": "SMB_RANSOMWARE_WORM",
                "dst_port": 445,
                "protocol": "TCP",
                "packets_per_sec": 210.0,
                "bytes_per_pkt": 890.0,
                "conn_rate_per_sec": 48.0,
                "l7_payload_sig_score": 8.8,
                "payload_byte_entropy": 6.6,
            },
            91,
            2680,
            "SMB PORT 445 LATERAL WORM PROBE",
            40,
            "10.10.50",
            2,
        ),
    ]

    new_keys = {"ipspoof", "botnet", "udp_amp", "arpspoof", "land_frag", "c2_swarm"}
    if selected == "new":
        active_list = [s for s in scenarios if s[0] in new_keys]
    elif selected == "all":
        active_list = scenarios
    else:
        active_list = [
            s for s in scenarios if selected == s[0] or (selected == "xss" and s[0] == "rce")
        ]
        if not active_list:
            active_list = [s for s in scenarios if s[0] in new_keys]

    total = len(active_list)
    for idx, (short_key, title, code, base_frame, def_cpu, def_lat, def_state, pkts_per_wave, spoof_subnet, ips_per_wave) in enumerate(active_list, start=1):
        effective_subnet = spoof_subnet or ("10.99.88" if force_spoof_ips else None)
        effective_count = ips_per_wave if spoof_subnet else (2 if force_spoof_ips else 1)

        def _make_wave_fn(b_frame, a_code, d_cpu, d_lat, d_state, p_wave, s_subnet, ip_cnt):
            def _wave(w: int, el: int, dur: int) -> Tuple[str, int, List[str]]:
                if s_subnet:
                    wave_ips = generate_spoofed_ips_for_wave(s_subnet, w, ip_cnt)
                    spoof_label = f"SpoofIP:{wave_ips[0]}" if len(wave_ips) == 1 else f"BotIPs:{wave_ips[0]}..+{len(wave_ips)-1}"
                else:
                    wave_ips = [kali_ip]
                    spoof_label = f"SrcIP:{kali_ip}"

                any_replied = False
                for ip_addr in wave_ips:
                    frame = dict(b_frame)
                    frame["src_ip"] = ip_addr
                    frame["process_details"] = (
                        f"Simulated {a_code} wave #{w} ({el}s/{dur}s) from spoofed/multi-IP source {ip_addr}"
                        if s_subnet
                        else f"Simulated {a_code} wave #{w} ({el}s/{dur}s) from {ip_addr}"
                    )
                    if send_telemetry_to_commander(target_ip, http_port, udp_port, frame):
                        any_replied = True

                time.sleep(0.15)
                eff = query_target_effect_monitor(
                    target_ip,
                    effect_port,
                    ", ".join(wave_ips),
                    a_code,
                    w,
                    el,
                    dur,
                    any_replied,
                )
                line_str = format_target_effect_line(eff, w, d_cpu, d_lat, d_state, spoof_label=spoof_label)
                return line_str, p_wave, wave_ips
            return _wave

        run_sustained_20s_attack(
            idx,
            total,
            title,
            code,
            _make_wave_fn(base_frame, code, def_cpu, def_lat, def_state, pkts_per_wave, effective_subnet, effective_count),
            duration_sec=duration_per_attack,
        )

    print(f"\n{DIM}" + "=" * 104 + f"{RESET}")
    print(f"{BOLD}{GREEN}  [SIMULATION COMPLETE] All {total} scenarios executed ({duration_per_attack}s each) against {target_ip}!{RESET}")
    print(f"{DIM}" + "=" * 104 + f"{RESET}")


def interactive_menu(
    target_ip: str,
    http_port: int,
    ssh_port: int,
    udp_port: int,
    effect_port: int,
    kali_ip: str,
    duration_per_attack: int,
    force_spoof_ips: bool = False,
):
    options = {
        "1": ("icmp", "ICMP Ping Flood Simulation (20+ sec)"),
        "2": ("sqli", "SQL Injection Simulation (20+ sec)"),
        "3": ("rce", "Web Script / Command Injection Simulation (20+ sec)"),
        "4": ("lfi", "Directory Path Traversal Simulation (20+ sec)"),
        "5": ("slowloris", "Slow HTTP Socket Exhaustion Simulation (20+ sec)"),
        "6": ("bruteforce", "SSH / Login Brute-Force Simulation (20+ sec)"),
        "7": ("dns", "DNS Tunneling Simulation (20+ sec)"),
        "8": ("portscan", "Multi-Port Scan Simulation (20+ sec)"),
        "9": ("synflood", "TCP SYN Flood Simulation (20+ sec)"),
        "10": ("zeroday", "Novel Zero-Day High-Entropy Simulation (20+ sec)"),
        "11": ("ipspoof", "[NEW] Multi-IP Source Spoofing SYN Flood (20 Rotating Spoofed IPs)"),
        "12": ("botnet", "[NEW] Distributed Multi-IP Botnet HTTP Layer-7 Swarm (3 Bot IPs/Wave)"),
        "13": ("udp_amp", "[NEW] Spoofed UDP Reflection / DNS & NTP Amplification DDoS"),
        "14": ("arpspoof", "[NEW] Layer-2 ARP Cache Poisoning & MITM Spoofing Simulation"),
        "15": ("land_frag", "[NEW] Spoofed LAND & Overlapping IP Fragmentation Exploit"),
        "16": ("c2_swarm", "[NEW] Multi-Host SMB Lateral Worm & C2 Botnet Swarm Simulation"),
        "n": ("new", "Run ALL 6 NEW Multi-IP Spoofing & Botnet Scenarios (#11-#16)"),
        "a": ("all", "Run ALL 16 Scenarios Sequentially (20+ seconds each)"),
    }
    while True:
        print(f"\n{BOLD}{CYAN}--- 20-SECOND SUSTAINED SIMULATION MENU (v5.2 — Target: {target_ip}) ---{RESET}")
        for k, (_, desc) in options.items():
            color = GREEN if k in ("11", "12", "13", "14", "15", "16", "n") else RESET
            print(f"  [{BOLD}{k:<2}{RESET}] {color}{desc}{RESET}")
        print(f"  [{BOLD}q {RESET}] Quit")
        choice = input("Select scenario > ").strip().lower()
        if choice == "q":
            break
        if choice in options:
            run_kali_attacks(
                target_ip,
                http_port,
                ssh_port,
                udp_port,
                effect_port,
                kali_ip,
                selected=options[choice][0],
                duration_per_attack=duration_per_attack,
                force_spoof_ips=force_spoof_ips,
            )


def main():
    parser = argparse.ArgumentParser(description="20-Second Sustained Network Simulation with Multi-IP Spoofing & Target Effect Monitor (v5.2)")
    parser.add_argument("--target", default="127.0.0.1", help="IP address of the Target Host (e.g. 192.168.56.105)")
    parser.add_argument("--http-port", type=int, default=8080, help="Cyber Commander HTTP sensor port (default: 8080)")
    parser.add_argument("--ssh-port", type=int, default=2222, help="Cyber Commander SSH sensor port (default: 2222)")
    parser.add_argument("--udp-port", type=int, default=53530, help="Cyber Commander UDP sensor port (default: 53530)")
    parser.add_argument("--effect-port", type=int, default=9090, help="Target Effect Monitor UDP port (default: 9090)")
    parser.add_argument("--kali-ip", default="", help="Simulated source IP (auto-detected if omitted)")
    parser.add_argument(
        "--attack",
        default="new",
        help=(
            "Scenario to run: new (runs all 6 new Multi-IP Spoofing/Botnet scenarios), all (all 16), "
            "ipspoof, botnet, udp_amp, arpspoof, land_frag, c2_swarm, icmp, sqli, rce, lfi, slowloris, bruteforce, dns, portscan, synflood, zeroday"
        ),
    )
    parser.add_argument(
        "--spoof-ips",
        action="store_true",
        help="Force rotating spoofed source IPs on ANY selected attack scenario",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=20,
        help="Duration in seconds per scenario (default: 20 seconds; minimum 20s unless --fast-test)",
    )
    parser.add_argument("--fast-test", action="store_true", help="Allow shorter duration for quick automated checks")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive menu")
    args = parser.parse_args()

    dur = args.duration if args.fast_test else max(20, args.duration)

    if args.interactive:
        interactive_menu(args.target, args.http_port, args.ssh_port, args.udp_port, args.effect_port, args.kali_ip, dur, args.spoof_ips)
    else:
        run_kali_attacks(
            args.target,
            args.http_port,
            args.ssh_port,
            args.udp_port,
            args.effect_port,
            args.kali_ip,
            selected=args.attack,
            duration_per_attack=dur,
            force_spoof_ips=args.spoof_ips,
        )


if __name__ == "__main__":
    main()