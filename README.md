# Autonomous AI Cyber Commander (Advanced Edition)







**Autonomous AI Cyber Commander** is an end-to-end, real-time autonomous network defense framework that transitions cybersecurity operations from passive **detect-and-alert** monitoring to closed-loop **detect–correlate–decide–enforce–remember** mitigation.

By combining multi-vector network telemetry, an **18-feature Gaussian-Mahalanobis & Zero-Day Anomaly AI Engine**, agentic LLM function calling (**Google Gemini 2.5 Flash** & **Groq Llama-3.3-70B**), a deterministic **Policy Validator**, and wire-speed **Linux Kernel eBPF/XDP packet filtering**, the system autonomously identifies and blocks known, multi-IP spoofed, and zero-day cyberattacks in milliseconds.

---

## Key Architectural Highlights

| Capability | Technical Implementation | Operational Benefit |
| :--- | :--- | :--- |
| **Multi-Vector Real-Time Detection** | Raw kernel sockets (`IPPROTO_ICMP`, `IPPROTO_TCP`), Scapy sniffers, `/proc/net/snmp` & `/proc/net/arp` polling, and L7 DPI traps (`8080`, `8081`, `2222`, `53530`) | Detects **16 known attack families** plus unseen **Zero-Day volumetric/entropy anomalies** |
| **18-Feature Behavioral Fingerprint** | Extracts 18 transport, session, and L7 metrics to compute an IP-agnostic SHA-256 signature (`fp_<20_hex_chars>`) | Neutralizes **Multi-IP Source Spoofing** and **Distributed Botnet Swarms** on sight |
| **O(1) Attack Memory Fast-Path** | Dual-persistence SQLite (`attack_memory.db`), JSON (`attack_history.json`), and append-only audit log (`attack_history.log`) | Blocks repeat attacks and spoofed waves in **< 0.5 ms**, bypassing cloud LLM latency |
| **Hybrid AI + Cloud LLM Reasoning** | Local 17-class Gaussian-Mahalanobis classifier + Google Gemini & Groq `block_ip(ip, duration, reason)` tool calling | Combines sub-millisecond local statistical inference with contextual LLM security reasoning |
| **Deterministic Safety Guardrail** | `PolicyValidator` enforces host/gateway allowlists (via kernel `SIOCGIFADDR` `0x8915` `ioctl`), IP verification, and TTL caps (`1–3600s`) | Prevents AI hallucinations, arbitrary shell execution, and accidental self-lockout |
| **Wire-Speed eBPF/XDP Firewall** | Kernel C program (`eBPF.c`) attached via BCC with `BPF_HASH` blocklist map + automatic fallback to `nftables` / `iptables` | Drops malicious packets (`XDP_DROP`) at the NIC driver layer before `sk_buff` allocation |
| **Plug-and-Play USB Auto-Guard** | `start_usb_guard.sh` + `udev` / `systemd` rules auto-discover host IP/interface and launch the live console | Protects any Linux host immediately upon USB insertion without manual IP configuration |
| **Closed-Loop Impact Verification** | `TargetSystemEffectMonitor` (`UDP:9090` / `HTTP:9080`) tracks live CPU, socket pool, and latency recovery | Demonstrates real-time recovery from `97% CPU / 3850 ms` under attack to `6% CPU / 3 ms` |

---

## System Workflow & Decision Pipeline

### 1. End-to-End Autonomous Defense Pipeline

```text
Incoming Network Traffic (Raw ICMP/TCP, Scapy, /proc/net/snmp, L7 DPI Ports 8080/8081/2222/53530)
          │
          ▼
  Multi-Vector Detectors (16 Attack Families + Zero-Day Entropy/Volumetric Sensor)
          │
          ▼
  DetectorEvent / SecurityEvent (18 Standardized Numerical Features)
          │
          ▼
  EventBus & AttackCorrelator (30-Second Sliding Window Multi-Vector Correlation)
          │
          ▼
  Compute IP-Agnostic Behavioral Fingerprint: fp_<20_hex_chars>
          │
          ├──► [KNOWN PATTERN IN ATTACK MEMORY] ──► Static Memory Fast-Path (< 0.5 ms)
          │                                         (Skips Cloud LLM — Reuses Validated Rule)
          │
          └──► [NEW / UNFAMILIAR ATTACK]
                     │
                     ▼
               Hybrid AI Engine (17-Class Gaussian-Mahalanobis + Zero-Day Detector)
                     │
                     ▼
               CyberDefenseAgent (Google Gemini 2.5 Flash / Groq Llama-3.3-70B)
               Structured Tool Call: block_ip(ip, duration, reason)
          │
          ▼
  Deterministic PolicyValidator (Anti-Self-Lockout, Allowlist Check, TTL Bounds 1–3600s)
          │
          ▼
  FirewallManager & FirewallEnforcer
  ├── Primary : Kernel eBPF/XDP (`eBPF.c` -> `blocklist` BPF_HASH -> `XDP_DROP`)
  └── Fallback: Linux Kernel `nftables` (`inet cyber_commander`) / `iptables` (`CYBER_COMMANDER`)
          │
          ▼
  Post-Mitigation Verification + Auto-Expiry Timer + Shield Broadcast (UDP:9090)
```

### 2. Kernel eBPF/XDP Packet Processing Flow (`eBPF.c`)

```text
NIC Driver Frame Arrival (struct xdp_md *ctx)
          │
          ▼
  Parse Ethernet Header (struct ethhdr)
  └── Bounds Check Failed or Protocol != ETH_P_IP (IPv4)? ──► XDP_PASS
          │
          ▼
  Parse IPv4 Header (struct iphdr)
  └── Increment total_packets[0] (BPF_ARRAY Counter)
          │
          ▼
  Lookupiph->saddr in blocklist (BPF_HASH Map, Capacity: 16,384 IPs)
  ├── Not Found ──► XDP_PASS (Normal Kernel Stack Processing)
  └── Match Found ──► Atomic Increment drop_cnt + Return XDP_DROP (Wire-Speed Drop)
```

---

## 17-Class Threat Taxonomy & Enforcement Actions

The system classifies and enforces tailored mitigations across **16 known cyberattack categories**, **1 unsupervised Zero-Day category**, and **Benign traffic**:

| # | Category Code | Attack Type & Description | Primary Detection Vector | Default Mitigation Action | Default TTL |
| :- | :--- | :--- | :--- | :--- | :--- |
| 1 | `SYN_FLOOD_DDOS` | TCP SYN Half-Open Flood | Raw TCP Sniffer (`SYN/ACK >= 12x`, `>= 500 pps`) | `XDP_EARLY_SYN_DROP` | 1800s |
| 2 | `UDP_AMPLIFICATION_DDOS` | DNS/NTP Reflection & Volumetric UDP Flood | UDP Sensor (`>= 400 pps`, `>= 800 B/pkt`, `amp >= 6x`) | `XDP_VOLUMETRIC_UDP_DROP` | 1800s |
| 3 | `ICMP_PING_FLOOD` | ICMP Echo Flood, Smurf & Ping-of-Death | Raw `IPPROTO_ICMP` + `/proc/net/snmp` (`InEchos >= 25/s`) | `FIREWALL_ICMP_ECHO_DROP` | 1800s |
| 4 | `HTTP_L7_FLOOD` | High-RPS HTTP GET/POST Application Flood | HTTP Sensor (`>= 120 req/s`, `>= 350 pps`) | `FIREWALL_L7_RATE_AND_DROP` | 1800s |
| 5 | `SLOW_HTTP` | Slowloris / RUDY Socket Exhaustion | Socket Hold Monitor (`duration >= 30s`, `comp <= 0.20`) | `FIREWALL_CONN_LIMIT_AND_DROP` | 1800s |
| 6 | `SQL_INJECTION` | SQLi (`UNION SELECT`, `OR 1=1`, `sleep()`) | L7 Regex DPI (`l7_payload_sig_score >= 8.0`) | `WAF_AND_FIREWALL_SQLI_DROP` | 3600s |
| 7 | `XSS_AND_WEB_INJECTION` | XSS `<script>`, Log4Shell `${jndi:ldap}`, RCE | L7 Regex DPI (`l7_payload_sig_score >= 8.0`) | `WAF_AND_FIREWALL_RCE_DROP` | 3600s |
| 8 | `PATH_TRAVERSAL_LFI` | Directory Traversal (`../../../etc/passwd`, `.env`) | L7 Regex DPI (`l7_payload_sig_score >= 7.5`) | `WAF_AND_FIREWALL_LFI_DROP` | 3600s |
| 9 | `BRUTE_FORCE` | SSH / HTTP Auth Credential Stuffing | Auth Trap `TCP:22/2222/8081` (`>= 15 fails/min`) | `FIREWALL_AUTH_DROP` | 1800s |
| 10 | `PORT_SCAN` | TCP SYN / FIN / Stealth Multi-Port Sweep | Raw TCP Sniffer (`unique_dst_ports >= 10`) | `FIREWALL_SCAN_DROP` | 1800s |
| 11 | `DNS_TUNNELING` | Covert DNS Exfiltration & DNS Rebinding | DNS Sensor (`query_len >= 42`, `entropy >= 3.75`) | `FIREWALL_DNS_BLOCK` | 1800s |
| 12 | `ARP_MITM_SPOOFING` | Layer-2 ARP Cache Poisoning & MITM | `/proc/net/arp` Duplicate MAC-to-IP Conflict | `L2_ARP_STATIC_LOCK_AND_DROP` | 3600s |
| 13 | `SMB_RANSOMWARE_WORM` | Port 445/139 EternalBlue / WannaCry Probe | SMB Flow & Entropy Sensor (`dst_port` 445/139) | `FIREWALL_SMB_WORM_ISOLATION` | 3600s |
| 14 | `C2_BOTNET_BEACONING` | Periodic Malware Callback & DGA Traffic | C2 Port & Periodicity Sensor (`6667`, `4444`, `9001`) | `FIREWALL_C2_SINKHOLE_AND_DROP` | 3600s |
| 15 | `TLS_SSL_EXPLOIT` | TLS Handshake Flood & Renegotiation Abuse | TLS Flow Monitor (`dst_port` 443/8443, `comp <= 0.30`) | `FIREWALL_TLS_HANDSHAKE_DROP` | 1800s |
| 16 | `LAND_AND_IP_FRAGMENT_ATTACK` | Malformed `SYN+FIN`, Teardrop & LAND Packet | Raw Header Inspector (`malformed_header_score >= 8.0`) | `XDP_MALFORMED_HEADER_DROP` | 3600s |
| 17 | `ZERO_DAY_ANOMALY` | Unseen Polymorphic High-Entropy Volumetric Surge | Subspace Anomaly (`entropy >= 7.35`, `>= 600 pps`) | `XDP_AND_FIREWALL_DROP` | 600s |

---

## The 18-Feature Behavioral Fingerprint

Every network event is converted into an **18-feature numerical vector** (`event_schema.py`) to power both the Gaussian-Mahalanobis classifier and the IP-agnostic `compute_fingerprint()` hash:

| Index | Feature Name | Layer | Baseline (Benign) | Description & Role in Detection |
| :- | :--- | :--- | :--- | :--- |
| `0` | `packets_per_sec` | L3/L4 | `8.0` | Packet arrival velocity from the source flow |
| `1` | `bytes_per_pkt` | L3/L4 | `520.0` | Mean packet size in bytes (small in SYN floods; large in ICMP/UDP floods) |
| `2` | `conn_rate_per_sec` | L4 | `1.2` | New connection initiation rate per second |
| `3` | `concurrent_conns` | L4/L5 | `2.0` | Simultaneous open sockets held by the source |
| `4` | `avg_conn_duration_sec` | L4/L5 | `1.8` | Mean connection hold time (spikes in Slowloris; near zero in scans) |
| `5` | `request_completion_ratio` | L5/L7 | `0.98` | Ratio of completed requests to opened sockets (`< 0.10` in Slow HTTP) |
| `6` | `unique_dst_ports` | L4 | `1.0` | Distinct destination ports probed within the sliding window |
| `7` | `syn_to_ack_ratio` | L4 | `1.05` | Ratio of TCP SYN to ACK packets (`>= 12.0` in half-open SYN floods) |
| `8` | `auth_failures_per_min` | L7 | `0.0` | Failed authentication attempts per minute across SSH/HTTP |
| `9` | `unique_usernames_tried` | L7 | `0.0` | Distinct usernames attempted during login brute-forcing |
| `10` | `dns_query_len` | L7 | `15.0` | Character length of queried DNS domain names |
| `11` | `dns_shannon_entropy` | L7 | `2.3` | Shannon entropy (bits/char) of DNS subdomain labels |
| `12` | `dns_qps` | L7 | `0.4` | DNS queries per second from the source |
| `13` | `payload_byte_entropy` | L7 | `4.2` | Shannon entropy (`0.0–8.0` bits/byte) of raw payload bytes (`>= 7.35` in Zero-Day) |
| `14` | `icmp_pps` | L3 | `0.0` | Incoming ICMP Echo request velocity per second |
| `15` | `udp_amplification_ratio` | L4/L7 | `1.0` | Payload amplification multiplier in UDP reflection floods |
| `16` | `l7_payload_sig_score` | L7 | `0.0` | Deep Packet Inspection regex match score (`0.0–10.0`) for SQLi/XSS/LFI/RCE |
| `17` | `malformed_header_score` | L2/L3/L4 | `0.0` | Header anomaly score (`0.0–10.0`) for `SYN+FIN`, LAND, Teardrop, and ARP spoofing |

---

## Repository Structure

```text
Autonomous-AI-cyber-commander-advanced/
├── cyber_commander.py               # Main unified orchestrator & daemon entry point (v5.0)
├── ai_agent.py                      # Google Gemini 2.5 Flash + Groq Llama-3.3-70B function-calling agent
├── ai_engine.py                     # 18-Feature 17-Class Gaussian-Mahalanobis + Zero-Day AI Engine
├── event_schema.py                  # Standardized DetectorEvent & 18-feature behavioral fingerprint
├── attack_memory.py                 # Self-healing SQLite + JSON + Log O(1) Fast-Path Attack Memory
├── attack_correlator.py             # 30-second sliding-window multi-vector attack correlator
├── decision_engine.py               # Fast-path vs. AI reasoning coordinator
├── firewall_enforcer.py             # Host IP auto-discovery (SIOCGIFADDR ioctl), PolicyValidator & Enforcer
├── firewall_manager.py              # Kernel eBPF/XDP manager (BCC) + nftables/iptables fallback
├── firewall_tools.py                # Controlled tool interface exposed to the AI agent
├── eBPF.c                           # Kernel eBPF/XDP C source code (xdp_firewall & blocklist map)
├── live_network_sensor.py           # Raw ICMP/TCP sniffers + Socket DPI sensors (8080, 2222, 53530)
├── multi_vector_detector.py         # 12-vector L7 DPI & /proc/net/snmp + /proc/net/arp kernel monitor
├── http_detector.py                 # Slowloris & HTTP L7 flood detector
├── dns_detector.py                  # High-entropy DNS tunneling & covert query detector
├── port_scan_detector.py            # Horizontal/vertical port sweep detector
├── brute_force_detector.py          # SSH & HTTP authentication brute-force detector
├── terminal_dashboard.py            # Low-glare ANSI live terminal UI & plain-English attack narrator
├── target_effect_monitor.py         # Target host live CPU/latency impact & recovery monitor (UDP:9090 / HTTP:9080)
├── kali_attack_simulator.py         # 16-scenario sustained 20s offensive simulator (with Multi-IP Spoofing)
├── kali_native_commands.sh          # Native Kali CLI offensive test suite (ping, curl, nmap, sockets)
├── start_usb_guard.sh               # Plug-and-play USB launcher with dynamic host IP discovery
├── install_usb_autorun.sh           # One-time udev + systemd + desktop autostart installer for USB guard
├── Detectors & Prototype Modules/
│   ├── cyber_commander/             # Modular package mirror of core Cyber Commander components
│   ├── detectors/                   # Scapy & socket detectors (SYN, ICMP, ARP, DNS, Slow HTTP, Port 8081)
│   ├── Attacks/                     # 11 standalone prototype attack scripts (syn_flood_sim.py, etc.)
│   └── usb_autorun/                 # Linux udev rules, systemd service & desktop terminal launchers
├── data/
│   ├── attack_memory.db             # SQLite Fast-Path pattern & incident database (auto-created)
│   ├── attack_memory_snapshot.json  # JSON mirror of validated patterns & recent incidents
│   ├── attack_history.log           # Human-readable append-only incident audit log
│   └── active_firewall_rules.json   # Live active kernel firewall / XDP rule table
└── models/
    └── cyber_commander_model.json   # Trained 17-class Gaussian-Mahalanobis model & validation metrics
```

---

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/JP-05-CB/Autonomous-AI-cyber-commander-advanced.git
cd Autonomous-AI-cyber-commander-advanced
```

### 2. Install Dependencies

Install the Python packages:

```bash
pip3 install -r requirements.txt
```

*(Optional)* For hardware/driver-level eBPF/XDP attachment via BCC on Ubuntu/Debian/Kali:

```bash
sudo apt-get update
sudo apt-get install -y bpfcc-tools python3-bpfcc linux-headers-$(uname -r) nftables iptables
```

> **Note:** If BCC or root privileges are unavailable, Cyber Commander automatically falls back to Linux `nftables`/`iptables` or safe Kernel-State Simulation Mode so execution never fails.

### 3. Configure AI API Keys (Google Gemini / Groq)

Cyber Commander supports **Google Gemini** (`gemini-2.5-flash` / `gemini-2.0-flash`) and **Groq** (`llama-3.3-70b-versatile`), and automatically discovers keys from environment variables, `.env`, or `gemini_api_key.txt` (even when run under `sudo`):

```bash
export GEMINI_API_KEY="your_gemini_api_key_here"
export GROQ_API_KEY="your_groq_api_key_here"   # Optional secondary cloud LLM fallback
```

Or save your key directly into `.env` in the project root:

```ini
GEMINI_API_KEY=your_gemini_api_key_here
GROQ_API_KEY=your_groq_api_key_here
```

If the protected machine is on an isolated offline LAN without internet access, the system seamlessly falls back to the built-in **17-Class Gaussian-Mahalanobis & Zero-Day Hybrid AI Engine**.

---

## Running Autonomous AI Cyber Commander

### Mode 1: Standard Live Protection Daemon

```bash
sudo python3 cyber_commander.py --daemon
```

The system automatically discovers your active network interface (`wlp*`, `enp*`, `eth*`) and real host IPv4 address via kernel `SIOCGIFADDR` (`0x8915`) `ioctl`, attaches the firewall, spawns all background detector threads, and displays the live protection console.

### Mode 2: Plug-and-Play Live USB Guard

Run directly from a mounted USB drive:

```bash
sudo bash start_usb_guard.sh
```

To configure a Linux host so that inserting the USB pendrive automatically pops open the Cyber Commander terminal window:

```bash
sudo bash install_usb_autorun.sh
```

### Command-Line Options (`cyber_commander.py`)

| Flag | Description |
| :--- | :--- |
| `--daemon` | Run continuous live terminal protection (default behavior) |
| `--fresh-history` | Wipe existing attack memory and start with a clean Attack History |
| `--live-demo` | Execute automated multi-attack validation suite, then transition to live daemon |
| `--host-ip <IP>` | Explicitly override the protected host IPv4 address |
| `--interface <IFACE>` | Explicitly override the protected network interface (e.g., `enp0s8`, `wlan0`) |
| `--duration <SEC>` | Run daemon for a fixed number of seconds and exit cleanly |
| `--status` | Print current host identity, active firewall rules, and AI metrics as JSON |

---

## Live Lab Demonstration (2-Machine or Single-Machine Testbed)

You can evaluate the complete **Detect–Decide–Enforce–Recover** lifecycle using the included **Target System Effect Monitor** and **20-Second Sustained Kali Attack Simulator**.

```text
+-----------------------------------+          +----------------------------------------+
|       Kali Linux (Attacker)       |          |        Ubuntu Host (Defender)          |
|                                   |  Waves   |                                        |
|  kali_attack_simulator.py (v5.2)  | =======► | 1. target_effect_monitor.py (UDP:9090) |
|  16 Scenarios + Multi-IP Spoofing |          | 2. cyber_commander.py (eBPF/XDP + AI)  |
+-----------------------------------+          +----------------------------------------+
```

### Step 1: Start the Target System Effect Monitor (on Defender Host)

Open Terminal 1 on the target machine before starting Cyber Commander:

```bash
python3 target_effect_monitor.py
```

*Optional Web Dashboard:* Open `http://127.0.0.1:9080` in your browser for a live 1-second auto-refreshing telemetry dashboard.

### Step 2: Launch Sustained Attack Waves (from Kali Linux or Terminal 2)

Run the 20-second sustained simulator against the defender's IP address:

```bash
# Run interactive menu with all 16 scenarios:
python3 kali_attack_simulator.py --target <DEFENDER_IP> --interactive

# Run all 6 Multi-IP Source Spoofing & Distributed Botnet Swarm scenarios:
python3 kali_attack_simulator.py --target <DEFENDER_IP> --attack new

# Run a specific scenario (e.g., synflood, sqli, icmp, dns, slowloris, zeroday, ipspoof):
python3 kali_attack_simulator.py --target <DEFENDER_IP> --attack ipspoof

# Force rotating spoofed source IPs on any attack scenario:
python3 kali_attack_simulator.py --target <DEFENDER_IP> --attack sqli --spoof-ips
```

While **unprotected**, `target_effect_monitor.py` displays severe service degradation (`CPU: 84%–98%`, `Socket Pool: 49/50 busy`, `Latency: 1,850–3,920 ms`).

### Step 3: Engage Cyber Commander (Insert USB or Start Daemon)

Open Terminal 3 on the defender host (or insert the Cyber Commander USB pendrive):

```bash
sudo bash start_usb_guard.sh
```

Within milliseconds:
1. **Wave #1** is classified by the AI Engine / Gemini Agent and blocked in the eBPF/XDP & kernel firewall.
2. **Waves #2–#20** (even from rotating spoofed IPs `10.10.99.101..120`) match the **18-feature behavioral fingerprint** in `AttackMemoryDB` and are dropped in **< 0.5 ms** via `STATIC_MEMORY_FASTPATH`.
3. `target_effect_monitor.py` receives the live shield broadcast on `UDP:9090` and immediately recovers to **HEALTHY (`CPU: 6%`, `Latency: 3 ms`)**.

---

## Self-Healing Attack History Management

All learned attack fingerprints and incident logs are stored in:
- `data/attack_memory.db` (SQLite Fast-Path store)
- `data/attack_memory_snapshot.json` (JSON inspection mirror)
- `data/attack_history.log` (Human-readable chronological audit log)
- `attack_history.json` (Prototype-compatible history store)

**Dynamic Reset Feature:** You can delete `data/attack_history.log` or `data/attack_memory.db` at any time—even while the daemon is actively running—using your file manager or `rm -f data/attack_history.log`. Cyber Commander detects the file removal on the next event cycle, flushes stale memory caches, and automatically initializes a fresh history file.

---

## Ethical Use & Safety Notice

This framework is developed strictly for **academic research, authorized laboratory testing, and defensive cybersecurity education**. Only execute the included attack simulators (`kali_attack_simulator.py`, `kali_native_commands.sh`, and `Attacks/*`) against virtual machines, isolated lab networks, or hosts that you own or have explicit permission to test.

---

## Authors & Academic Attribution

- **Team Members**:
  - **Jayaprasath SV** (Reg. No: `2023105034`)
  - **Kalaiselvan** (Reg. No: `2023105303`)
- **Supervisor & Head of Department**: **Dr. M A Bhagyaveni**
- **Department**: B.E. Electronics and Communication Engineering (Cybersecurity Minor)
- **Institution**: College of Engineering Guindy (CEG), Anna University, Chennai
