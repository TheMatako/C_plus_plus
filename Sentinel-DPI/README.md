# SentinelDPI

A lightweight Deep Packet Inspection (DPI) engine written in modern **C++20** with zero external dependencies. SentinelDPI streams `.pcap` captures, decodes network protocol layers from raw bytes, and evaluates packets against Snort-inspired detection rules.

## Features

- **Streaming PCAP reader:** Reads `.pcap` files packet-by-packet in constant memory (little/big endian, microsecond & nanosecond timestamps).
- **Multi-layer binary parser:** Decodes Ethernet, IPv4, TCP, UDP, and ICMP (via IPv4 protocol identification) while extracting raw application payloads.
- **Snort-inspired rule engine:** Short-circuit evaluation ordered from cheapest to most expensive check (`protocol` → `IPs` → `ports` → `TCP flags` → `payload content`).
- **Strict rule validation:** Custom DSL parser with line-accurate syntax error reporting.
- **Memory safe:** Compiled with strict warnings (`-Wall -Wextra -Wshadow -Wswitch`) and verified leak-free with Valgrind.

## Architecture

```text
.pcap file  ──▶ PcapReader ──▶ PacketParser ──▶ Packet
                                                     │
.rules file ──▶ RuleLoader ──▶ RuleEngine ◀────────┘
                                   │
                                   ▼
                        Console Alerts & Summary
```

```text
src/
├── core/        # Packet container, ProtocolType enum
├── protocols/   # ProtocolLayer base, Ethernet, IPv4, TCP, UDP
├── parser/      # PcapReader (streaming), PacketParser (binary decoding)
├── dpi/         # Rule, RuleLoader, RuleEngine, Alert
├── rules/       # Sample detection rules
├── files/       # Sample .pcap files
└── main.cpp     # CLI entry point & scan statistics
```

## Build & Usage

### Prerequisites
- C++20 compiler (`g++ >= 13` or `clang++ >= 16` with `<format>` support)
- CMake `>= 3.20`

### Compile
```bash
cmake -B build
cmake --build build
```

### Run
```bash
./build/sentinel <path_to_pcap> <path_to_rules>
```

## Rule Syntax

```text
alert <protocol> <src_ip> <src_port> -> <dst_ip> <dst_port> (<options>)
```

- **Protocols:** `tcp`, `udp`, `icmp`, `ip`, `any`
- **Endpoints:** IPv4 address / port number, or `any`
- **Options:**

| Option | Required | Description |
| :--- | :---: | :--- |
| `sid:<id>;` | Yes | Unique positive rule identifier |
| `msg:"<text>";` | Yes | Alert description |
| `severity:<level>;` | No | `low`, `medium` (default), `high`, or `critical` |
| `flags:<mask>;` | No | TCP flags bitmask (`F`, `S`, `R`, `P`, `A`, `U`) |
| `content:"<pattern>";` | No | Byte sequence to search in the raw payload |
| `nocase;` | No | Makes `content` matching case-insensitive |

### Example Rules
```text
alert tcp any any -> any 22 (msg:"SSH SYN Scan"; flags:S; severity:medium; sid:1000001;)
alert tcp 192.168.1.50 any -> 10.0.0.10 80 (msg:"SQL Injection Attempt"; content:"UNION SELECT"; nocase; flags:PA; severity:critical; sid:1000002;)
alert udp any any -> 8.8.8.8 53 (msg:"Suspicious DNS Query"; content:"evil.com"; severity:high; sid:1000003;)
alert icmp any any -> 10.0.0.10 any (msg:"ICMP Echo Request"; severity:low; sid:1000004;)
```

## Example Output

```text
Loaded 4 rule(s). Scanning 'src/files/test_capture.pcap'...

[ALERT MEDIUM] Matches rule number 1000001: SSH SYN Scan.
Time: 21/11/2026 09:45:45.000000 | Protocol used: TCP
Source IP: 192.168.1.50 | Source Port: 54321 | Destination IP: 10.0.0.10 | Destination Port: 22.

[ALERT CRITICAL] Matches rule number 1000002: SQL Injection Attempt.
Time: 21/11/2026 09:45:46.001000 | Protocol used: TCP
Source IP: 192.168.1.50 | Source Port: 54322 | Destination IP: 10.0.0.10 | Destination Port: 80.

[ALERT HIGH] Matches rule number 1000003: Suspicious DNS Query.
Time: 21/11/2026 09:45:48.003000 | Protocol used: UDP
Source IP: 192.168.1.99 | Source Port: 55555 | Destination IP: 8.8.8.8 | Destination Port: 53.

[ALERT LOW] Matches rule number 1000004: ICMP Echo Request.
Time: 21/11/2026 09:45:49.004000 | Protocol used: ICMP
Source IP: 192.168.1.50 | Source Port: 0 | Destination IP: 10.0.0.10 | Destination Port: 0.

--- Scan Summary ---
Inspected 6 packets.
Triggered 4 alerts with
1 CRITICAL | 1 HIGH | 1 MEDIUM | 1 LOW
```