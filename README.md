 <div align="center">

# ⬡ DEEP PACKET ANALYZER

### `PACKET IN. INSIGHT OUT.`

**Offline Network Traffic Analysis · Deep Packet Inspection · Rule-Based Filtering**

`PYTHON 3.10+` · `CLASSIC PCAP` · `NETWORK SECURITY`

```text
┌─────────────────────────────────────────────────────────┐
│                 NETWORK ANALYSIS ENGINE                 │
├─────────────────────────────────────────────────────────┤
│                                                         │
│   PCAP INPUT ──► PACKET PARSER ──► METADATA EXTRACTION  │
│                                         │               │
│                                         ▼               │
│                                    FLOW TRACKER         │
│                                         │               │
│                                         ▼               │
│                                   RULE ENGINE           │
│                                    /        \           │
│                                   ▼          ▼          │
│                              PERMIT FLOW  BLOCK FLOW    │
│                                   │                     │
│                                   ▼                     │
│                              OUTPUT PCAP                │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

</div>

---

## 01. Overview

Deep Packet Analyzer is a modular Python application designed to inspect offline Ethernet packet captures, parse network protocols, track directional network flows, extract available application-layer metadata, and filter traffic using configurable rules.

The project implements a packet-processing pipeline with a custom PCAP reader, protocol parser, metadata extractor, flow tracker, rule manager, and optional multithreaded processing.

It is intended for network diagnostics, protocol analysis, cybersecurity learning, and experimentation with network traffic processing.

**Operating mode:** Passive offline analysis. The application processes existing capture files without opening live capture interfaces or transmitting packets.

## 02. Key Capabilities

| Capability | Implementation |
|---|---|
| PCAP processing | Classic PCAP reading and writing |
| Packet parsing | Ethernet II, VLAN, IPv4, IPv6, TCP and UDP |
| Metadata extraction | TLS SNI, HTTP Host and DNS question names when visible |
| Flow tracking | Directional five-tuples, packet counters and byte counters |
| Application classification | Hostname-based application signatures |
| Traffic filtering | IP, application, domain, substring and destination-port rules |
| Concurrent processing | Configurable workers and bounded queues |
| Reporting | Packet inspection and filtering statistics |
| Testing | Automated tests for parsing, PCAP handling and filtering |

## 03. System Architecture

The application separates packet processing into modules to make individual components easier to maintain, test, and extend.

```text
              ┌───────────────────┐
              │   Input PCAP      │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │    PCAP Reader    │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │   Packet Parser   │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │ Metadata Extractor│
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │   Flow Tracking   │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │   Rule Manager    │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │ Filtering / Output│
              └───────────────────┘
```

This is a logical overview. The exact execution sequence can differ between inspection and filtering modes.

### Core modules

| Module | Responsibility |
|---|---|
| `pcap_reader.py` | Reads and writes classic PCAP records, including timestamps and packet bytes |
| `packet_parser.py` | Parses Ethernet, VLAN, IPv4, IPv6, TCP and UDP headers |
| `sni_extractor.py` | Extracts available TLS SNI, HTTP Host and DNS question-name metadata |
| `connection_tracker.py` | Tracks flows, counters, TCP state observations and stale entries |
| `rule_manager.py` | Manages configurable traffic-filtering rules |
| `fast_path.py` | Performs flow classification, rule evaluation and filtering decisions |
| `load_balancer.py` | Routes flows using stable five-tuple affinity |
| `thread_safe_queue.py` | Provides bounded queue operations for concurrent processing |
| `dpi_mt.py` | Supports multithreaded packet processing |
| `dpi_engine.py` | Coordinates analysis, filtering and reporting |
| `main.py` | Provides the command-line interface |

## 04. Technology Stack

- **Language:** Python 3.10+
- **Packet format:** Classic PCAP
- **Runtime dependencies:** Python standard library
- **Testing:** Pytest
- **Version control:** Git and GitHub

The Python implementation does not require a C++ compiler or CMake configuration.

## 05. Installation

### Prerequisites

- Python 3.10 or newer
- Git
- Windows, Linux or macOS

### Clone the repository

```bash
git clone https://github.com/Anshmhjn786/Deep-Packet-Analyser.git
cd Deep-Packet-Analyser
```

### Create a virtual environment

For Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

For Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install the project

```bash
python -m pip install -e ".[test]"
```

This installs the package in editable mode with its optional test dependencies, as configured in `pyproject.toml`.

## 06. Command-Line Usage

### Display available options

```powershell
deep-packet-analyzer --help
```

Alternatively, run directly from the source tree:

```powershell
$env:PYTHONPATH = "src"
python -m deep_packet_analyzer --help
```

### Inspect a packet capture

Inspect up to ten packets from a sample capture:

```powershell
deep-packet-analyzer .\samples\test_dpi.pcap --max-packets 10
```

Inspection mode reports available packet and flow information without intentionally printing payload contents.

### Filter network traffic

Write permitted packets to a new PCAP file:

```powershell
deep-packet-analyzer .\samples\test_dpi.pcap .\samples\filtered_output.pcap --block-app YouTube --block-ip 192.168.1.50 --block-domain "*.example.com" --block-port 8443
```

This example demonstrates the intended CLI options. Exact behavior depends on the implemented filtering path and the metadata available in the capture.

### Generate a test capture

```powershell
python .\scripts\generate_test_pcap.py .\samples\test_dpi.pcap
```

Review the generator before running it if you want to preserve an existing sample file.

## 07. Rule Configuration

The analyzer supports filtering by source IP, application, domain, domain substring, and destination port.

Example rule file:

```text
[BLOCKED_IPS]
192.168.1.50

[BLOCKED_APPS]
YouTube

[BLOCKED_DOMAINS]
*.example.com

[BLOCKED_DOMAIN_SUBSTRINGS]
facebook

[BLOCKED_PORTS]
8443
```

Rules can also be configured through the Python API.

```python
from deep_packet_analyzer import DPIEngine, DPIEngineConfig

engine = DPIEngine(
    DPIEngineConfig(rules_file="blocking_rules.txt")
)

engine.block_app("YouTube")

report = engine.process_file(
    "input.pcap",
    "filtered.pcap"
)

print(report["packets"])
```

The example assumes the installed package exposes these APIs and the report contains the referenced key.

## 08. Protocol Support

| Protocol or format | Supported behavior |
|---|---|
| Classic PCAP | Microsecond and nanosecond timestamps, both byte orders |
| Ethernet II | Ethernet frame parsing |
| VLAN | Common 802.1Q and 802.1ad tags |
| IPv4 | Header parsing and address extraction |
| IPv6 | Parsing with common extension headers |
| TCP | Header parsing, flow tracking and state observations |
| UDP | Header parsing and flow tracking |
| TLS | SNI extraction from visible ClientHello messages |
| HTTP | Host header extraction |
| DNS | Question-name extraction |

Application classification relies on implemented hostname signatures. It should not be treated as definitive identification of every application or encrypted connection.

## 09. Testing and Validation

Run the automated test suite from the project root:

```powershell
python -m pytest -v
```

The test suite covers packet parsing, malformed frames, PCAP byte order and truncation, flow tracking, filtering rules, queue behavior, metadata extraction, and end-to-end filtering.

Tests should be run against the current implementation before relying on particular features or performance claims.

## 10. Design Considerations

**Custom packet parsing:** The parser provides direct control over header validation and packet-byte handling.

**Modular implementation:** Parsing, metadata extraction, flow tracking, rules and processing orchestration are separated into dedicated modules.

**Bounded resource usage:** Bounded queues and flow-table capacity help constrain resource consumption during processing.

**Offline processing:** The tool analyzes existing capture files rather than performing live packet capture or network transmission.

**Concurrent execution:** The multithreaded implementation supports bounded worker queues and ordered output. CPU-bound Python code can remain limited by the CPython Global Interpreter Lock.

## 11. Limitations

The current documented implementation does not include:

- Live packet capture or packet replay
- TCP stream reassembly
- Reconstruction of fragmented TLS ClientHello messages
- QUIC decryption or complete QUIC CRYPTO-frame reassembly
- PCAP-NG parsing
- IPv6 jumbogram support
- Generic decoding of every network protocol
- Machine-learning-based anomaly detection

Encrypted ClientHello, incomplete captures and fragmented protocol messages can prevent metadata extraction. Non-IP and non-TCP/UDP packets are not copied to the DPI output in the documented filtering path.

## 12. Future Development

Potential extensions include:

- Machine-learning-based network anomaly detection
- Supervised network traffic classification
- Interactive traffic statistics dashboard
- Exportable analysis reports
- Performance benchmarking on representative PCAP datasets
- Additional protocol decoders and stream reconstruction

These are proposed enhancements, not claims of implemented functionality.

## 13. Security and Privacy

Use only packet captures that you own or are authorized to inspect. Capture files may contain sensitive addresses, hostnames, application metadata or payload data.

- Review sample captures before publishing them.
- Do not commit credentials, private datasets or sensitive packet captures.
- Keep payload inspection separate from unnecessary payload logging.
- Use the analyzer only for authorized network analysis.

## License

See the [LICENSE](LICENSE) file for licensing terms.

<div align="center">

**Deep Packet Analyzer**

*Built for network analysis, protocol inspection and cybersecurity research.*

</div>
