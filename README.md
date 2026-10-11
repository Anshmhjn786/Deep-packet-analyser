 <div align="center">

<img src="https://img.shields.io/badge/DEEP%20PACKET%20ANALYZER-NETWORK%20INTELLIGENCE-00D9FF?style=for-the-badge&labelColor=07111F" alt="Deep Packet Analyzer Network Intelligence"/>

<br/>

# ⌬ DEEP PACKET ANALYZER

### `PACKET IN. INSIGHT OUT.`

**Offline Network Traffic Analysis · Deep Packet Inspection · Rule-Based Filtering**

<br/>

<img src="https://img.shields.io/badge/LANGUAGE-Python%203.10%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+"/>
<img src="https://img.shields.io/badge/INPUT-Classic%20PCAP-00B8A9?style=flat-square" alt="Classic PCAP"/>
<img src="https://img.shields.io/badge/MODE-Offline%20Analysis-7C83FD?style=flat-square" alt="Offline Analysis"/>

<br/><br/>

```text
   CAPTURE  ──►  DECODE  ──►  CLASSIFY  ──►  FILTER
      │             │            │             │
    PCAP         Protocols      Flows        Rules
```

</div>

---

## About the Project

Deep Packet Analyzer is a modular Python application for inspecting Ethernet packet captures, parsing network protocols, tracking directional flows, extracting available application-layer metadata, and filtering traffic using configurable rules.

It processes existing PCAP files without opening live capture interfaces or transmitting packets.


**Inspect. Decode. Analyze.**

A Python-based engine for offline packet inspection, network flow tracking, protocol metadata extraction, and rule-based traffic filtering.

---

`PYTHON` · `PCAP` · `DEEP PACKET INSPECTION` · `NETWORK SECURITY`

</div>
# Deep Packet Analyzer

**Offline PCAP Analysis, Deep Packet Inspection, and Rule-Based Network Traffic Filtering**

Deep Packet Analyzer is a Python application for inspecting Ethernet packet captures, parsing network protocols, tracking directional flows, extracting available application-layer metadata, and applying configurable traffic-filtering rules.

The project implements a modular packet-processing pipeline using Python's standard library. It focuses on structured packet parsing, bounded processing queues, flow tracking, and preservation of captured packet bytes.

## 1. Problem Statement

Network packet captures contain information at multiple protocol layers. Manually inspecting individual packets makes it difficult to understand traffic patterns, identify application protocols, track connections, and apply consistent filtering rules.

Deep Packet Analyzer addresses this by providing a reusable offline analysis pipeline that reads PCAP files, parses packet headers, extracts selected protocol metadata, evaluates filtering rules, and reports processing statistics.

## 2. System Architecture

The analyzer is organized into the following processing stages:

```text
             Input PCAP File
                    |
                    v
               PCAP Reader
                    |
                    v
              Packet Parser
                    |
                    v
          Protocol Metadata Extraction
                    |
                    v
             Flow Classification
                    |
                    v
              Rule Evaluation
                    |
             +------+------+
             |             |
             v             v
        Permitted        Blocked
          Packets        Packets
             |
             v
       Output PCAP File

       Processing Statistics
```

The diagram represents the logical workflow. Exact execution order and filtering behavior depend on the selected CLI mode and implementation.

### Core components

| Module | Responsibility |
|---|---|
| `pcap_reader.py` | Reads and writes classic PCAP records, including timestamps and captured packet bytes |
| `packet_parser.py` | Parses Ethernet, VLAN, IPv4, IPv6, TCP, and UDP headers with bounds checks |
| `sni_extractor.py` | Extracts available TLS SNI, HTTP Host, and DNS question-name metadata |
| `connection_tracker.py` | Tracks directional flows, counters, TCP state observations, and stale-flow cleanup |
| `rule_manager.py` | Manages filtering rules for IP addresses, applications, domains, and destination ports |
| `fast_path.py` | Performs flow classification and rule evaluation |
| `load_balancer.py` | Routes flows using stable five-tuple affinity |
| `thread_safe_queue.py` | Provides bounded queue operations for concurrent processing |
| `dpi_mt.py` | Coordinates multithreaded packet processing |
| `dpi_engine.py` | Integrates analysis, filtering, and reporting functionality |
| `main.py` | Provides the command-line entry point |

## 3. Technical Features

### Packet parsing

The packet parser supports Ethernet II frames, common VLAN tags, IPv4, IPv6 with common extension headers, TCP, and UDP. Bounds checks help prevent malformed or truncated packets from being read beyond available data.

The PCAP reader supports classic PCAP files with microsecond or nanosecond timestamps and both byte orders.

### Protocol metadata extraction

The analyzer can extract selected metadata from:

- **TLS:** Server Name Indication (SNI) from visible ClientHello messages.
- **HTTP:** Host headers from available HTTP request data.
- **DNS:** Question names from DNS messages.

Metadata extraction is limited by the available packet data. Encryption, fragmentation, and incomplete captures can prevent hostname identification.

### Flow tracking

Flows are tracked using directional five-tuples:

`Source IP + Source Port + Destination IP + Destination Port + Protocol`

The connection tracker maintains packet and byte counters, observes TCP state transitions, cleans up stale entries, and supports bounded flow-table capacity.

Reverse-direction packets are treated as separate flows in accordance with the existing implementation.

### Rule-based filtering

The analyzer supports rules based on:

- Source IP address
- Application classification
- Exact or wildcard domain
- Domain substring
- Destination port

Rules can be configured through the command-line interface or the Python API. A matched flow can remain blocked for subsequent packets, depending on the configured processing path.

### Concurrent processing

The multithreaded implementation uses bounded queues and configurable worker processing. Flow affinity helps route packets consistently, and the pipeline supports ordered output writing.

Python threads preserve the processing architecture, but the Global Interpreter Lock can limit CPU-bound parsing performance. Native C++ implementations may offer higher throughput under comparable conditions.

## 4. Installation

### Requirements

- Python 3.10 or newer
- Pytest for running the test suite
- Git for cloning the repository

The runtime implementation uses Python's standard library.

Clone the repository:

```bash
git clone https://github.com/Anshmhjn786/Deep-Packet-Analyser.git
cd Deep-Packet-Analyser
```

Create a virtual environment on Windows:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Install the project and its test dependencies:

```powershell
python -m pip install -e ".[test]"
```

## 5. Usage

### Inspect a capture

Inspect up to ten packets from a sample PCAP:

```powershell
deep-packet-analyzer .\samples\test_dpi.pcap --max-packets 10
```

### Filter traffic

Create a filtered output capture using application, source-IP, domain, and destination-port rules:

```powershell
deep-packet-analyzer .\samples\test_dpi.pcap .\samples\filtered_output.pcap --block-app YouTube --block-ip 192.168.1.50 --block-domain "*.example.com" --block-port 8443
```

Check the available command-line options:

```powershell
deep-packet-analyzer --help
```

### Use the Python API

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

The example assumes the package has been installed and the API matches the current source.

## 6. Testing and Validation

Run the automated tests from the repository root:

```powershell
python -m pytest -v
```

The test suite covers packet parsing, malformed frames, PCAP byte order and truncation, flow tracking, filtering rules, queue behavior, metadata extraction, and end-to-end filtering.

Testing is important because malformed packet captures can contain incomplete headers, invalid lengths, and truncated records.

## 7. Design Decisions

**Offline-first processing:** The analyzer works on existing capture files instead of opening live capture interfaces or transmitting packets.

**Custom parsing:** A standard-library implementation provides direct control over packet boundaries, raw-frame handling, and protocol support.

**Modular architecture:** Parsing, metadata extraction, flow tracking, rules, concurrency, and orchestration are separated into individual modules.

**Bounded processing:** Bounded queues and flow-table capacity help limit resource use during analysis.

**Explicit limitations:** The implementation distinguishes supported protocol parsing from features that require stream reconstruction or cryptographic processing.

## 8. Limitations

The current implementation does not provide:

- Live packet capture or packet replay
- TCP stream reassembly
- Fragmented TLS ClientHello reconstruction
- QUIC decryption or complete QUIC CRYPTO-frame reassembly
- PCAP-NG parsing
- Generic decoding of every network protocol
- Machine-learning-based anomaly detection

IPv6 jumbograms and non-Ethernet link types are also outside the documented support scope. Application classification depends on implemented hostname signatures and should not be treated as definitive identification of all traffic.

## 9. Future Development

Potential extensions include:

- Machine-learning-based network anomaly detection
- Supervised network traffic classification
- Traffic statistics dashboards
- Exportable analysis reports
- Benchmarking against representative datasets
- Additional protocol decoders and stream reconstruction

These are
