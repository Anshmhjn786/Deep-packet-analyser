 <div align="center">

# 🛡️ Deep Packet Analyzer

### Offline Network Traffic Analysis & Deep Packet Inspection

**A Python-powered tool for packet analysis, network flow tracking, protocol identification, and rule-based traffic filtering.**

<p>
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+"/>
  <img src="https://img.shields.io/badge/Network-PCAP_Analysis-00A67D?style=for-the-badge" alt="PCAP Analysis"/>
  <img src="https://img.shields.io/badge/Testing-Pytest-0A9EDC?style=for-the-badge&logo=pytest&logoColor=white" alt="Pytest"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="MIT License"/>
</p>

<p>
  <a href="https://github.com/Anshmhjn786/Deep-Packet-Analyser">
    <strong>Repository</strong>
  </a>
  •
  <a href="https://github.com/Anshmhjn786/Deep-Packet-Analyser/issues">
    <strong>Report an Issue</strong>
  </a>
</p>

</div>

---

## 🔍 Project Overview

Deep Packet Analyzer is a modular Python application designed to inspect offline Ethernet packet captures, analyze network protocols, track connections, extract available hostname metadata, and filter traffic using configurable rules.

It provides a foundation for network diagnostics, protocol analysis, and cybersecurity research, with scope for future machine-learning-based traffic classification and anomaly detection.

> **Operating mode:** Passive offline analysis. The application processes existing PCAP files rather than capturing live network traffic.

## ⚡ Key Features

| Feature | Description |
|---|---|
| 📦 PCAP Processing | Read and write classic PCAP files |
| 🌐 Packet Parsing | Ethernet, VLAN, IPv4, IPv6, TCP and UDP |
| 🔎 Deep Packet Inspection | Extract visible TLS SNI, HTTP Host and DNS question names |
| 🔗 Flow Tracking | Track directional flows, packet counts and byte counts |
| 🚦 Rule-Based Filtering | Filter by source IP, application, domain and destination port |
| ⚙️ Multithreading | Bounded queues and configurable packet-processing workers |
| 📊 Statistics | Inspect packet processing and filtering results |
| 🧪 Automated Testing | Validate packet parsing, PCAP handling and filtering behavior |

## 🧰 Technology Stack

<p>
  <img src="https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/Pytest-0A9EDC?style=flat-square&logo=pytest&logoColor=white" alt="Pytest"/>
  <img src="https://img.shields.io/badge/Git-F05032?style=flat-square&logo=git&logoColor=white" alt="Git"/>
  <img src="https://img.shields.io/badge/GitHub-181717?style=flat-square&logo=github&logoColor=white" alt="GitHub"/>
</p>

- **Language:** Python 3.10+
- **Packet format:** Classic PCAP
- **Architecture:** Modular Python package
- **Testing:** Pytest
- **Runtime dependencies:** Python standard library

## 🚀 Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/Anshmhjn786/Deep-Packet-Analyser.git
cd Deep-Packet-Analyser
```

### 2. Create a virtual environment

**Windows PowerShell**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install the project

```powershell
python -m pip install -e ".[test]"
```

### 4. Inspect a packet capture

```powershell
deep-packet-analyzer .\samples\test_dpi.pcap --max-packets 10
```

To see all available commands and options:

```powershell
deep-packet-analyzer --help
```

## 🧪 Run Tests

```powershell
python -m pytest -v
```

## 🔐 Security & Privacy

- Designed for authorized offline packet analysis.
- Does not capture live network traffic or transmit packets.
- Packet payloads are inspected in memory and are not intended to be printed or logged.
- PCAP files can contain sensitive information. Review captures before sharing them publicly.

## 🛣️ Future Roadmap

- [ ] Machine-learning-based network anomaly detection
- [ ] Network traffic classification using trained models
- [ ] Interactive traffic analysis dashboard
- [ ] Exportable analysis reports
- [ ] Performance benchmarking on representative datasets

*Roadmap items are planned enhancements, not claims of existing functionality.*

## ⚠️ Limitations

- No live packet capture or packet replay.
- No TCP stream reassembly.
- No QUIC decryption or full QUIC CRYPTO-frame reassembly.
- Limited visibility into encrypted or fragmented protocol metadata.
- Python threading may not accelerate CPU-bound packet parsing.

## 📄 License

Distributed under the [MIT License](LICENSE).

<div align="center">

**Built for learning, network analysis, and cybersecurity research.**

</div>
