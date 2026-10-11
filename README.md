# Deep Packet Analyzer (Python migration)

Offline Ethernet PCAP inspection and filtering, fully migrated to Python. The
package lives in `src/deep_packet_analyzer/`; sample captures are in `samples/`
and the test-capture generator is in `scripts/`.

This is a passive, offline analyzer. It does not open sockets, capture live
traffic, or modify transmitted packets. Treat input captures as sensitive:
payloads are inspected in memory but are not printed or logged.

## Migration map

The former repository had two different command paths. Its CMake target built
`main.cpp` with an IPv4-only parser; separate single- and multithreaded DPI
programs implemented inspection/filtering, while an additional componentized
engine exposed tracker, rule, and fast-path classes. The table records how all
of those C++ files map into this consolidated Python CLI and package.

| C++ source/header | Python module | Migrated behavior / audit notes |
|---|---|---|
| `include/types.h`, `src/types.cpp` | [`types.py`](src/deep_packet_analyzer/types.py) | Five-tuple, app/state/action enums, labels, and legacy hostname signatures. |
| `include/pcap_reader.h`, `src/pcap_reader.cpp` | [`pcap_reader.py`](src/deep_packet_analyzer/pcap_reader.py) | Streaming classic PCAP reader/writer, preserving packet timestamps and captured/original lengths. Supports both byte orders and micro/nanosecond PCAP magic values. |
| `include/packet_parser.h`, `src/packet_parser.cpp` | [`packet_parser.py`](src/deep_packet_analyzer/packet_parser.py) | Bounded Ethernet, VLAN, IPv4, IPv6, TCP, and UDP parsing. IPv6 support is added because the old header advertises IPv6 but the C++ parser never decoded it. |
| `include/sni_extractor.h`, `src/sni_extractor.cpp` | [`sni_extractor.py`](src/deep_packet_analyzer/sni_extractor.py) | TLS ClientHello SNI, HTTP Host, DNS question extraction. `extractExtensions` was an empty stub in C++; the Python version validates and returns extension values. |
| `include/rule_manager.h`, `src/rule_manager.cpp` | [`rule_manager.py`](src/deep_packet_analyzer/rule_manager.py) | Source-IP, application, exact/wildcard domain, and destination-port rules; the multithreaded CLI's substring-domain behavior is also preserved. Persistence keeps the C++ INI-like section names and adds a section for substring rules. |
| `include/connection_tracker.h`, `src/connection_tracker.cpp` | [`connection_tracker.py`](src/deep_packet_analyzer/connection_tracker.py) | Per-worker directional flows, counters, TCP states, stale cleanup, capacity eviction, aggregate reporting. |
| `include/fast_path.h`, `src/fast_path.cpp` | [`fast_path.py`](src/deep_packet_analyzer/fast_path.py) | Flow classification, rule evaluation, drop/forward decisions, and per-worker counters. |
| `include/load_balancer.h`, `src/load_balancer.cpp` | [`load_balancer.py`](src/deep_packet_analyzer/load_balancer.py) | Stable five-tuple-affinity routing. |
| `include/thread_safe_queue.h`, `src/dpi_mt.cpp` | [`thread_safe_queue.py`](src/deep_packet_analyzer/thread_safe_queue.py), [`dpi_mt.py`](src/deep_packet_analyzer/dpi_mt.py) | Bounded blocking queues, concurrent processing, and ordered output writing. |
| `include/dpi_engine.h`, `src/dpi_engine.cpp`, `src/main_dpi.cpp` | [`dpi_engine.py`](src/deep_packet_analyzer/dpi_engine.py), [`main.py`](src/deep_packet_analyzer/main.py) | Engine orchestration, rules, PCAP filtering, statistics, and CLI. The old engine's sleep-based queue draining is replaced by queue completion sentinels and joins. |
| `src/main.cpp`, `src/main_simple.cpp`, `src/main_working.cpp` | `main.py` | Packet inspection and the earlier single-threaded analysis workflow. |
| `src/fast_path.cpp`, `src/dpi_mt.cpp` QUIC path | `sni_extractor.py` | QUIC Initial detection is available, but QUIC SNI extraction is not claimed: the legacy implementation only scanned encrypted packet bytes heuristically and did not decrypt/reassemble QUIC CRYPTO frames. |
| `include/platform.h` | Python `struct` and `ipaddress` | Network byte order and address decoding are handled with standard-library primitives. |

### Behavior and implementation differences

- The C++ packet parser only decoded IPv4 and assumed a 14-byte Ethernet header.
  The migrated parser additionally handles IPv6, common IPv6 extension headers,
  and VLAN tags, while retaining bounds checks for malformed/truncated input.
- Packet and flow keys retain the legacy directional five-tuple semantics.
  Reverse-direction packets are therefore separate flows, as in the standalone
  DPI programs.
- Hostname-to-application lookup retains the original substring signatures and
  their ordering. A hostname not in that signature list maps to generic HTTPS,
  matching `sniToAppType`; HTTP Host extraction can therefore produce that
  legacy generic classification.
- The C++ thread workers use native threads. Python also uses bounded threads
  to preserve concurrent processing and flow affinity, but CPU-bound parsing is
  constrained by the CPython GIL; throughput is expected to be lower than
  optimized native C++ for large captures. The Python pipeline restores input
  order in the output PCAP.
- The declared QUIC, IPv6, and `extractExtensions` APIs were not fully
  functional in the original source. QUIC decryption/reassembly and IPv6
  jumbograms remain unsupported.

## Requirements and installation

Python 3.10 or newer is required. Runtime dependencies are limited to the
standard library; Scapy and dpkt are intentionally not used because the project
needs a small custom parser, exact raw-frame preservation, and no packet-writing
or live-capture functionality. Pytest is an optional test dependency.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
```

The source can also be run without installation:

```powershell
$env:PYTHONPATH = "src"
python -m deep_packet_analyzer --help
```

## Usage

Inspect packets without writing payload data to the terminal:

```powershell
deep-packet-analyzer .\test_dpi.pcap --max-packets 10
```

Filter an offline capture and write permitted TCP/UDP IP packets to a new PCAP:

```powershell
deep-packet-analyzer .\test_dpi.pcap .\filtered.pcap `
  --block-app YouTube --block-ip 192.168.1.50 `
  --block-domain "*.example.com" --block-port 8443
```

Load/save rule files through the Python API:

```python
from deep_packet_analyzer import DPIEngine, DPIEngineConfig

engine = DPIEngine(DPIEngineConfig(rules_file="blocking_rules.txt"))
engine.block_app("YouTube")
report = engine.process_file("input.pcap", "filtered.pcap")
print(report["packets"])
```

Rule files retain the C++ format:

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

The CLI accepts `--lbs` and `--fps` to configure the load-balancer/worker
topology and `--queue-size` to bound per-worker buffering. `--verbose` reports
malformed frames and progress without dumping payload bytes. Omitting the output
PCAP or specifying `--inspect` selects inspection mode.

Inspection also accepts the original positional packet limit, for example
`deep-packet-analyzer capture.pcap 10`.

## Supported behavior

- Classic PCAP files (microsecond and nanosecond timestamps; either byte order),
  with Ethernet link type for packet decoding.
- Ethernet II, 802.1Q/802.1ad VLAN tags, IPv4, IPv6 with common extension
  headers, TCP, UDP, and non-IP Ethernet identification.
- TCP/UDP five-tuple flow tracking, SYN/SYN-ACK/FIN/RST state observations,
  byte/packet counters, stale-flow cleanup, and bounded flow-table eviction.
- TLS ClientHello SNI, HTTP request Host, and DNS question-name extraction.
- Application classification for the source signatures: Google, Facebook,
  YouTube, Twitter/X, Instagram, Netflix, Amazon, Microsoft, Apple, WhatsApp,
  Telegram, TikTok, Spotify, Zoom, Discord, GitHub, Cloudflare, plus generic
  HTTP/HTTPS/DNS/unknown labels.
- Source-IP, application, exact-domain, `*.domain` wildcard, substring-domain
  CLI rules, and destination-port blocking. A matched flow remains blocked for
  subsequent packets.
- Multiple configurable worker threads with bounded queues and ordered PCAP
  output. The separate Python `ThreadSafeQueue` implementation also exposes the
  legacy blocking, nonblocking, timeout, and shutdown behaviors.
- Malformed packet frames are counted and skipped; malformed/truncated PCAP
  structures fail explicitly. Non-IP and non-TCP/UDP packets are not copied to
  the DPI output, matching the legacy DPI command path.

## Tests

```powershell
python -m pytest
```

The test suite covers valid/malformed Ethernet frames, IPv4/IPv6 with TCP/UDP,
PCAP byte order and truncation, empty captures, both retained sample captures,
flow state and eviction, rules, queue bounds/shutdown, TLS SNI/HTTP/DNS
inspection, QUIC Initial detection and safe plaintext-ClientHello scanning,
and end-to-end filtering using the `scripts/generate_test_pcap.py` generator
with both one and multiple workers. The checked-in test capture's expected
77-inspected/69-forwarded/8-dropped rule scenario is asserted in the suite.

The existing sample files [`test_dpi.pcap`](samples/test_dpi.pcap) and
[`output.pcap`](samples/output.pcap) are retained unchanged. To regenerate the
former:

```powershell
python .\scripts\generate_test_pcap.py .\samples\test_dpi.pcap
```

## Performance and limitations

The Python implementation favors correctness, input validation, bounded memory,
and an inspectable standard-library parser. No profiling data or C++/Python
throughput comparison is claimed unless both implementations are measured on
the same capture and machine. Pure Python threads preserve the existing worker
topology but are not expected to accelerate CPU-bound analysis under the GIL.
The current PCAP writer emits the original captured bytes; this analyzer does
not repair checksums or replay packets.

TCP stream reassembly, fragmented TLS ClientHello reconstruction, QUIC
decryption, IPv6 jumbograms, PCAP-NG, live capture, non-Ethernet link types,
and generic protocol decoding beyond the listed headers are not implemented.
SNI visibility can also be unavailable when the ClientHello is fragmented,
encrypted through ECH, or absent from the capture.

The Python package is the sole analyzer implementation; no C++ compiler or
CMake configuration is required.
