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
: