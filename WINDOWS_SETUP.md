# Windows setup

The migrated analyzer runs on Python 3.10+ and uses only the standard library
at runtime. A C++ compiler is not required for Python use.

## Install and run

From PowerShell in the repository root:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
```

Inspect a capture:

```powershell
deep-packet-analyzer .\samples\test_dpi.pcap --max-packets 10
```

Filter it into a separate output file:

```powershell
deep-packet-analyzer .\samples\test_dpi.pcap .\filtered.pcap `
  --block-app YouTube --block-ip 192.168.1.50 `
  --block-domain "*.example.com"
```

Without installing, run from the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m deep_packet_analyzer .\samples\test_dpi.pcap .\filtered.pcap --block-app YouTube
```

Run tests with:

```powershell
python -m pytest
```

If script execution is disabled and venv activation is blocked, use the venv
interpreter directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\deep-packet-analyzer.exe .\samples\test_dpi.pcap .\filtered.pcap
```
