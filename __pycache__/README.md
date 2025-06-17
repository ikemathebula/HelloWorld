# Network Diagnostic Tool

A Streamlit app to monitor latency, packet loss, scan ports (incl. 10443), traceroute, DNS lookups, and even network-wide scans.

## Features
- Real-time ping monitor (with adjustable interval)
- DNS lookup
- Port scan (22, 80, 443, 8080, 10443)
- /24 network scan
- Traceroute visualization
- Error logs & dark theme

## Run locally
```bash
python -m venv .venv
. .venv/Scripts/activate         # Windows
# or source .venv/bin/activate  # Mac/Linux
pip install -r requirements.txt
python -m streamlit run app.py
