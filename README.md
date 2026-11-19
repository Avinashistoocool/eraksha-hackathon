# IoT flow prototypes

This repository contains separate Python prototypes for simulated network flows, anomaly detection, and a device dashboard. The scripts use SQLite files in the repository.

## Set up the simulator

Use a Python environment that supports the packages in `requirements.txt`. Run these commands from the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python simulator.py
```

`simulator.py` reads `devices.json` and writes generated device and flow records to `data/flows.db`. Stop the loop with Ctrl+C.

Start `anomaly_detector.py` in a separate terminal after the simulator writes at least 50 flows:

```powershell
.\.venv\Scripts\python anomaly_detector.py
```

The detector trains an IsolationForest model from the latest flows. It adds score and status columns to the `flows` table. It then checks new flows in a loop.

## Other scripts

| File | Purpose | SQLite file |
| --- | --- | --- |
| `test_flow_generator.py` | Creates simulated devices and flows with a different table layout. | `data/flows.db` |
| `sniffer.py` | Captures packets with Scapy and records device and flow data. | `dataflows.db` |
| `live_nmap_flow_generator.py` | Uses Nmap to find devices and generates flow records. | `dataflows.db` |
| `advanced_anomaly_detector.py` | Uses device data and local memory for its anomaly logic. | `dataflows.db` |
| `server.py` | Shows devices in a Flask dashboard on port 5000. | `devices.db` |

These scripts are not one end-to-end pipeline. Their SQLite files and table layouts differ. The dashboard reads `devices.db`; the simulator writes `data/flows.db`.

Back up the SQLite files before you start a different script. Some scripts delete tables when they start.

Use packet capture and Nmap only on networks that you have permission to inspect. Check the configured network before you start a scan.
