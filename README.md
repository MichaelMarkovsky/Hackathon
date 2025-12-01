# CarSniffer - CAN Bus Intrusion Detection System

A CAN-network intrusion detection system that **sniffs, visualizes, learns baselines, and detects attacks** on automotive CAN traffic in real time.



![example](https://github.com/user-attachments/assets/43430165-42c1-42be-8783-d411ad18c7af)

> **CAN (Controller Area Network)** is the communication bus used inside modern vehicles -  
> it allows ECUs (engine, brakes, steering, sensors) to exchange messages in real time.


## Features
- Reads & monitors live **CAN frame streams**.
- Real-time dashboard with **graph, logs, decoded signals, alerts**.
- 5 detection mechanisms:
  - Spoofing / Fake Injection (value jump delta)
  - Replay Attack (signature repetition hashing)
  - Flooding / DoS (rate-based threshold)
  - DLC Manipulation (unexpected frame length)
  - Timing Anomalies (irregular intervals)
- Learns baseline values per ID and flags deviations.
- Supports **datasets or real CAN-bus sniffing interface**.
- Highlights malicious frames directly in the live feed UI.

## Overview

When running the project, we start with a normal dataset: `normalrun.txt`

Source:  
https://ocslab.hksecurity.net/Datasets/CAN-intrusion-dataset

This dataset is **clean (attack-free)**, meaning we can extract its structure to understand what "normal" CAN communication looks like.

---

### Baseline Learning Stage

The script `baseline_learn.py` parses `normalrun.txt` and extracts:

| Field | Meaning |
|---|---|
| **ID**  | The CAN message identifier |
| **DLC** | Data Length Code (payload size) |

These learned values are saved into `baseline_dlc.txt`, which becomes a map of legal ID/DLC structure.  
If later traffic has mismatched values => it's suspicious.

---

### Simulation & Detection Stage

The main script `replay.py` streams `normalrun.txt` like a real CAN buffer.  
It runs all 5 detection mechanisms live while feeding the UI.

If a frame violates expected behavior (wrong DLC, replay signature, abnormal spike, DoS-rate, timing irregularity) => an alert is triggered instantly.

---

## Attack Detection Types

| Attack Type | Detected By | Example |
|---|---|---|
| **Spoofing / Fake Injection** | **Δ-value threshold per ID** - checks abnormal jumps in signal values between consecutive frames | RPM normally increases gradually (1500=>1600=>1700) but spoof jumps to **9000 instantly** |
| **Replay Attack** | Signature repetition hashing - detects repeated payload patterns over time | Valid data but injected at the **wrong moment** |
| **Flooding / DoS** | Message-rate counter - too many frames per second triggers overload alert | Excessive traffic causes **ECUs to lose arbitration** |
| **DLC Manipulation** | `baseline_dlc.txt` legality check - invalid DLC compared to learned baseline | ID normally uses DLC=8, attacker sends DLC=2 |
| **Timing Anomalies** | Interval deviation tracking - detects irregular time spacing between frames | Messages arrive **too early or too late** vs expected rhythm |


<p align="center">
  <img src="https://github.com/user-attachments/assets/3e02b7b2-8b5c-4ebc-a456-b0ed2cc0f434" height="220"/>
  <img src="https://github.com/user-attachments/assets/f53e9059-9c3a-4212-9183-d9ff7fd645d7" height="200"/>
</p>

---

## Dataset Flow Summary

| File | Purpose |
|---|---|
| `normalrun.txt` | Clean dataset - used for simulation |
| `baseline_learn.py` | Builds `baseline_dlc.txt` by extracting IDs + DLC |
| `baseline_dlc.txt` | Legal reference of CAN ID/DLC structure |
| `replay.py` | Simulates & detects attacks in real time |

---

## Example CAN Log Input

```text
Timestamp: 1479121434.850202        ID: 0350    000    DLC: 8    05 28 84 66 6d 00 00 a2
Timestamp: 1479121434.850423        ID: 02c0    000    DLC: 8    14 00 00 00 00 00 00 00
Timestamp: 1479121434.850977        ID: 0430    000    DLC: 8    00 00 00 00 00 00 00 00

```

## Usage

0. Create `.env` inside `virtual_backend/`:

    virtual_backend/.env
    `FILEPATH=./normalrun.txt`
     *or set absolute file path if dataset is elsewhere*

1. Generate baseline (required once):

    `python virtual_backend/baseline_learn.py`

2. Open dashboard UI in browser:

    `dashboard/index.html`      *or open with Live Server*

3. Run simulation + intrusion detection:

    `python virtual_backend/replay.py`


