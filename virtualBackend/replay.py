import can
import time
from dotenv import load_dotenv
import os
from pathlib import Path


# ================== CAN BUS ==================
bus = can.Bus(interface='virtual')

load_dotenv()
FILEPATH = os.getenv("FILEPATH")   # log file to replay


# ================== LOAD BASELINE DLC ==================
SCRIPT_DIR = Path(__file__).resolve().parent
baseline_dlc_file = SCRIPT_DIR / "baseline_dlc.txt"   # << NEW

baseline_dlc = {}   # msg_id → dlc

if baseline_dlc_file.exists():
    with open(baseline_dlc_file, "r") as f:
        for line in f:
            line=line.strip()
            if not line: 
                continue
            try:
                msg_id_hex, dlc = line.split(",")
                baseline_dlc[int(msg_id_hex,16)] = int(dlc)
            except:
                pass

print(f"Loaded {len(baseline_dlc)} baseline IDs\n")


# ================== PROCESS LOG ==================
with open(FILEPATH, "r") as f:
    for line in f:
        line = line.strip()
        if "ID:" not in line or "DLC:" not in line:
            continue

        try:
            parts = line.split()

            # ----- CAN ID -----
            msg_id = int(parts[parts.index("ID:")+1],16)

            # Unknown ID detection
            if msg_id not in baseline_dlc:
                print(f"UNKNOWN ID → {hex(msg_id)}")

            # ----- DLC -----
            dlc = int(parts[parts.index("DLC:")+1])

            # DLC anomaly detection
            if msg_id in baseline_dlc and dlc != baseline_dlc[msg_id]:
                print(f"DLC MISMATCH → {hex(msg_id)} expected={baseline_dlc[msg_id]} got={dlc}")


            # ----- Extract data -----
            data_tokens = parts[parts.index("DLC:")+2 : parts.index("DLC:")+2+dlc]
            data_bytes = bytes.fromhex(" ".join(data_tokens))


            # ----- SEND INTO vCAN -----
            msg = can.Message(arbitration_id=msg_id, data=data_bytes)
            bus.send(msg)
            raw_hex = " ".join(parts[parts.index("DLC:")+2 : parts.index("DLC:")+2+dlc])
            print(f"[OK] {hex(msg_id)} → RAW: {raw_hex} | PARSED: {data_bytes}")


            time.sleep(0.01)

        except Exception as e:
            print("Parse Error:", e, "\nLine:", line)
