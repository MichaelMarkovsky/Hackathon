import can
import time
from dotenv import load_dotenv
import os
from pathlib import Path


# ================== CAN BUS ==================
bus = can.Bus(interface='virtual')

load_dotenv()
FILEPATH = os.getenv("FILEPATH")


# ================== LOAD BASELINE DLC ==================
SCRIPT_DIR = Path(__file__).resolve().parent
baseline_dlc_file = SCRIPT_DIR / "baseline_dlc.txt"

baseline_dlc = {}
if baseline_dlc_file.exists():
    with open(baseline_dlc_file, "r") as f:
        for line in f:
            if not line.strip(): continue
            msg_hex, dlc = line.split(",")
            baseline_dlc[int(msg_hex,16)] = int(dlc)

print(f"\nLoaded {len(baseline_dlc)} DLC profiles\n")


# ================== PER-ID SPOOF THRESHOLDS ==================
spoof_thresholds = {
    0x130: 600,  # Fast changing — likely RPM/Torque
    0x131: 600,
    0x350: 550,
    0x545: 350,
    0x2a0: 350,
    0x529: 350 if 0x329 else None,
    0x260: 250,
    0x2c0: 150,
}

DEFAULT_SPOOF_THRESHOLD = 300      # fallback if ID not present

# store last payload for comparing
last_data = {}



# ================== PROCESS LOG ==================
with open(FILEPATH, "r") as f:
    for line in f:
        if "ID:" not in line or "DLC:" not in line:
            continue
        
        try:
            parts = line.split()

            # ----- ID -----
            msg_id = int(parts[parts.index("ID:")+1],16)

            if msg_id not in baseline_dlc:
                print(f"❓UNKNOWN ID → {hex(msg_id)} (not in DLC baseline)")

            # ----- DLC -----
            dlc = int(parts[parts.index("DLC:")+1])
            if msg_id in baseline_dlc and dlc != baseline_dlc[msg_id]:
                print(f"⚠ DLC MISMATCH → {hex(msg_id)} expected={baseline_dlc[msg_id]} got={dlc}")


            # ----- DATA -----
            data_tokens = parts[parts.index("DLC:")+2 : parts.index("DLC:")+2 + dlc]
            data_bytes = bytes.fromhex(" ".join(data_tokens))


            # ===== SPOOF DETECTION WITH PER-ID THRESHOLDS =====
            TH = spoof_thresholds.get(msg_id, DEFAULT_SPOOF_THRESHOLD)

            if msg_id in last_data:
                diff = sum(abs(data_bytes[i] - last_data[msg_id][i]) for i in range(len(data_bytes)))
                if diff > TH:
                    print(f"🚨 SPOOFING DETECTED → {hex(msg_id)} Δ={diff} (threshold {TH})")
            
            last_data[msg_id] = list(data_bytes)


            # ================== SEND + PRINT ==================
            msg = can.Message(arbitration_id=msg_id, data=data_bytes)
            bus.send(msg)

            raw_str = " ".join(data_tokens)
            print(f"[OK] {hex(msg_id)} → RAW: {raw_str} | BYTES: {data_bytes!r}")


            time.sleep(0.01)

        except Exception as e:
            print("Parse Error:", e, "\nLine:", line)
