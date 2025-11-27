import can
import time
from dotenv import load_dotenv
import os
from pathlib import Path

bus = can.Bus(interface='virtual')
load_dotenv()
FILEPATH = os.getenv("FILEPATH")

SCRIPT_DIR = Path(__file__).resolve().parent
baseline_dlc_file = SCRIPT_DIR / "baseline_dlc.txt"


# ========== Load DLC Baseline ==========
baseline_dlc = {}
if baseline_dlc_file.exists():
    for line in open(baseline_dlc_file):
        msg, dlc = line.strip().split(",")
        baseline_dlc[int(msg,16)] = int(dlc)


print(f"[INFO] Loaded {len(baseline_dlc)} DLC baseline entries\n")


# ========== Adaptive Spoof Learning ==========
history = {}          # msg_id → min/max for spoofing
last_time = {}        # msg_id → last timestamp for replay



# ========== Replay Sensitivity (seconds) ==========
REPLAY_THRESHOLD = 0.045  


# ========== DoS Detection Variables ==========
msg_count_total = 0                    # messages/second
msg_count_id = {}                      # per-ID message rate
WINDOW_START = time.time()
BUS_RATE_LIMIT = 400                    # global flooding threshold
ID_RATE_LIMIT = 120                     # per-ID flood threshold



# ========== Process CAN log ==========
with open(FILEPATH,"r") as f:
    for line in f:

        if "ID:" not in line or "DLC:" not in line:
            continue

        try:
            parts     = line.split()
            msg_id    = int(parts[parts.index("ID:")+1],16)
            dlc       = int(parts[parts.index("DLC:")+1])
            raw_hex   = parts[parts.index("DLC:")+2 : parts.index("DLC:")+2+dlc]
            payload   = bytes.fromhex(" ".join(raw_hex))
            data      = list(payload)
            now       = time.time()


            # ================= UNKNOWN ID =================
            if msg_id not in baseline_dlc:
                print(f"🚨 UNKNOWN ID DETECTED → {hex(msg_id)}")


            # ================= DLC MISMATCH =================
            if msg_id in baseline_dlc and dlc != baseline_dlc[msg_id]:
                print(f"⚠ BAD DLC LENGTH → {hex(msg_id)} expected={baseline_dlc[msg_id]} got={dlc}")



            # ================= REPLAY ATTACK =================
            if msg_id in last_time and (now - last_time[msg_id]) < REPLAY_THRESHOLD:
                print(f"🚨 REPLAY ATTACK → {hex(msg_id)} sent too fast")
            last_time[msg_id] = now



            # ================= SPOOFING RANGE BREAK =================
            if msg_id not in history:
                history[msg_id] = {"min":data[:], "max":data[:]}
            else:
                for i in range(len(data)):
                    if not history[msg_id]["min"][i] <= data[i] <= history[msg_id]["max"][i]:
                        print(f"🚨 SPOOF RANGE → {hex(msg_id)} byte[{i}]={data[i]} "
                              f"(allowed {history[msg_id]['min'][i]}–{history[msg_id]['max'][i]})")

                # Auto-learn dynamic expansion
                history[msg_id]["min"] = [min(history[msg_id]["min"][i],data[i]) for i in range(len(data))]
                history[msg_id]["max"] = [max(history[msg_id]["max"][i],data[i]) for i in range(len(data))]



            # ======================= DoS FLOOD DETECTION =======================
            # 1) overall messages/sec
            msg_count_total += 1

            # count per-ID rate
            msg_count_id[msg_id] = msg_count_id.get(msg_id,0) + 1


            # Sliding 1-second window
            if now - WINDOW_START >= 1.0:
                if msg_count_total > BUS_RATE_LIMIT:
                    print(f"\n🔥🔥 BUS FLOODING DETECTED — {msg_count_total} msg/s (limit {BUS_RATE_LIMIT})")

                for mid,count in msg_count_id.items():
                    if count > ID_RATE_LIMIT:
                        print(f"🚨 DoS on ID {hex(mid)} → {count} msg/s")

                # Reset counters
                msg_count_total = 0
                msg_count_id.clear()
                WINDOW_START = now



            # ================= PRINT =================
            print(f"[OK] {hex(msg_id)} → RAW: {' '.join(raw_hex)} | PARSED: {data}")


            # Send to virtual CAN
            bus.send(can.Message(arbitration_id=msg_id, data=payload))
            time.sleep(0.01)

        except Exception as e:
            print("Parse error:",e,"\nLINE:",line)
