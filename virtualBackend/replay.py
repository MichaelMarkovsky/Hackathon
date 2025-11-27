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
history = {}
last_time = {}

# ========== Timing / Replay Detection ==========
timing = {}
TIMING_LEARN_RATE = 0.05
REPLAY_FACTOR    = 0.35
DELAY_FACTOR     = 2.0

# ========== DoS Vars ==========
msg_count_total = 0
msg_count_id = {}
WINDOW_START = time.time()
BUS_RATE_LIMIT = 400
ID_RATE_LIMIT = 120


# ===================== PROCESS LOG =====================
with open(FILEPATH,"r") as f:
    for line in f:

        if "ID:" not in line or "DLC:" not in line:
            continue

        try:
            parts = line.replace("=",":").split()  # safer split

            # ---- SAFE ID + DLC PARSING FIX ----
            msg_id = int(parts[parts.index("ID:")+1],16)   # always finds correct field now
            dlc    = int(parts[parts.index("DLC:")+1])

            # extract data bytes reliably
            data_start = parts.index("DLC:") + 2
            raw_hex = parts[data_start : data_start+dlc]
            payload = bytes.fromhex(" ".join(raw_hex))
            data = list(payload)


            # ===== Timestamp detection FIX =====
            if parts[0].startswith("Timestamp:"):
                now = float(parts[1])        # log timestamp OK
            else:
                now = time.time()            # fallback


            # ================= UNKNOWN ID =================
            if msg_id not in baseline_dlc:
                print(f"🚨 UNKNOWN ID → {hex(msg_id)}")

            # ================= DLC MISMATCH =================
            if msg_id in baseline_dlc and dlc != baseline_dlc[msg_id]:
                print(f"⚠ BAD DLC LENGTH → {hex(msg_id)} expected={baseline_dlc[msg_id]} got={dlc}")


            # ================= TIMING ANOMALY =================
            if msg_id not in timing:
                timing[msg_id] = {"avg":None,"last":now}
            else:
                dt = now - timing[msg_id]["last"]

                if timing[msg_id]["avg"] is None:
                    timing[msg_id]["avg"] = dt
                else:
                    timing[msg_id]["avg"] = timing[msg_id]["avg"]*(1-TIMING_LEARN_RATE) + dt*TIMING_LEARN_RATE

                    if dt < timing[msg_id]["avg"]*REPLAY_FACTOR:
                        print(f"🚨 REPLAY / FAST BURST → {hex(msg_id)} Δ={dt:.6f}s avg={timing[msg_id]['avg']:.6f}s")

                    if dt > timing[msg_id]["avg"]*DELAY_FACTOR:
                        print(f"⚠ TIMING DELAY → {hex(msg_id)} Δ={dt:.6f}s avg={timing[msg_id]['avg']:.6f}s")

                timing[msg_id]["last"] = now


            # ================= SPOOFING DETECT =================
            if msg_id not in history:
                history[msg_id] = {"min":data[:], "max":data[:]}

            else:
                for i in range(len(data)):
                    if not history[msg_id]["min"][i] <= data[i] <= history[msg_id]["max"][i]:
                        print(f"🚨 SPOOF RANGE → {hex(msg_id)} byte[{i}]={data[i]} "
                              f"(allowed {history[msg_id]['min'][i]}–{history[msg_id]['max'][i]})")

                history[msg_id]["min"] = [min(history[msg_id]["min"][i],data[i]) for i in range(len(data))]
                history[msg_id]["max"] = [max(history[msg_id]["max"][i],data[i]) for i in range(len(data))]


            # ================= DoS Detection =================
            msg_count_total += 1
            msg_count_id[msg_id] = msg_count_id.get(msg_id,0) + 1

            if now - WINDOW_START >= 1.0:
                if msg_count_total > BUS_RATE_LIMIT:
                    print(f"\n🔥 BUS FLOODING — {msg_count_total} msg/s")

                for mid,count in msg_count_id.items():
                    if count > ID_RATE_LIMIT:
                        print(f"🚨 DoS on {hex(mid)} → {count} msg/s")

                msg_count_total=0
                msg_count_id.clear()
                WINDOW_START=now


            # ================= OUTPUT =================
            print(f"[{now:.6f}s] ✔ {hex(msg_id):>6}  RAW: {' '.join(raw_hex)} | PARSED: {data}")

            bus.send(can.Message(arbitration_id=msg_id,data=payload))
            time.sleep(0.01)

        except Exception as e:
            print("Parse error:",e,"\nLINE:",line)
