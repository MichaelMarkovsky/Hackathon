import os
import time
from pathlib import Path

import can
import socketio
import eventlet
from dotenv import load_dotenv

# ============ Socket.IO SERVER ============
sio = socketio.Server(cors_allowed_origins="*")
app = socketio.WSGIApp(sio)

# ============ CAN BUS SETUP ============
bus = can.Bus(interface="virtual")

# ============ ENV / FILES ============
load_dotenv()
FILEPATH = os.getenv("FILEPATH")  # path to your GIDS log file

if not FILEPATH:
    raise RuntimeError("Set FILEPATH in .env as FILEPATH=/full/path/to/log.txt")

SCRIPT_DIR = Path(__file__).resolve().parent
baseline_dlc_file = SCRIPT_DIR / "baseline_dlc.txt"

# ========== Load DLC Baseline ==========
baseline_dlc = {}
if baseline_dlc_file.exists():
    with open(baseline_dlc_file, "r") as bf:
        for line in bf:
            msg, dlc = line.strip().split(",")
            baseline_dlc[int(msg, 16)] = int(dlc)

print(f"[INFO] Loaded {len(baseline_dlc)} DLC baseline entries\n")

# ========== State for IDS ==========
history = {}
timing = {}

TIMING_LEARN_RATE = 0.05
REPLAY_FACTOR = 0.35
DELAY_FACTOR = 2.0

msg_count_total = 0
msg_count_id = {}
WINDOW_START = time.time()
BUS_RATE_LIMIT = 400
ID_RATE_LIMIT = 120


def process_log():
    """Replay log file, run IDS, send frames to web via Socket.IO + virtual CAN."""
    global msg_count_total, msg_count_id, WINDOW_START

    with open(FILEPATH, "r") as f:
        for line in f:
            if "ID:" not in line or "DLC:" not in line:
                continue

            try:
                parts = line.replace("=", ":").split()

                msg_id = int(parts[parts.index("ID:") + 1], 16)
                dlc = int(parts[parts.index("DLC:") + 1])

                # extract DLC bytes
                data_start = parts.index("DLC:") + 2
                raw_hex = parts[data_start: data_start + dlc]
                payload = bytes.fromhex(" ".join(raw_hex))
                data = list(payload)

                # timestamp from log if exists
                if parts[0].startswith("Timestamp:"):
                    now = float(parts[1])
                else:
                    now = time.time()

                flags = []   # IDS flags
                reasons = [] # human-readable for UI

                # ===== UNKNOWN ID / DLC baseline =====
                if msg_id not in baseline_dlc:
                    baseline_dlc[msg_id] = dlc  # learn it once
                    flags.append("new_id")
                    reasons.append("New CAN ID seen")
                    print(f" NEW ID → {hex(msg_id)}")

                elif dlc != baseline_dlc[msg_id]:
                    flags.append("bad_dlc")
                    reasons.append(f"Bad DLC (expected {baseline_dlc[msg_id]}, got {dlc})")
                    print(f"⚠ BAD DLC → {hex(msg_id)} expected={baseline_dlc[msg_id]} got={dlc}")

                # ===== TIMING ANOMALY =====
                if msg_id not in timing:
                    timing[msg_id] = {"avg": None, "last": now}
                else:
                    dt = now - timing[msg_id]["last"]

                    if timing[msg_id]["avg"] is None:
                        timing[msg_id]["avg"] = dt
                    else:
                        timing[msg_id]["avg"] = (
                            timing[msg_id]["avg"] * (1 - TIMING_LEARN_RATE)
                            + dt * TIMING_LEARN_RATE
                        )

                        if dt < timing[msg_id]["avg"] * REPLAY_FACTOR:
                            flags.append("replay_fast")
                            reasons.append(f"Replay/fast burst Δ={dt:.6f}s")
                            print(
                                f"🚨 REPLAY / FAST BURST → {hex(msg_id)} Δ={dt:.6f}s "
                                f"avg={timing[msg_id]['avg']:.6f}s"
                            )

                        if dt > timing[msg_id]["avg"] * DELAY_FACTOR:
                            flags.append("delay")
                            reasons.append(f"Timing delay Δ={dt:.6f}s")
                            print(
                                f"⚠ TIMING DELAY → {hex(msg_id)} Δ={dt:.6f}s "
                                f"avg={timing[msg_id]['avg']:.6f}s"
                            )

                    timing[msg_id]["last"] = now

                # ===== SPOOF RANGE DETECTION =====
                if msg_id not in history:
                    history[msg_id] = {"min": data[:], "max": data[:]}
                else:
                    for i, val in enumerate(data):
                        if not (history[msg_id]["min"][i] <= val <= history[msg_id]["max"][i]):
                            flags.append("spoof_range")
                            reasons.append(f"Spoof byte[{i}]={val}")
                            print(
                                f"🚨 SPOOF RANGE → {hex(msg_id)} byte[{i}]={val} "
                                f"(allowed {history[msg_id]['min'][i]}–{history[msg_id]['max'][i]})"
                            )

                    history[msg_id]["min"] = [
                        min(history[msg_id]["min"][i], data[i])
                        for i in range(len(data))
                    ]
                    history[msg_id]["max"] = [
                        max(history[msg_id]["max"][i], data[i])
                        for i in range(len(data))
                    ]

                # ===== DoS DETECTION =====
                msg_count_total += 1
                msg_count_id[msg_id] = msg_count_id.get(msg_id, 0) + 1

                if now - WINDOW_START >= 1.0:
                    if msg_count_total > BUS_RATE_LIMIT:
                        print(f"\n BUS FLOODING — {msg_count_total} msg/s")
                        sio.emit("alert", {
                            "type": "dos_bus",
                            "msg": f"BUS FLOODING — {msg_count_total} msg/s",
                            "timestamp": time.time(),
                        })

                    for mid, count in msg_count_id.items():
                        if count > ID_RATE_LIMIT:
                            print(f"🚨 DoS on {hex(mid)} → {count} msg/s")
                            sio.emit("alert", {
                                "type": "dos_id",
                                "msg": f"DoS on {hex(mid)} → {count} msg/s",
                                "id": hex(mid),
                                "timestamp": time.time(),
                            })

                    msg_count_total = 0
                    msg_count_id.clear()
                    WINDOW_START = now

                # ===== Print + send to virtual CAN =====
                print(f"[{now:.6f}s] ✔ {hex(msg_id):>6} RAW: {' '.join(raw_hex)} | PARSED: {data}")
                bus.send(can.Message(arbitration_id=msg_id, data=payload))

                # ===== Emit to web dashboard =====
                frame_obj = {
                    "id": msg_id,
                    "hex_id": hex(msg_id),
                    "raw_hex": raw_hex,
                    "data": data,
                    "timestamp": now,
                    "flags": flags,
                    "reasons": reasons,
                }
                sio.emit("frame", frame_obj)

                eventlet.sleep(0.01)

            except Exception as e:
                print("Parse error:", e, "\nLINE:", line)


if __name__ == "__main__":
    print("[INFO] Starting IDS + Socket.IO server at http://localhost:5001")
    eventlet.spawn(process_log)
    eventlet.wsgi.server(eventlet.listen(("0.0.0.0", 5001)), app)
