import can
import time
from dotenv import load_dotenv
import os
from pathlib import Path



bus = can.Bus(interface='virtual')

load_dotenv()  # loads .env variables into environment

FILEPATH = os.getenv("FILEPATH")


# ===== load previous baseline =====
SCRIPT_DIR = Path(__file__).resolve().parent
baseline_file = SCRIPT_DIR / "baseline_ids.txt"
known_ids = set()

if os.path.exists(baseline_file):
    with open(baseline_file, "r") as f:
        known_ids = {int(line.strip(), 16) for line in f}



with open(FILEPATH, "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue

        try:
            parts = line.split()

            # Find ID
            id_idx = parts.index("ID:")      # ... ID: 02b0 ...
            msg_id_str = parts[id_idx + 1]   # "02b0"
            msg_id = int(msg_id_str, 16)


            if msg_id not in known_ids:
                print("Anomaly: unknown ID ->", hex(msg_id))
              


            # Find DLC
            dlc_idx = parts.index("DLC:")    # ... DLC: 5 ...
            dlc = int(parts[dlc_idx + 1])    # 5

            # Data bytes start right after DLC value
            data_tokens = parts[dlc_idx + 2 : dlc_idx + 2 + dlc]

            # Join them into a single hex string and convert to bytes
            data_bytes = bytes.fromhex(" ".join(data_tokens))

            msg = can.Message(arbitration_id=msg_id, data=data_bytes)
            bus.send(msg)

   
            print(msg)

            
            time.sleep(0.01)

        except Exception as e:
            print("Parse Error:", e, "\nLine:", line)
