import can
import time
from dotenv import load_dotenv
import os

bus = can.Bus(interface='virtual')

load_dotenv()  # loads .env variables into environment

FILEPATH = os.getenv("FILEPATH")

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
