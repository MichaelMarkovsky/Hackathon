import os
from pathlib import Path
from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent  # directory of this script
load_dotenv()

FILEPATH = os.getenv("FILEPATH")  # normalrun.txt path
baseline_dlc_file = SCRIPT_DIR / "baseline_dlc.txt"

# Storage: ID → DLC
learned_dlc = {}

# ===== Extract ID & DLC from log =====
with open(FILEPATH, "r") as f:
    for line in f:
        if "ID:" not in line or "DLC:" not in line:
            continue

        try:
            msg_id_str = line.split("ID:")[1].split()[0]
            dlc_str = line.split("DLC:")[1].split()[0]

            msg_id = int(msg_id_str, 16)
            dlc = int(dlc_str)

            learned_dlc[msg_id] = dlc  # last seen wins (normal)

        except:
            continue

# ===== Save as ID,DLC baseline =====
with open(baseline_dlc_file, "w") as f:
    for msg_id in sorted(learned_dlc.keys()):
        f.write(f"{hex(msg_id)},{learned_dlc[msg_id]}\n")

# ===== Output preview =====
print("\n===== ✔ Baseline Learned =====")
print("DLC profile saved to:", baseline_dlc_file)
print(f"Total IDs recorded: {len(learned_dlc)}\n")

print("Baseline DLC Mapping (ID → DLC):\n")
for msg_id,dlc in learned_dlc.items():
    print(f"{hex(msg_id)} → DLC={dlc}")
