import os
import os
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent   # folder of this script


# ===== configure input log =====
from dotenv import load_dotenv
load_dotenv()

FILEPATH = os.getenv("FILEPATH")      # points to normalrun.txt
baseline_file = SCRIPT_DIR / "baseline_ids.txt"    # where learned IDs will be stored

# ===== storage for extracted IDs =====
learned_ids = set()

# ===== extract all IDs from logfile =====
with open(FILEPATH, "r") as f:
    for line in f:
        if "ID:" not in line:
            continue

        try:
            # get everything after "ID:"
            msg_id_str = line.split("ID:")[1].split()[0]
            msg_id = int(msg_id_str, 16)   # convert hex string -> integer
            learned_ids.add(msg_id)

        except:
            pass  # just skip if anything doesnt parse


# ===== save baseline to file AS HEX =====
with open(baseline_file, "w") as f:
    for msg_id in sorted(learned_ids):
        f.write(f"{hex(msg_id)}\n")

print("✔ Baseline learned successfully")
print("✔ IDs saved to:", baseline_file)
print(f"Total IDs found: {len(learned_ids)}")
print("\nBaseline content:\n")

for msg_id in learned_ids:
    print(hex(msg_id))
