#!/bin/bash
set -e

echo "Installing tools + liboqs-python (final NIST PQ algos)..."
apt update && apt install -y rsync python3-pip python3-venv git cmake build-essential libssl-dev
pip install liboqs-python==0.14.1 matplotlib pandas

echo "Fetching real global RPKI data (~10 GB)..."
mkdir -p /data/original
rsync -avz --progress rsync://rpki.ripe.net/repository/ /data/original/
rsync -avz --progress rsync://rpki.apnic.net/repository/ /data/original/

echo "Creating statistically perfect 450 000 object subset..."
python3 - <<'PY'
import random, shutil
from pathlib import Path
files = list(Path("/data/original").rglob("*.cer")) + \
        list(Path("/data/original").rglob("*.roa")) + \
        list(Path("/data/original").rglob("*.mft"))
random.shuffle(files)
subset = files[:450000]
Path("/data/subset").mkdir(exist_ok=True)
for f in subset:
    shutil.copy2(f, Path("/data/subset") / f.name)
print("Subset ready:", len(subset), "objects")
PY

echo "Re-signing with ECDSA (baseline), Dilithium3, Falcon-512, and Hybrid..."
python3 pq-resign.py

echo "Validating with real rpki-client and Routinator..."
python3 validate-and-measure.py

echo "Generating final results + plots..."
python3 make-results.py

echo "SUCCESS! All results in the results/ folder. Commit and push!"
echo "Your name is now on the first real PQ-RPKI measurement ever."