@echo off
echo Starting the final run with fast 450k subset + progress bar...
docker compose run --rm rpki bash -c ^
"apt update && apt install -y pv rsync && ^
echo '#!/bin/bash
set -e
echo \"=== Creating FAST 450 000 object subset with progress bar ===\"
mkdir -p /data/subset
find /data/original -type f \( -name \"*.cer\" -o -name \"*.roa\" -o -name \"*.mft\" \) | shuf | head -450000 | pv -l -s 450000 > /tmp/list
echo \"Copying 450000 files (you will see progress) ...\"
pv -l -s 450000 /tmp/list | xargs -n1 -I{} cp -a --parents {} /data/subset/
echo \"Subset ready!\"
' > fast-subset.sh && chmod +x fast-subset.sh && ^
source /work/venv/bin/activate && ^
./fast-subset.sh && ^
python3 /work/pq-resign.py && ^
python3 /work/validate.py && ^
python3 /work/results.py && ^
echo \"SUCCESS! Results in D:\code-space\pq-rpki-2025\RESULTS.md and PNGs\""