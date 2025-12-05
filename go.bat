@echo off
echo Starting the FINAL run - this time it WILL NOT close
echo Installing pv + running everything...
echo.

docker compose run --rm rpki bash -c ^
"apt update > /dev/null 2>&1 && apt install -y pv rsync > /dev/null 2>&1 && ^
source /work/venv/bin/activate && ^
echo '=== Fast 450 000 object subset with progress bar ===' && ^
./fast-subset.sh && ^
echo '' && ^
echo '=== Re-signing with Dilithium3 + Falcon-512 ===' && ^
python3 /work/pq-resign.py && ^
echo '' && ^
echo '=== Validating ===' && ^
python3 /work/validate.py && ^
echo '' && ^
echo '=== Generating results ===' && ^
python3 /work/results.py && ^
echo '' && ^
echo '=============================================================' && ^
echo '  SUCCESS! Your results are ready!' && ^
echo '  Open RESULTS.md and the PNG files on your Desktop' && ^
echo '=============================================================' && ^
bash"