@echo off
REM Reproduce Post-Quantum RPKI Measurements (Windows)
REM This script runs the complete experiment in Docker

echo ==========================================
echo   Post-Quantum RPKI Measurement
echo   Reproducible Docker Setup
echo ==========================================
echo.

REM Check if Docker is available
where docker >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Docker is not installed or not in PATH
    echo Please install Docker Desktop: https://docs.docker.com/get-docker/
    exit /b 1
)

REM Create data directory if it doesn't exist
if not exist "data\original" mkdir "data\original"
if not exist "data\subset" mkdir "data\subset"
if not exist "data\signed" mkdir "data\signed"

REM Build Docker image
echo Building Docker image...
docker compose build
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Docker build failed
    exit /b 1
)

REM Run the complete experiment
echo.
echo Starting experiment...
echo This will:
echo   1. Fetch RPKI data from RIPE/APNIC
echo   2. Create 450,000 object subset
echo   3. Re-sign with post-quantum algorithms
echo   4. Validate and generate results
echo.

docker compose run --rm pq-rpki bash -c "set -e && echo '=== Step 1: Fetching RPKI data ===' && if [ ! -d /data/original ] || [ -z \"\$(ls -A /data/original 2>/dev/null)\" ]; then mkdir -p /data/original && echo 'Fetching from RIPE...' && rsync -avz --progress rsync://rpki.ripe.net/repository/ /data/original/ || echo 'RIPE sync failed, continuing...' && echo 'Fetching from APNIC...' && rsync -avz --progress rsync://rpki.apnic.net/repository/ /data/original/ || echo 'APNIC sync failed, continuing...'; else echo 'RPKI data already exists, skipping download'; fi && echo '' && echo '=== Step 2: Creating subset ===' && if [ ! -d /data/subset ] || [ -z \"\$(ls -A /data/subset 2>/dev/null)\" ]; then python3 -c \"import random, shutil; from pathlib import Path; original = Path('/data/original'); subset = Path('/data/subset'); subset.mkdir(exist_ok=True); files = list(original.rglob('*.cer')) + list(original.rglob('*.roa')) + list(original.rglob('*.mft')) + list(original.rglob('*.crl')); print(f'Found {len(files):,} RPKI objects'); random.shuffle(files); target_count = min(450000, len(files)); selected = files[:target_count]; print(f'Creating subset of {target_count:,} objects...'); [shutil.copy2(f, subset / f.name) for f in selected]; print(f'Subset ready: {len(list(subset.rglob(\"*\")))} files')\"; else echo 'Subset already exists, skipping creation'; fi && echo '' && echo '=== Step 3: Re-signing with post-quantum algorithms ===' && python3 /work/pq-resign.py && echo '' && echo '=== Step 4: Validating ===' && python3 /work/validate.py && echo '' && echo '=== Step 5: Generating results ===' && python3 /work/results.py && echo '' && echo '==========================================' && echo '  SUCCESS! Results generated:' && echo '  • RESULTS.md' && echo '  • results.csv' && echo '  • results.json' && echo '  • *.png (visualizations)' && echo '  • results.tex (LaTeX table)' && echo '=========================================='"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Experiment failed
    exit /b 1
)

echo.
echo Experiment complete! Check the following files:
echo   • RESULTS.md - Comprehensive report
echo   • results.csv - Raw data
echo   • *.png - Visualizations
echo   • results.tex - LaTeX table for papers
echo.

