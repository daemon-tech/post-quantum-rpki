#!/bin/bash
# Reproduce Post-Quantum RPKI Measurements
# This script runs the complete experiment in Docker

set -e

echo "=========================================="
echo "  Post-Quantum RPKI Measurement"
echo "  Reproducible Docker Setup"
echo "=========================================="
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed or not in PATH"
    echo "Please install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

# Create data directory if it doesn't exist
mkdir -p data/original data/subset data/signed

# Build Docker image
echo "Building Docker image..."
docker compose build

# Run the complete experiment
echo ""
echo "Starting experiment..."
echo "This will:"
echo "  1. Fetch RPKI data from RIPE/APNIC"
echo "  2. Create 450,000 object subset"
echo "  3. Re-sign with post-quantum algorithms"
echo "  4. Validate and generate results"
echo ""

docker compose run --rm pq-rpki bash -c "
    set -e
    
    echo '=== Step 1: Fetching RPKI data ==='
    if [ ! -d /data/original ] || [ -z \"\$(ls -A /data/original 2>/dev/null)\" ]; then
        mkdir -p /data/original
        echo 'Fetching from RIPE...'
        rsync -avz --progress rsync://rpki.ripe.net/repository/ /data/original/ || echo 'RIPE sync failed, continuing...'
        echo 'Fetching from APNIC...'
        rsync -avz --progress rsync://rpki.apnic.net/repository/ /data/original/ || echo 'APNIC sync failed, continuing...'
    else
        echo 'RPKI data already exists, skipping download'
    fi
    
    echo ''
    echo '=== Step 2: Creating subset ==='
    if [ ! -d /data/subset ] || [ -z \"\$(ls -A /data/subset 2>/dev/null)\" ]; then
        python3 << 'PYTHON'
import random
import shutil
from pathlib import Path

original = Path('/data/original')
subset = Path('/data/subset')
subset.mkdir(exist_ok=True)

# Find all RPKI objects
files = list(original.rglob('*.cer')) + \
        list(original.rglob('*.roa')) + \
        list(original.rglob('*.mft')) + \
        list(original.rglob('*.crl'))

if len(files) == 0:
    print('ERROR: No RPKI files found in /data/original')
    print('Please ensure RPKI data is available')
    exit(1)

print(f'Found {len(files):,} RPKI objects')
random.shuffle(files)

# Create subset (up to 450,000 or all available)
target_count = min(450000, len(files))
selected = files[:target_count]

print(f'Creating subset of {target_count:,} objects...')
for f in selected:
    relative = f.relative_to(original)
    dest = subset / relative.name
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(f, dest)

print(f'Subset ready: {len(list(subset.rglob(\"*\")))} files')
PYTHON
    else
        echo 'Subset already exists, skipping creation'
    fi
    
    echo ''
    echo '=== Step 3: Re-signing with post-quantum algorithms ==='
    python3 /work/pq-resign.py
    
    echo ''
    echo '=== Step 4: Validating ==='
    python3 /work/validate.py
    
    echo ''
    echo '=== Step 5: Generating results ==='
    python3 /work/results.py
    
    echo ''
    echo '=========================================='
    echo '  SUCCESS! Results generated:'
    echo '  • RESULTS.md'
    echo '  • results.csv'
    echo '  • results.json'
    echo '  • *.png (visualizations)'
    echo '  • results.tex (LaTeX table)'
    echo '=========================================='
"

echo ""
echo "Experiment complete! Check the following files:"
echo "  • RESULTS.md - Comprehensive report"
echo "  • results.csv - Raw data"
echo "  • *.png - Visualizations"
echo "  • results.tex - LaTeX table for papers"
echo ""

