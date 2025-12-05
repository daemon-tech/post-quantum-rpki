# Reproducibility Guide

This document provides detailed instructions for reproducing the Post-Quantum RPKI measurements.

## System Requirements

- **Docker** 20.10+ and **Docker Compose** 2.0+
- **Disk Space**: ~15 GB (for RPKI data)
- **RAM**: 4 GB minimum, 8 GB recommended
- **Network**: Stable internet connection for downloading RPKI data

## Quick Reproduction

### Linux/macOS

```bash
./reproduce.sh
```

### Windows

```cmd
reproduce.bat
```

## Step-by-Step Manual Reproduction

### 1. Build Docker Image

```bash
docker compose build
```

This installs:
- Ubuntu 24.04 base
- Python 3.12
- liboqs-python 0.14.1 (NIST post-quantum algorithms)
- matplotlib, pandas, tqdm
- rpki-client
- All system dependencies

### 2. Fetch RPKI Data

```bash
docker compose run --rm pq-rpki bash -c "
  mkdir -p /data/original
  rsync -avz rsync://rpki.ripe.net/repository/ /data/original/
  rsync -avz rsync://rpki.apnic.net/repository/ /data/original/
"
```

**Note**: This downloads ~10 GB of data and may take 30-60 minutes depending on your connection.

### 3. Create Subset

```bash
docker compose run --rm pq-rpki python3 << 'PYTHON'
import random, shutil
from pathlib import Path

original = Path('/data/original')
subset = Path('/data/subset')
subset.mkdir(exist_ok=True)

files = list(original.rglob('*.cer')) + \
        list(original.rglob('*.roa')) + \
        list(original.rglob('*.mft')) + \
        list(original.rglob('*.crl'))

random.shuffle(files)
target = min(450000, len(files))
selected = files[:target]

for f in selected:
    shutil.copy2(f, subset / f.name)

print(f'Created subset: {len(list(subset.rglob("*")))} files')
PYTHON
```

### 4. Re-sign with Post-Quantum Algorithms

```bash
docker compose run --rm pq-rpki python3 /work/pq-resign.py
```

This will:
- Check algorithm availability
- Re-sign all files with ML-DSA-44 (Dilithium-2)
- Re-sign all files with Falcon-512
- Create baseline (ECDSA, no re-signing)

**Expected time**: 30-60 minutes depending on CPU

### 5. Validate

```bash
docker compose run --rm pq-rpki python3 /work/validate.py
```

This validates the signed repositories and collects metrics.

### 6. Generate Results

```bash
docker compose run --rm pq-rpki python3 /work/results.py
```

This generates:
- `RESULTS.md` - Comprehensive report
- `results.csv` - Raw data
- `results.json` - Detailed JSON
- `*.png` - Visualizations
- `results.tex` - LaTeX table

## Expected Results

### Size Overhead (vs ECDSA baseline)
- **ML-DSA-44 (Dilithium-2)**: ~+130% (2.3x)
- **Falcon-512**: ~+36% (1.36x)

### File Counts
- All algorithms: ~96,728 files (or your subset size)

### Validation Times
- May show 0.0s if rpki-client cannot process the format
- Signature verification times will be measured if OQS is available

## Troubleshooting

### Docker not found
```bash
# Install Docker Desktop from https://docs.docker.com/get-docker/
```

### Out of disk space
```bash
# Clean up Docker
docker system prune -a

# Remove old data
rm -rf data/original/*
```

### rsync fails
The RPKI repositories may be temporarily unavailable. Try:
1. Wait and retry later
2. Use a different mirror if available
3. Use pre-downloaded data if provided

### Algorithm not available
If you see "MechanismNotSupportedError":
1. Ensure liboqs-python 0.14.1+ is installed
2. Check that liboqs was compiled with ML-DSA support
3. Verify algorithm names: "ML-DSA-44" (not "Dilithium2")

### Validation times are 0.0s
This is expected if:
- Files aren't in standard RPKI certificate format
- rpki-client cannot process the appended signatures

The size measurements are still scientifically valid.

## Reproducibility Notes

### Random Seed
The subset creation uses Python's `random.shuffle()` which is not seeded. This means:
- Each run will create a different subset
- Results may vary slightly between runs
- For exact reproducibility, set a random seed in the subset creation script

### Version Pinning
All dependencies are pinned:
- `liboqs-python==0.14.1`
- Python 3.12 (via Ubuntu 24.04)
- Specific algorithm names (ML-DSA-44, Falcon-512)

### Data Sources
RPKI data is fetched from:
- `rsync://rpki.ripe.net/repository/`
- `rsync://rpki.apnic.net/repository/`

These are live repositories and may change over time.

## Citation

When reproducing or building upon this work, please cite:

```bibtex
@software{pq_rpki_2025,
  author = {Moes, Sam},
  title = {Real-World Measurements of NIST Post-Quantum Signatures in RPKI},
  year = {2025},
  month = {December},
  version = {1.0.0},
  url = {https://github.com/daemon-tech/pq-rpki-2025}
}
```

## License

MIT License - See [LICENSE](LICENSE) file.

