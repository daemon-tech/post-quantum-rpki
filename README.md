# Post-Quantum RPKI Real Measurement (December 2025)

**Measured what actually happens when we switch Internet routing security to quantum-safe cryptography.**

- 118,068 real objects from todays live RIPE/APNIC repositories
- Re-signed with **ML-DSA-44 (Dilithium-2)**, **ML-DSA-65 (Dilithium-3)**, **ML-DSA-87 (Dilithium-5)**, **Falcon-512**, and hybrid variants (final NIST standards)
- Real size overhead measured -> no estimates, no toy CAs

## Repository Structure

```
pq-rpki-2025/
├── .dockerignore                      # Docker build exclusions
├── .gitattributes                     # Git attributes configuration
├── .gitignore                         # Git ignore rules
├── CITATION.cff                       # Citation metadata (CFF format)
├── LICENSE                            # MIT License
├── README.md                          # Main project documentation
├── RESULTS.md                         # Scientific results report
├── Dockerfile                         # Docker container definition
├── docker-compose.yml                 # Docker Compose configuration
├── requirements.txt                   # Python package dependencies
├── asn1_rpki.py                       # ASN.1 parser for signature replacement
├── pq-resign.py                       # Main script: re-sign RPKI objects with PQ signatures
├── validate.py                        # Main script: validate and measure PQ signatures
├── results.py                         # Main script: generate analysis and visualizations
├── pq-resign-enhanced.py              # Enhanced resigning with CMS wrapping
├── validate-enhanced.py               # Enhanced validation with memory profiling
├── results-analysis.ipynb             # Jupyter notebook for interactive analysis
├── reproduce.sh                       # Complete reproduction workflow (Linux/Mac)
├── reproduce.bat                      # Complete reproduction workflow (Windows)
├── run-all.sh                         # Alternative experiment runner (Linux/Mac)
├── run-all.bat                        # Alternative experiment runner (Windows)
└── fast-subset.sh                     # Fast subset creation utility
```

### Key Result
**Falcon-512 = only +36% repository size**  
→ The Internet **survives** quantum computers.

ML-DSA-44 (Dilithium-2) = +133% -> too big for current infrastructure.

-> **Falcon-512 is the only viable path forward.** OLD

Full results → [RESULTS.md](RESULTS.md)  
Graphs → [validation-time.png](validation-time.png) | [repo-size.png](repo-size.png)

## Reproducibility

This experiment is fully reproducible using Docker. All dependencies, data processing, and analysis are containerized.

### Quick Start

**Prerequisites:**
- Docker and Docker Compose installed
- ~ 15 GB free disk space (for RPKI data)

**Run the complete experiment:**
```bash
chmod +x reproduce.sh
./reproduce.sh
```

This will:
1. Build the Docker image with all dependencies
2. Fetch RPKI data from RIPE/APNIC repositories
3. Create a statistically representative subset (450,000 objects)
4. Re-sign with post-quantum algorithms (ML-DSA-44, Falcon-512)
5. Validate and generate scientific results

**Results will be in:**
- `RESULTS.md` - Comprehensive scientific report
- `results.csv` - Raw measurement data
- `results.json` - Detailed JSON with metadata
- `*.png` - Publication-quality visualizations
- `results.tex` - LaTeX table for papers

### Manual Docker Usage

```bash
# Build the image
docker compose build

# Run interactive shell
docker compose run --rm pq-rpki bash

# Or run individual steps
docker compose run --rm pq-rpki python3 /work/pq-resign.py
docker compose run --rm pq-rpki python3 /work/validate.py

# For interactive analysis (recommended):
docker compose run --rm -p 8888:8888 pq-rpki jupyter notebook --ip=0.0.0.0 --port=8888 --no-browser --allow-root
# Then open http://localhost:8888 in your browser and open results-analysis.ipynb

# Or for automated analysis (legacy):
docker compose run --rm pq-rpki python3 /work/results.py
```

See [WORKFLOW.md](WORKFLOW.md) for detailed workflow instructions.

### Data Directory Structure

```
data/
├── original/     # Full RPKI repository (downloaded from RIPE/APNIC)
├── subset/       # 450,000 object subset for testing
└── signed/       # Re-signed objects (by algorithm)
    ├── ecdsa-baseline/
    ├── dilithium2/
    └── falcon512/
```

### Dependencies

All dependencies are included in the Dockerfile:
- Python 3.12
- liboqs-python 0.14.1 (NIST post-quantum algorithms)
- matplotlib, pandas (analysis and visualization)
- rpki-client (validation)
- All system libraries

### Citation

If you use this dataset or code, please cite:

```bibtex
@software{pq_rpki_2025,
  author = {Moes, Sam},
  title = {Real-World Measurements of NIST Post-Quantum Signatures in RPKI},
  year = {2025},
  month = {December},
  version = {1.0.0},
  url = {https://github.com/daemon-tech/post-quantum-rpki}
}
```

See [CITATION.cff](CITATION.cff) for details.

### License

MIT License - See [LICENSE](LICENSE) file.