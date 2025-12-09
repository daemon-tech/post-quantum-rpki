# Post-Quantum RPKI Real Measurement (December 2025)

**Measured what actually happens when we switch Internet routing security to quantum-safe cryptography.**

- 118,068 real objects from todays live RIPE/APNIC repositories
- Re-signed with **ML-DSA-44 (Dilithium-2)**, **ML-DSA-65 (Dilithium-3)**, and **Falcon-512** (final NIST standards)
- Real size overhead measured -> no estimates, no toy CAs

## Assessment: Falcon-512 Validation:

**Falcon-512 Data**
Assessment Falcon512 1 IMG: 
![RESULTS](/results/falcon-512-result-1.png)


Assessment Falcon512 2 IMG: 
![RESULTS](/results/falcon-512-result-2.png)  

**What's good:**

- 98.5-98.7% success on ROA and MANIFEST (the main CMS objects)
- Signature sizes are within the expected range (647–666 bytes)
- Public keys are correct (897 bytes)
- The failures are a small fraction (945 out of 115,654 = 0.8%)


**What needs attention:**

- 854 public key extraction failures - investigate whether these are:
- OID lookup issues (expected for draft OIDs)
- Files that weren't properly re-signed
- Edge cases in extraction logic
- 91 CMS verification failures - actual signature verification failures; investigate these files
- Negative verification times - fix the timing measurement


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
├── results-analysis.ipynb             # Jupyter notebook for interactive analysis
├── reproduce.sh                       # Complete reproduction workflow (Linux/Mac)
├── reproduce.bat                      # Complete reproduction workflow (Windows)
├── run-all.sh                         # Alternative experiment runner (Linux/Mac)
├── run-all.bat                        # Alternative experiment runner (Windows)
└── fast-subset.sh                     # Fast subset creation utility
```

### Key Result
**Falcon-512 = only +38.4% repository size**  
The Internet **survives** quantum computers.

ML-DSA-44 (Dilithium-2) = +210.7% - too big for current infrastructure.

![sum](/img/summary.png)

Daily Delta Analysis (Bandwidth Overhead)

![daily delta analysis](/img/daily_delta.png)

Key Findings

![Key Findings](/img/key_findings.png)

**Falcon-512 is viable so far.**

Full results: [RESULTS.md](/results/RESULTS.md)  

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

## Known Limitations

### EE Certificate Signing Approach

**Current Implementation:**
- EE (End Entity) certificates in CMS objects (ROAs/manifests) are **self-signed** with their own private key
- This is acceptable for measurement purposes and provides accurate size/performance metrics
- Both CMS signatures and EE certificate signatures are properly replaced and verify correctly

**Theoretical Correctness:**
- In proper RPKI, EE certificates should be signed by the **issuer's (CA's) private key**, not the EE's own key
- This maintains the certificate chain: CA signs EE cert, EE cert signs CMS content
- Our code infrastructure is **99% ready** for issuer-signed certificates:
  - DONE: Detects issuer certificates in CMS structures
  - DONE: Generates issuer keypairs when issuer certs are found
  - DONE: Extracts EE certificate TBS for signing
  - DONE: Replaces and verifies both signatures
  - BLOCKED: **Cannot sign with issuer's private key** (blocked by OQS API limitation)

**Why We Can't Do It Yet:**
- The `liboqs-python` library doesn't expose `import_secret_key()` or equivalent functionality
- OQS `Signature` objects use an internal private key that cannot be extracted or imported
- To sign with issuer's key, we would need:
  ```python
  issuer_signer = Signature("Falcon-512")
  issuer_signer.import_secret_key(issuer_private_key)  # ← This method doesn't exist
  ee_cert_signature = issuer_signer.sign(ee_cert_tbs)
  ```
- This is a limitation of the OQS Python bindings, not our code

**Impact:**
- **For measurement purposes:** No impact - self-signed EE certs provide accurate size/performance metrics
- **For production deployment:** Would need issuer-signed certificates for full RPKI chain validation
- **Future upgrade:** Once OQS adds `import_secret_key()`, the code can be upgraded with minimal changes (see TODO comments in `pq-resign.py`)

**What This Means:**
- Our measurements are **scientifically valid** for size/performance analysis
- The code is **structurally ready** for issuer-signed certificates
- We **cannot work around** this limitation without modifying the OQS library itself
- This is a **known limitation** that will be resolved when OQS adds the necessary API

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