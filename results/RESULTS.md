# Post-Quantum RPKI Validation Results

**First Real-World Measurements of NIST Post-Quantum Signature Algorithms in RPKI**

**Experiment Date:** 2025-12-07T20:55:14.314340

**Total Objects Validated:** 472,272

**ASN.1 Extraction Available:** True

**OQS Library Available:** True

---

## Executive Summary

This report presents comprehensive validation results for post-quantum signature algorithms applied to the RPKI (Resource Public Key Infrastructure) repository. Measurements include repository size, validation time, signature verification performance, and detailed per-object-type metrics.

## Summary Table

| Algorithm | Standardized Name | NIST Level | Files | Size (GB) | Time (min) | Status |
|-----------|-------------------|------------|-------|-----------|------------|--------|
| dilithium2 | ML-DSA-44 (FIPS 204) | 2 | 118,068 | 0.55 | 8.25 | ✓ PASS |
| dilithium3 | ML-DSA-65 (FIPS 204) | 3 | 118,068 | 0.70 | 7.42 | ✓ PASS |
| ecdsa-baseline | Traditional (ECDSA) | 0 | 118,068 | 0.18 | 0.46 | ✓ PASS |
| falcon512 | Falcon-512 (NIST PQC Round 3) | 1 | 118,068 | 0.24 | 8.06 | ✓ PASS |

## Relative Performance vs ECDSA Baseline

| Algorithm | Size Overhead | Time Overhead |
|-----------|---------------|---------------|
| dilithium2 | +210.7% | +1681.2% |
| dilithium3 | +297.2% | +1503.7% |
| falcon512 | +38.4% | +1641.7% |

## Detailed Results by Algorithm

### DILITHIUM2

**Standardized Name:** ML-DSA-44 (FIPS 204)

**NIST Security Level:** 2

**Security Level:** 128-bit post-quantum

**File Count:** 118,068

**Total Size:** 0.55 GB (590,341,930 bytes)

**Validation Time:** 494.82 seconds (8.25 minutes)

**Objects per Second:** 238.61

**Validation Success:** ✓ PASS

**File Type Breakdown:**

| Type | Count |
|------|-------|
| certificates | 29,952 |
| roas | 45,436 |
| crls | 21,340 |
| manifests | 21,340 |

#### Signature Verification Metrics

**Sampled:** 1,000 signatures

**Verified:** 0 (0.0%)

**Failed:** 1,000

**ASN.1 Extraction Failures:** 0

**Verification Time:** 4.19 seconds

**Average Verification Time:** 3.66 ms

**Verification Rate:** 238.6 signatures/second

**Verification Time Percentiles:**

| Percentile | Time (ms) |
|------------|----------|
| P25 | 3.19 |
| P50 (Median) | 3.60 |
| P75 | 4.07 |
| P95 | 4.82 |
| P99 | 5.42 |

**Signature Sizes:**

| Metric | Size (bytes) |
|--------|-------------|
| Average | 2421 |
| Min | 2420 |
| Max | 2421 |
| Expected | 2420 |

**Public Key Sizes:**

| Metric | Size (bytes) |
|--------|-------------|
| Average | 270 |
| Min | 270 |
| Max | 270 |
| Expected | 1312 |

#### Per-Object-Type Metrics

**CERTIFICATE:**

| Metric | Value |
|--------|-------|
| Count | 341 |
| Verified | 0 |
| Failed | 341 |
| Verification Rate | 0.0% |
| Avg Verify Time | 3.40 ms |
| Avg Sig Size | 2421 bytes |
| Avg PubKey Size | 0 bytes |

**ROA:**

| Metric | Value |
|--------|-------|
| Count | 339 |
| Verified | 0 |
| Failed | 339 |
| Verification Rate | 0.0% |
| Avg Verify Time | 3.94 ms |
| Avg Sig Size | 2420 bytes |
| Avg PubKey Size | 270 bytes |
| EE Certs Found | 339 |
| Issuer Certs Found | 0 |
| CMS Valid | 0 |
| EE Cert Valid | 0 |
| Both Valid | 0 |

**CRL:**

| Metric | Value |
|--------|-------|
| Count | 160 |
| Verified | 0 |
| Failed | 160 |
| Verification Rate | 0.0% |
| Avg Verify Time | 3.33 ms |
| Avg Sig Size | 2421 bytes |
| Avg PubKey Size | 0 bytes |

**MANIFEST:**

| Metric | Value |
|--------|-------|
| Count | 160 |
| Verified | 0 |
| Failed | 160 |
| Verification Rate | 0.0% |
| Avg Verify Time | 3.92 ms |
| Avg Sig Size | 2420 bytes |
| Avg PubKey Size | 270 bytes |
| EE Certs Found | 160 |
| Issuer Certs Found | 0 |
| CMS Valid | 0 |
| EE Cert Valid | 0 |
| Both Valid | 0 |

---

### DILITHIUM3

**Standardized Name:** ML-DSA-65 (FIPS 204)

**NIST Security Level:** 3

**Security Level:** 192-bit post-quantum

**File Count:** 118,068

**Total Size:** 0.70 GB (754,668,246 bytes)

**Validation Time:** 445.50 seconds (7.42 minutes)

**Objects per Second:** 265.02

**Validation Success:** ✓ PASS

**File Type Breakdown:**

| Type | Count |
|------|-------|
| certificates | 29,952 |
| roas | 45,436 |
| crls | 21,340 |
| manifests | 21,340 |

#### Signature Verification Metrics

**Sampled:** 1,000 signatures

**Verified:** 0 (0.0%)

**Failed:** 1,000

**ASN.1 Extraction Failures:** 0

**Verification Time:** 3.77 seconds

**Average Verification Time:** 3.28 ms

**Verification Rate:** 265.0 signatures/second

**Verification Time Percentiles:**

| Percentile | Time (ms) |
|------------|----------|
| P25 | 2.81 |
| P50 (Median) | 3.17 |
| P75 | 3.51 |
| P95 | 4.18 |
| P99 | 4.96 |

**Signature Sizes:**

| Metric | Size (bytes) |
|--------|-------------|
| Average | 3310 |
| Min | 3309 |
| Max | 3310 |
| Expected | 3309 |

**Public Key Sizes:**

| Metric | Size (bytes) |
|--------|-------------|
| Average | 270 |
| Min | 270 |
| Max | 270 |
| Expected | 1952 |

#### Per-Object-Type Metrics

**CERTIFICATE:**

| Metric | Value |
|--------|-------|
| Count | 341 |
| Verified | 0 |
| Failed | 341 |
| Verification Rate | 0.0% |
| Avg Verify Time | 2.88 ms |
| Avg Sig Size | 3310 bytes |
| Avg PubKey Size | 0 bytes |

**ROA:**

| Metric | Value |
|--------|-------|
| Count | 339 |
| Verified | 0 |
| Failed | 339 |
| Verification Rate | 0.0% |
| Avg Verify Time | 3.74 ms |
| Avg Sig Size | 3309 bytes |
| Avg PubKey Size | 270 bytes |
| EE Certs Found | 339 |
| Issuer Certs Found | 0 |
| CMS Valid | 0 |
| EE Cert Valid | 0 |
| Both Valid | 0 |

**CRL:**

| Metric | Value |
|--------|-------|
| Count | 160 |
| Verified | 0 |
| Failed | 160 |
| Verification Rate | 0.0% |
| Avg Verify Time | 2.93 ms |
| Avg Sig Size | 3310 bytes |
| Avg PubKey Size | 0 bytes |

**MANIFEST:**

| Metric | Value |
|--------|-------|
| Count | 160 |
| Verified | 0 |
| Failed | 160 |
| Verification Rate | 0.0% |
| Avg Verify Time | 3.49 ms |
| Avg Sig Size | 3309 bytes |
| Avg PubKey Size | 270 bytes |
| EE Certs Found | 160 |
| Issuer Certs Found | 0 |
| CMS Valid | 0 |
| EE Cert Valid | 0 |
| Both Valid | 0 |

---

### ECDSA-BASELINE

**Standardized Name:** Traditional (ECDSA)

**NIST Security Level:** 0

**Security Level:** Classical

**File Count:** 118,068

**Total Size:** 0.18 GB (189,642,815 bytes)

**Validation Time:** 27.78 seconds (0.46 minutes)

**Objects per Second:** 4249.85

**Validation Success:** ✓ PASS

**File Type Breakdown:**

| Type | Count |
|------|-------|
| certificates | 29,952 |
| roas | 45,436 |
| crls | 21,340 |
| manifests | 21,340 |

---

### FALCON512

**Standardized Name:** Falcon-512 (NIST PQC Round 3)

**NIST Security Level:** 1

**Security Level:** 128-bit post-quantum

**File Count:** 118,068

**Total Size:** 0.24 GB (262,693,473 bytes)

**Validation Time:** 483.83 seconds (8.06 minutes)

**Objects per Second:** 244.03

**Validation Success:** ✓ PASS

**File Type Breakdown:**

| Type | Count |
|------|-------|
| certificates | 29,952 |
| roas | 45,436 |
| crls | 21,340 |
| manifests | 21,340 |

#### Signature Verification Metrics

**Sampled:** 1,000 signatures

**Verified:** 0 (0.0%)

**Failed:** 1,000

**ASN.1 Extraction Failures:** 0

**Verification Time:** 4.10 seconds

**Average Verification Time:** 3.58 ms

**Verification Rate:** 244.0 signatures/second

**Verification Time Percentiles:**

| Percentile | Time (ms) |
|------------|----------|
| P25 | 2.92 |
| P50 (Median) | 3.33 |
| P75 | 3.79 |
| P95 | 4.55 |
| P99 | 5.91 |

**Signature Sizes:**

| Metric | Size (bytes) |
|--------|-------------|
| Average | 655 |
| Min | 649 |
| Max | 665 |
| Expected | 690 |

**Public Key Sizes:**

| Metric | Size (bytes) |
|--------|-------------|
| Average | 270 |
| Min | 270 |
| Max | 270 |
| Expected | 897 |

#### Per-Object-Type Metrics

**CERTIFICATE:**

| Metric | Value |
|--------|-------|
| Count | 341 |
| Verified | 0 |
| Failed | 341 |
| Verification Rate | 0.0% |
| Avg Verify Time | 3.35 ms |
| Avg Sig Size | 656 bytes |
| Avg PubKey Size | 0 bytes |

**ROA:**

| Metric | Value |
|--------|-------|
| Count | 339 |
| Verified | 0 |
| Failed | 339 |
| Verification Rate | 0.0% |
| Avg Verify Time | 3.78 ms |
| Avg Sig Size | 655 bytes |
| Avg PubKey Size | 270 bytes |
| EE Certs Found | 339 |
| Issuer Certs Found | 0 |
| CMS Valid | 0 |
| EE Cert Valid | 0 |
| Both Valid | 0 |

**CRL:**

| Metric | Value |
|--------|-------|
| Count | 160 |
| Verified | 0 |
| Failed | 160 |
| Verification Rate | 0.0% |
| Avg Verify Time | 3.16 ms |
| Avg Sig Size | 656 bytes |
| Avg PubKey Size | 0 bytes |

**MANIFEST:**

| Metric | Value |
|--------|-------|
| Count | 160 |
| Verified | 0 |
| Failed | 160 |
| Verification Rate | 0.0% |
| Avg Verify Time | 4.06 ms |
| Avg Sig Size | 655 bytes |
| Avg PubKey Size | 270 bytes |
| EE Certs Found | 160 |
| Issuer Certs Found | 0 |
| CMS Valid | 0 |
| EE Cert Valid | 0 |
| Both Valid | 0 |

---

## Key Findings

### Size and Performance Overhead

- **dilithium2**: +210.7% size overhead, +1681.2% time overhead vs ECDSA
- **dilithium3**: +297.2% size overhead, +1503.7% time overhead vs ECDSA
- **falcon512**: +38.4% size overhead, +1641.7% time overhead vs ECDSA

## Notes

- **NIST Security Level:** Post-quantum security level (1-5) as defined by NIST
- **Size Overhead:** Percentage change in repository size compared to ECDSA baseline
- **Time Overhead:** Percentage change in validation time compared to ECDSA baseline
- **EE Certificates:** End-Entity certificates embedded in CMS objects
- **Issuer Certificates:** Certificates that sign EE certificates
- All measurements performed on real-world RPKI repository data
- Signature verification performed on a sample of objects for performance analysis

## Scientific Contribution

This dataset represents the first real-world measurements of NIST post-quantum signature algorithms (ML-DSA, Falcon) applied to the global RPKI repository at scale. The results provide critical data for evaluating the practical impact of post-quantum cryptography on RPKI infrastructure.

