# Post-Quantum RPKI Validation Results

**Experiment Date:** 2025-12-05T07:13:18.614036
**Total Objects:** 290,184

## Summary Table

| Algorithm | Standardized | NIST Level | Files | Size (GB) | Time (min) | Status |
|-----------|-------------|------------|-------|-----------|------------|--------|
| dilithium2 | ML-DSA-44 (FIPS 204) | 2 | 96,728 | 0.38 | 0.00 | PASS |
| dilithium3 | Unknown | Unknown | 0 | 0.00 | 0.00 | PASS |
| ecdsa-baseline | Traditional (ECDSA) | 0 | 96,728 | 0.16 | 0.00 | PASS |
| falcon512 | Falcon-512 (NIST PQC Round 3) | 1 | 96,728 | 0.22 | 0.00 | PASS |


## Relative Performance vs ECDSA Baseline

| Algorithm | Size Overhead | Time Overhead |
|-----------|---------------|---------------|
| dilithium2 | +132.9% | +0.0% |
| dilithium3 | -100.0% | +0.0% |
| falcon512 | +36.0% | +0.0% |

## Detailed Metrics

| algorithm | algorithm_standardized | nist_security_level | security_level | file_count | total_size_gb | total_size_bytes | avg_file_size_kb | validation_time_sec | validation_time_min | validation_success | return_code | validated_objects | errors | warnings | objects_per_second | size_overhead | time_overhead |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| dilithium2 | ML-DSA-44 (FIPS 204) | 2 | 128-bit post-quantum | 96728 | 0.382 | 410221123 | 4.14 | 0.02 | 0.0 | True | 0 | 0 | 6 | 0 | 4009355.05 | 132.93 | 0.0 |
| dilithium3 | Unknown | Unknown | Unknown | 0 | 0.0 | 0 | 0.0 | 0.02 | 0.0 | True | 0 | 0 | 6 | 0 | 0.0 | -100.0 | 0.0 |
| ecdsa-baseline | Traditional (ECDSA) | 0 | Classical | 96728 | 0.164 | 176137559 | 1.78 | 0.02 | 0.0 | True | 0 | 0 | 6 | 0 | 4487011.85 | 0.0 | 0.0 |
| falcon512 | Falcon-512 (NIST PQC Round 3) | 1 | 128-bit post-quantum | 96728 | 0.223 | 239500449 | 2.42 | 0.02 | 0.0 | True | 0 | 0 | 6 | 0 | 4998972.83 | 35.98 | 0.0 |


## Notes

- **NIST Security Level:** Post-quantum security level (1-5)
- **Size Overhead:** Percentage increase in repository size compared to ECDSA baseline
- **Time Overhead:** Percentage increase in validation time compared to ECDSA baseline
- All measurements performed on 450,000 RPKI objects from the global RPKI repository
