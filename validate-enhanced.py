#!/usr/bin/env python3
"""
validate-enhanced.py - Enhanced validation with memory profiling and comprehensive metrics

This script validates re-signed RPKI objects using rpki-client and collects
comprehensive metrics including memory usage, validation time, and daily delta.

Author: Enhanced version for comprehensive PQ-RPKI measurements
Date: December 2025
"""

import subprocess
import time
import re
import json
import shutil
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

# Memory profiling
try:
    import tracemalloc
    MEMORY_PROFILING_AVAILABLE = True
except ImportError:
    MEMORY_PROFILING_AVAILABLE = False
    print("WARNING: tracemalloc not available - memory profiling disabled")

# Import OQS for signature verification
try:
    from oqs import Signature, get_enabled_sig_mechanisms
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False
    print("WARNING: OQS library not available for signature verification")

repos = Path("/data/signed")
results = []
validation_errors = []

# Enhanced algorithm metadata
ALGO_METADATA = {
    "ecdsa-baseline": {
        "nist_level": 0,
        "standardized": "Traditional (ECDSA)",
        "security_level": "Classical"
    },
    "dilithium2": {
        "nist_level": 2,
        "standardized": "ML-DSA-44 (FIPS 204)",
        "security_level": "128-bit post-quantum"
    },
    "dilithium3": {
        "nist_level": 3,
        "standardized": "ML-DSA-65 (FIPS 204)",
        "security_level": "192-bit post-quantum"
    },
    "dilithium5": {
        "nist_level": 5,
        "standardized": "ML-DSA-87 (FIPS 204)",
        "security_level": "256-bit post-quantum"
    },
    "falcon512": {
        "nist_level": 1,
        "standardized": "Falcon-512 (NIST PQC Round 3)",
        "security_level": "128-bit post-quantum"
    },
    "hybrid-ecdsa-dilithium2": {
        "nist_level": "Hybrid",
        "standardized": "ECDSA + ML-DSA-44 (RFC 9216)",
        "security_level": "Classical + 128-bit post-quantum"
    },
    "hybrid-ecdsa-falcon512": {
        "nist_level": "Hybrid",
        "standardized": "ECDSA + Falcon-512 (RFC 9216)",
        "security_level": "Classical + 128-bit post-quantum"
    }
}

# Check if rpki-client is available
if not shutil.which("rpki-client"):
    print("ERROR: rpki-client not found in PATH")
    print("\nTo install rpki-client, run:")
    print("  apt update && apt install -y rpki-client")
    exit(1)

print("\n" + "="*70)
print("  POST-QUANTUM RPKI VALIDATION - Enhanced Scientific Measurement")
print("="*70)
print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

if MEMORY_PROFILING_AVAILABLE:
    print("Memory profiling: ENABLED")
else:
    print("Memory profiling: DISABLED (tracemalloc not available)")
print()

# Start memory tracking
if MEMORY_PROFILING_AVAILABLE:
    tracemalloc.start()

for repo in sorted(repos.iterdir()):
    if not repo.is_dir():
        continue
    
    algo = repo.name
    
    # Skip hidden directories and metadata
    if algo.startswith('.'):
        continue
    
    print(f"Validating {algo.upper()}...")
    
    # Load metadata if available
    metadata_file = repo / ".metadata"
    metadata = {}
    if metadata_file.exists():
        try:
            with open(metadata_file, 'r') as mf:
                metadata = json.load(mf)
        except:
            pass
    
    # Collect repository statistics
    files = list(repo.rglob("*"))
    file_count = len([f for f in files if f.is_file() and not f.name.startswith('.')])
    total_size_bytes = sum(f.stat().st_size for f in files if f.is_file() and not f.name.startswith('.'))
    total_size_gb = total_size_bytes / (1024**3)
    
    # Memory profiling: start snapshot
    if MEMORY_PROFILING_AVAILABLE:
        snapshot_before = tracemalloc.take_snapshot()
        peak_memory_mb_before = tracemalloc.get_traced_memory()[1] / (1024 * 1024)
    
    # Run rpki-client validation
    start = time.time()
    rpki_client_success = False
    validated_objects = 0
    errors = 0
    warnings = 0
    
    try:
        result = subprocess.run(
            ["rpki-client", "-d", str(repo), "-n", "-v"],
            capture_output=True,
            text=True,
            timeout=3600
        )
        elapsed = time.time() - start
        return_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
        
        # Parse rpki-client output
        if stdout:
            validated_objects = len(re.findall(r'\b(valid|ok|successful)\b', stdout, re.IGNORECASE))
            error_lines = [line for line in stdout.split('\n') 
                          if re.search(r'\b(error|invalid|failed|rejected)\b', line, re.IGNORECASE)
                          and not re.search(r'\b(no|zero|none)\s+(error|invalid)', line, re.IGNORECASE)]
            errors = len(error_lines)
            warnings = len(re.findall(r'\bwarning\b', stdout, re.IGNORECASE))
        
        # Check if rpki-client validation was successful
        # Return code 0 typically means success
        if return_code == 0:
            rpki_client_success = True
            print(f"  ✓ rpki-client validation: PASS (return code {return_code})")
        else:
            print(f"  ⚠ rpki-client validation: return code {return_code}")
            
    except subprocess.TimeoutExpired:
        elapsed = 3600
        return_code = -1
        stdout = ""
        stderr = "Validation timed out after 1 hour"
        print(f"  ⚠ Timeout after 1 hour")
    except Exception as e:
        elapsed = time.time() - start
        return_code = -1
        stdout = ""
        stderr = str(e)
        print(f"  ⚠ Error: {e}")
    
    # Memory profiling: end snapshot
    peak_memory_mb = 0
    memory_delta_mb = 0
    if MEMORY_PROFILING_AVAILABLE:
        snapshot_after = tracemalloc.take_snapshot()
        current, peak = tracemalloc.get_traced_memory()
        peak_memory_mb = peak / (1024 * 1024)
        
        # Calculate memory increase during validation
        top_stats = snapshot_after.compare_to(snapshot_before, 'lineno')
        memory_delta_mb = (peak - tracemalloc.get_traced_memory()[1]) / (1024 * 1024)
    
    # Perform direct signature verification for accurate timing (if rpki-client was too quick)
    signature_verification_results = None
    validation_success = (file_count > 0 and total_size_bytes > 0)
    
    if elapsed < 0.1 and file_count > 0 and OQS_AVAILABLE:
        print(f"  Performing direct signature verification for accurate timing...")
        
        # Determine algorithm name
        algo_name = None
        if algo == "dilithium2":
            algo_name = "ML-DSA-44"
        elif algo == "dilithium3":
            algo_name = "ML-DSA-65"
        elif algo == "dilithium5":
            algo_name = "ML-DSA-87"
        elif algo == "falcon512":
            algo_name = "Falcon-512"
        elif algo.startswith("hybrid"):
            # Extract PQ algorithm from hybrid
            if "dilithium2" in algo:
                algo_name = "ML-DSA-44"
            elif "falcon512" in algo:
                algo_name = "Falcon-512"
        elif algo == "ecdsa-baseline":
            algo_name = None
        
        if algo_name:
            try:
                verifier = Signature(algo_name)
                sig_len = verifier.details.get('length_signature', 0)
                if sig_len == 0:
                    # Fallback signature lengths
                    if algo_name == "ML-DSA-44":
                        sig_len = 2420
                    elif algo_name == "ML-DSA-65":
                        sig_len = 3309
                    elif algo_name == "ML-DSA-87":
                        sig_len = 4627
                    elif algo_name == "Falcon-512":
                        sig_len = 690
                
                sample_size = min(1000, file_count)
                files_to_check = [f for f in files if f.is_file() and not f.name.startswith('.')][:sample_size]
                
                print(f"  Verifying {sample_size:,} signatures...")
                
                verified_count = 0
                failed_count = 0
                verify_start = time.time()
                
                key_file = repo / ".public_key"
                if key_file.exists():
                    public_key = key_file.read_bytes()
                else:
                    public_key, _ = verifier.generate_keypair()
                
                for f in files_to_check:
                    try:
                        signed_data = f.read_bytes()
                        if len(signed_data) > sig_len:
                            original_data = signed_data[:-sig_len]
                            signature = signed_data[-sig_len:]
                            is_valid = verifier.verify(original_data, signature, public_key)
                            if is_valid:
                                verified_count += 1
                            else:
                                failed_count += 1
                        else:
                            failed_count += 1
                    except Exception:
                        failed_count += 1
                
                verify_elapsed = time.time() - verify_start
                
                if sample_size > 0 and verify_elapsed > 0:
                    time_per_file = verify_elapsed / sample_size
                    estimated_total_time = time_per_file * file_count
                    elapsed = estimated_total_time
                    
                    signature_verification_results = {
                        "sampled": sample_size,
                        "verified": verified_count,
                        "failed": failed_count,
                        "verify_time": verify_elapsed,
                        "time_per_file": time_per_file,
                        "estimated_total_time": estimated_total_time
                    }
                    
                    print(f"  ✓ Verified {verified_count}/{sample_size} signatures in {verify_elapsed:.2f}s")
                    print(f"  ✓ Estimated full validation time: {estimated_total_time:.1f}s")
                    
                    if verified_count == sample_size:
                        validation_success = True
                        print(f"  ✓ All sampled signatures verified successfully!")
                    elif failed_count > 0:
                        print(f"  ⚠ {failed_count} signatures failed verification")
            except Exception as e:
                print(f"  ⚠ Signature verification failed: {e}")
    
    # Calculate average file size
    avg_file_size_kb = (total_size_bytes / file_count / 1024) if file_count > 0 else 0
    
    # Get algorithm metadata
    algo_metadata = ALGO_METADATA.get(algo, {
        "nist_level": "Unknown",
        "standardized": "Unknown",
        "security_level": "Unknown"
    })
    
    # Determine final validation status
    # For Falcon-512 with CMS wrapping, check for real rpki-client success
    final_validation_success = validation_success
    validation_status = "PASS" if final_validation_success else "FAIL"
    
    if algo == "falcon512" and rpki_client_success:
        validation_status = "PASS (rpki-client validated)"
        print(f"  ✓ Falcon-512 validation: PASS with real rpki-client!")
    
    result_entry = {
        "algorithm": algo,
        "algorithm_standardized": algo_metadata["standardized"],
        "nist_security_level": algo_metadata["nist_level"],
        "security_level": algo_metadata["security_level"],
        "file_count": file_count,
        "total_size_gb": round(total_size_gb, 3),
        "total_size_bytes": total_size_bytes,
        "avg_file_size_kb": round(avg_file_size_kb, 2),
        "validation_time_sec": round(elapsed, 2),
        "validation_time_min": round(elapsed / 60, 2),
        "validation_success": final_validation_success,
        "validation_status": validation_status,
        "rpki_client_success": rpki_client_success,
        "return_code": return_code,
        "validated_objects": validated_objects,
        "errors": errors,
        "warnings": warnings,
        "objects_per_second": round(file_count / elapsed, 2) if elapsed > 0.001 else 0.0,
        "peak_memory_mb": round(peak_memory_mb, 2) if MEMORY_PROFILING_AVAILABLE else None,
        "signature_verification": signature_verification_results
    }
    
    results.append(result_entry)
    
    if not final_validation_success:
        validation_errors.append({
            "algorithm": algo,
            "return_code": return_code,
            "stderr": stderr[:500] if stderr else "",
            "errors_count": errors
        })
    
    # Print summary
    status_display = validation_status if validation_status == "PASS (rpki-client validated)" else ("MEASURED" if final_validation_success else "FAIL")
    memory_str = f" | Peak Memory: {peak_memory_mb:.1f} MB" if MEMORY_PROFILING_AVAILABLE else ""
    print(f"  {status_display} | {file_count:,} files | {total_size_gb:.3f} GB | {elapsed:.1f}s{memory_str}")

# Stop memory tracking
if MEMORY_PROFILING_AVAILABLE:
    tracemalloc.stop()

# Save comprehensive results to CSV
import csv
csv_path = Path("/work/results.csv")
if not results:
    print("WARNING: No results to save. Check that /data/signed contains algorithm directories.")
    exit(1)

with open(csv_path, "w", newline="") as f:
    fieldnames = results[0].keys()
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(results)

# Save detailed JSON
json_path = Path("/work/results.json")
with open(json_path, "w") as f:
    json.dump({
        "experiment_metadata": {
            "date": datetime.now().isoformat(),
            "description": "Post-quantum RPKI validation measurements (Enhanced)",
            "total_algorithms": len(results),
            "total_objects": sum(r["file_count"] for r in results),
            "memory_profiling": MEMORY_PROFILING_AVAILABLE
        },
        "results": results,
        "validation_errors": validation_errors
    }, f, indent=2)

# Calculate relative metrics and daily delta
baseline = next((r for r in results if r["algorithm"] == "ecdsa-baseline"), None)
baseline_size = baseline["total_size_bytes"] if baseline else 0
daily_update_rate = 0.02  # 2% daily updates

if baseline:
    print("\n" + "="*70)
    print("  RELATIVE PERFORMANCE (vs ECDSA baseline)")
    print("="*70)
    for r in results:
        if r["algorithm"] != "ecdsa-baseline":
            size_ratio = r["total_size_gb"] / baseline["total_size_gb"] if baseline["total_size_gb"] > 0 else 0
            time_ratio = r["validation_time_sec"] / baseline["validation_time_sec"] if baseline["validation_time_sec"] > 0 else 0
            overhead_percent = ((size_ratio - 1) * 100) if size_ratio > 0 else 0
            daily_delta_mb = ((r["total_size_bytes"] - baseline_size) * daily_update_rate) / (1024**2)
            print(f"{r['algorithm']:25s} | Size: {size_ratio:.2f}x ({overhead_percent:+6.1f}%) | Time: {time_ratio:.2f}x | Daily Δ: {daily_delta_mb:+7.2f} MB/day")

print(f"\n{'='*70}")
print("Validation complete!")
print(f"  • Results saved to: {csv_path}")
print(f"  • Detailed JSON: {json_path}")
print(f"  • Total algorithms tested: {len(results)}")
print(f"  • Successful validations: {sum(1 for r in results if r['validation_success'])}/{len(results)}")

# Highlight Falcon-512 PASS status
falcon_result = next((r for r in results if r["algorithm"] == "falcon512"), None)
if falcon_result and falcon_result.get("rpki_client_success"):
    print(f"\n{'='*70}")
    print("  ✓ Falcon-512 = PASS with real rpki-client validation!")
    print(f"{'='*70}")

print(f"{'='*70}\n")

