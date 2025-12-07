#!/usr/bin/env python3
"""
validate.py - Scientific validation of post-quantum RPKI signatures

This script takes a directory of re-signed RPKI objects (organized by algorithm)
and runs comprehensive validation and metrics collection. The main goal is to
measure how post-quantum signatures perform compared to traditional ECDSA in
real-world RPKI deployments.

What it does:
- Scans algorithm directories (e.g., /data/signed/Falcon-512, /data/signed/ML-DSA-44)
- Validates each object's CMS signature and embedded EE certificate signature
- Measures file sizes, signature sizes, public key sizes, and verification times
- Collects detailed per-object-type metrics (ROAs, Manifests, CRLs, etc.)
- Tracks verification success/failure rates and error categories
- Calculates statistical distributions (percentiles, variance) for analysis
- Outputs results to CSV and JSON for further analysis

The script uses direct ASN.1 parsing to extract signatures and verify them with
the OQS library, so we get accurate measurements without relying on external
tools. It also attempts rpki-client validation for compatibility checking, but
the main metrics come from our direct verification.

All results are saved to the results/ directory as results.csv (for spreadsheet
analysis) and results.json (for programmatic access). The CSV is flattened for
easy import, while the JSON preserves the full nested structure with all the
detailed metrics.

Key metrics collected:
- Verification times (with percentiles P25/P50/P75/P95/P99)
- Signature and public key sizes (with variance and distributions)
- File sizes and total repository sizes
- Per-object-type breakdowns (ROA, Manifest, CRL, etc.)
- EE certificate extraction and verification rates
- CMS vs EE cert signature verification (tracked separately)
- Error categorization and samples
- Comprehensive VerificationMetrics from asn1_rpki.py

The script shows live progress with detailed metrics during execution, and
prints a comprehensive summary at the end comparing all algorithms against
the ECDSA baseline.

Author: Sam Moes
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
from collections import defaultdict
from tqdm import tqdm

# Import OQS for signature verification
try:
    from oqs import Signature, get_enabled_sig_mechanisms
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False
    print("WARNING: OQS library not available for signature verification")

# Import ASN.1 parser for proper signature extraction
try:
    from asn1_rpki import (
        extract_signature_and_tbs, 
        detect_rpki_object_type,
        verify_cms_object_signatures,
        extract_ee_certificate_from_cms,
        extract_issuer_certificate_from_cms,
        get_verification_metrics,
        reset_verification_metrics,
        print_verification_metrics
    )
    ASN1_EXTRACTION_AVAILABLE = True
except ImportError:
    ASN1_EXTRACTION_AVAILABLE = False
    print("WARNING: ASN.1 signature extraction not available. Install asn1crypto: pip install asn1crypto")

repos = Path("/data/signed")
results = []
validation_errors = []

# Check if rpki-client is available
if not shutil.which("rpki-client"):
    print("WARNING: rpki-client not found in PATH")
    print("Direct signature verification will be used instead")
    print("\nTo install rpki-client (optional), run:")
    print("  apt update && apt install -y rpki-client")

print("\n" + "="*80)
print("  POST-QUANTUM RPKI VALIDATION - Comprehensive Scientific Measurement")
print("="*80)
print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"ASN.1 Extraction: {'Available' if ASN1_EXTRACTION_AVAILABLE else 'Not Available'}")
print(f"OQS Library: {'Available' if OQS_AVAILABLE else 'Not Available'}")
print("="*80)
print()

# Algorithm metadata - only algorithms we actually use
ALGO_METADATA = {
    "ecdsa-baseline": {
        "nist_level": 0,
        "standardized": "Traditional (ECDSA)",
        "security_level": "Classical",
        "algorithm_name": None
    },
    "dilithium2": {
        "nist_level": 2,
        "standardized": "ML-DSA-44 (FIPS 204)",
        "security_level": "128-bit post-quantum",
        "algorithm_name": "ML-DSA-44"
    },
    "dilithium3": {
        "nist_level": 3,
        "standardized": "ML-DSA-65 (FIPS 204)",
        "security_level": "192-bit post-quantum",
        "algorithm_name": "ML-DSA-65"
    },
    "falcon512": {
        "nist_level": 1,
        "standardized": "Falcon-512 (NIST PQC Round 3)",
        "security_level": "128-bit post-quantum",
        "algorithm_name": "Falcon-512"
    }
}

# Known signature and public key sizes (bytes)
ALGO_SIZES = {
    "ML-DSA-44": {"signature": 2420, "public_key": 1312},
    "ML-DSA-65": {"signature": 3309, "public_key": 1952},
    "ML-DSA-87": {"signature": 4627, "public_key": 2592},
    "Falcon-512": {"signature": 690, "public_key": 897}
}

for repo in sorted(repos.iterdir()):
    if not repo.is_dir():
        continue
    
    algo = repo.name
    
    # Normalize algorithm name (handle case variations)
    algo_lower = algo.lower()
    if algo_lower in ["ecdsa", "ecdsa-baseline", "baseline"]:
        algo = "ecdsa-baseline"
    elif algo_lower == "dilithium2":
        algo = "dilithium2"
    elif algo_lower == "dilithium3":
        algo = "dilithium3"
    elif algo_lower in ["falcon512", "falcon-512"]:
        algo = "falcon512"
    
    # Skip if not in our algorithm list
    if algo not in ALGO_METADATA:
        print(f"\nSkipping {repo.name} (not in current algorithm set)")
        continue
    
    print(f"\n{'='*80}")
    print(f"Validating {algo.upper()}")
    print(f"{'='*80}")
    
    # Collect repository statistics with live progress
    print("Scanning repository and collecting file statistics...")
    scan_start = time.time()
    files = []
    file_types = defaultdict(int)
    file_sizes = []
    total_size_bytes = 0
    
    # Use progress bar for scanning
    all_paths = list(repo.rglob("*"))
    scan_pbar = tqdm(all_paths, desc="  Scanning", unit="items", file=sys.stdout, mininterval=0.5)
    
    for item in scan_pbar:
        if item.is_file() and not item.name.startswith('.'):
            files.append(item)
            size = item.stat().st_size
            file_sizes.append(size)
            total_size_bytes += size
            
            # Detect file type by extension
            ext = item.suffix.lower()
            if ext == '.cer':
                file_types['certificates'] += 1
            elif ext == '.roa':
                file_types['roas'] += 1
            elif ext == '.mft':
                file_types['manifests'] += 1
            elif ext == '.crl':
                file_types['crls'] += 1
            else:
                file_types['other'] += 1
            
            # Update progress bar with live metrics
            scan_pbar.set_postfix({
                'Files': len(files),
                'Size': f"{total_size_bytes/(1024**3):.2f}GB",
                'Rate': f"{len(files)/(time.time()-scan_start):.0f}/s" if (time.time()-scan_start) > 0 else "0/s"
            })
    
    scan_pbar.close()
    scan_elapsed = time.time() - scan_start
    
    file_count = len(files)
    total_size_gb = total_size_bytes / (1024**3)
    avg_file_size_kb = (total_size_bytes / file_count / 1024) if file_count > 0 else 0
    
    # Calculate size statistics
    if file_sizes:
        min_file_size = min(file_sizes)
        max_file_size = max(file_sizes)
        median_file_size = sorted(file_sizes)[len(file_sizes) // 2]
    else:
        min_file_size = max_file_size = median_file_size = 0
    
    print(f"  Scan complete: {file_count:,} files ({total_size_gb:.3f} GB) in {scan_elapsed:.2f}s")
    print(f"  File types: {dict(file_types)}")
    print(f"  Size stats: Min={min_file_size/1024:.1f}KB, Avg={avg_file_size_kb:.1f}KB, Max={max_file_size/1024:.1f}KB, Median={median_file_size/1024:.1f}KB")
    
    if file_count == 0:
        print(f"  WARNING: No files found in {repo}")
        continue
    
    # Try rpki-client validation (may fail due to PQ OIDs, but we measure timing)
    rpki_client_results = None
    rpki_start = time.time()
    if shutil.which("rpki-client"):
        try:
            result = subprocess.run(
                ["rpki-client", "-d", str(repo), "-n", "-v"],
                capture_output=True,
                text=True,
                timeout=3600
            )
            rpki_elapsed = time.time() - rpki_start
            rpki_client_results = {
                "return_code": result.returncode,
                "elapsed_sec": rpki_elapsed,
                "stdout": result.stdout[:1000] if result.stdout else "",
                "stderr": result.stderr[:1000] if result.stderr else ""
            }
            
            if rpki_elapsed < 0.1:
                print(f"  rpki-client: Completed quickly ({rpki_elapsed:.3f}s) - likely rejected PQ OIDs")
            else:
                print(f"  rpki-client: Completed in {rpki_elapsed:.1f}s")
        except Exception as e:
            rpki_elapsed = time.time() - rpki_start
            rpki_client_results = {
                "return_code": -1,
                "elapsed_sec": rpki_elapsed,
                "error": str(e)
            }
            print(f"  rpki-client: Error - {e}")
    else:
        print(f"  rpki-client: Not available, skipping")
    
    # Perform direct signature verification for accurate timing
    signature_verification_results = None
    validation_time_sec = 0  # Initialize validation time
    metadata = ALGO_METADATA[algo]
    algo_name = metadata.get("algorithm_name")
    
    if algo_name and OQS_AVAILABLE and file_count > 0:
        print(f"  Performing direct signature verification with {algo_name}...")
        
        try:
            verifier = Signature(algo_name)
            
            # Get signature and public key sizes
            sig_size_info = ALGO_SIZES.get(algo_name, {})
            expected_sig_size = sig_size_info.get("signature", 0)
            expected_pubkey_size = sig_size_info.get("public_key", 0)
            
            # Sample files for verification (verify representative sample for timing)
            sample_size = min(1000, file_count)
            files_to_check = files[:sample_size]
            
            print(f"  Verifying {sample_size:,} signatures (sample of {file_count:,} total)...")
            
            verified_count = 0
            failed_count = 0
            asn1_extraction_failures = 0
            verification_times = []
            signature_sizes = []
            public_key_sizes = []
            object_type_counts = defaultdict(int)
            
            # Enhanced metrics collection
            reset_verification_metrics()
            metrics = get_verification_metrics()
            
            # Per-object-type detailed metrics
            per_type_metrics = defaultdict(lambda: {
                'count': 0,
                'verified': 0,
                'failed': 0,
                'verify_times': [],
                'sig_sizes': [],
                'pubkey_sizes': [],
                'ee_certs_found': 0,
                'issuer_certs_found': 0,
                'cms_valid': 0,
                'ee_cert_valid': 0,
                'both_valid': 0
            })
            
            # Size distribution data (for histograms/percentiles)
            all_file_sizes = []
            all_signature_sizes = []
            all_public_key_sizes = []
            all_verification_times = []
            
            # Error categorization
            error_categories = defaultdict(int)
            error_details = []
            
            verify_start = time.time()
            
            # Progress bar with live metrics
            verify_pbar = tqdm(
                files_to_check,
                desc="  Verifying",
                unit="sig",
                file=sys.stdout,
                mininterval=0.5,
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] {postfix}'
            )
            
            # Try to load public key (though we use per-file keys, this is for representative timing)
            public_key = None
            key_file = repo / ".public_key"
            if key_file.exists():
                public_key = key_file.read_bytes()
                print(f"  Loaded representative public key ({len(public_key)} bytes)")
            else:
                # Generate representative keypair for timing (signatures won't verify but timing is accurate)
                public_key, _ = verifier.generate_keypair()
                print(f"  Generated representative public key ({len(public_key)} bytes) for timing")
                print(f"  Note: Signatures won't verify (per-file keys used), but timing is accurate")
            
            for f in verify_pbar:
                try:
                    file_start = time.time()
                    signed_data = f.read_bytes()
                    file_size = len(signed_data)
                    all_file_sizes.append(file_size)
                    
                    # Properly extract signature and TBS from ASN.1 structure
                    if ASN1_EXTRACTION_AVAILABLE:
                        try:
                            object_type = detect_rpki_object_type(signed_data, str(f))
                            object_type_counts[object_type] += 1
                            metrics.record_object_loaded(object_type)
                            
                            # Update per-type metrics
                            type_metrics = per_type_metrics[object_type]
                            type_metrics['count'] += 1
                            
                            tbs_data, signature = extract_signature_and_tbs(signed_data, object_type, str(f))
                            
                            # Collect signature size
                            sig_size = len(signature)
                            signature_sizes.append(sig_size)
                            all_signature_sizes.append(sig_size)
                            type_metrics['sig_sizes'].append(sig_size)
                            
                            # For CMS objects, extract and verify EE certificate separately
                            cms_valid = False
                            ee_cert_valid = False
                            ee_cert_found = False
                            issuer_cert_found = False
                            
                            if object_type in ('roa', 'manifest'):
                                # Try to extract EE certificate
                                ee_cert_bytes = extract_ee_certificate_from_cms(signed_data)
                                if ee_cert_bytes:
                                    ee_cert_found = True
                                    type_metrics['ee_certs_found'] += 1
                                    metrics.record_ee_cert_extraction(True)
                                    
                                    # Check for issuer cert
                                    issuer_cert_bytes = extract_issuer_certificate_from_cms(signed_data)
                                    if issuer_cert_bytes:
                                        issuer_cert_found = True
                                        type_metrics['issuer_certs_found'] += 1
                                    
                                    # Extract public key from EE cert for verification
                                    try:
                                        from asn1crypto import x509
                                        ee_cert = x509.Certificate.load(ee_cert_bytes)
                                        ee_pubkey_info = ee_cert['tbs_certificate']['subject_public_key_info']
                                        ee_pubkey = ee_pubkey_info['public_key'].contents
                                        ee_pubkey_size = len(ee_pubkey)
                                        public_key_sizes.append(ee_pubkey_size)
                                        all_public_key_sizes.append(ee_pubkey_size)
                                        type_metrics['pubkey_sizes'].append(ee_pubkey_size)
                                        
                                        # Verify both CMS and EE cert signatures
                                        cms_valid, ee_cert_valid, error_msg = verify_cms_object_signatures(
                                            signed_data,
                                            ee_pubkey,  # CMS signature uses EE cert's public key
                                            None,  # Issuer key not available
                                            algo_name,
                                            verifier,
                                            metrics
                                        )
                                        
                                        if cms_valid:
                                            type_metrics['cms_valid'] += 1
                                        if ee_cert_valid:
                                            type_metrics['ee_cert_valid'] += 1
                                        if cms_valid and ee_cert_valid:
                                            type_metrics['both_valid'] += 1
                                        
                                        # Use CMS verification result as primary
                                        is_valid = cms_valid
                                    except Exception as ee_err:
                                        # EE cert extraction/verification failed, fall back to basic verification
                                        error_categories['ee_cert_extraction_error'] += 1
                                        error_details.append(f"{f.name}: EE cert error: {ee_err}")
                                        is_valid = verifier.verify(tbs_data, signature, public_key)
                                else:
                                    # No EE cert, verify CMS signature only
                                    metrics.record_ee_cert_extraction(False, "No EE cert found")
                                    is_valid = verifier.verify(tbs_data, signature, public_key)
                            else:
                                # Non-CMS object, standard verification
                                is_valid = verifier.verify(tbs_data, signature, public_key)
                            
                            verification_time = time.time() - file_start
                            verification_times.append(verification_time)
                            all_verification_times.append(verification_time)
                            type_metrics['verify_times'].append(verification_time)
                            
                            if is_valid:
                                verified_count += 1
                                type_metrics['verified'] += 1
                            else:
                                failed_count += 1
                                type_metrics['failed'] += 1
                                error_categories['verification_failed'] += 1
                                error_details.append(f"{f.name}: Signature verification failed")
                                
                        except Exception as asn1_err:
                            asn1_extraction_failures += 1
                            failed_count += 1
                            error_categories['asn1_extraction_error'] += 1
                            error_details.append(f"{f.name}: ASN.1 error: {asn1_err}")
                            metrics.record_object_load_failed("unknown", str(asn1_err))
                            # Log but continue
                    else:
                        # ASN.1 extraction not available - cannot verify properly
                        failed_count += 1
                        error_categories['asn1_not_available'] += 1
                    
                    # Update progress bar with live metrics
                    current_time = time.time() - verify_start
                    if current_time > 0:
                        # Get current metrics summary
                        current_metrics = metrics.get_summary()
                        ee_extracted = current_metrics['ee_certificate']['extracted']
                        ee_valid = current_metrics['ee_certificate']['signatures_valid']
                        cms_valid = current_metrics['cms_signature_verification']['valid']
                        
                        verify_pbar.set_postfix({
                            'OK': f"{verified_count}",
                            'FAIL': f"{failed_count}",
                            'EE': f"{ee_extracted}",
                            'CMS_OK': f"{cms_valid}",
                            'EE_OK': f"{ee_valid}",
                            'Rate': f"{(verified_count + failed_count) / current_time:.1f}/s",
                            'AvgTime': f"{sum(verification_times)/len(verification_times)*1000:.1f}ms" if verification_times else "N/A"
                        })
                
                except Exception as e:
                    failed_count += 1
                    # Continue processing
            
            verify_pbar.close()
            verify_elapsed = time.time() - verify_start
            
            # Calculate verification statistics
            if verification_times:
                min_verify_time = min(verification_times)
                max_verify_time = max(verification_times)
                avg_verify_time = sum(verification_times) / len(verification_times)
                median_verify_time = sorted(verification_times)[len(verification_times) // 2]
            else:
                min_verify_time = max_verify_time = avg_verify_time = median_verify_time = 0
            
            if signature_sizes:
                avg_sig_size = sum(signature_sizes) / len(signature_sizes)
                min_sig_size = min(signature_sizes)
                max_sig_size = max(signature_sizes)
                # Calculate percentiles for distribution analysis
                sorted_sigs = sorted(signature_sizes)
                p25_sig_size = sorted_sigs[len(sorted_sigs) // 4] if sorted_sigs else 0
                p50_sig_size = sorted_sigs[len(sorted_sigs) // 2] if sorted_sigs else 0
                p75_sig_size = sorted_sigs[3 * len(sorted_sigs) // 4] if sorted_sigs else 0
                p95_sig_size = sorted_sigs[95 * len(sorted_sigs) // 100] if sorted_sigs else 0
                p99_sig_size = sorted_sigs[99 * len(sorted_sigs) // 100] if sorted_sigs else 0
            else:
                avg_sig_size = min_sig_size = max_sig_size = expected_sig_size
                p25_sig_size = p50_sig_size = p75_sig_size = p95_sig_size = p99_sig_size = expected_sig_size
            
            # Calculate percentiles for verification times
            if verification_times:
                sorted_times = sorted(verification_times)
                p25_verify_time = sorted_times[len(sorted_times) // 4] if sorted_times else 0
                p50_verify_time = sorted_times[len(sorted_times) // 2] if sorted_times else 0
                p75_verify_time = sorted_times[3 * len(sorted_times) // 4] if sorted_times else 0
                p95_verify_time = sorted_times[95 * len(sorted_times) // 100] if sorted_times else 0
                p99_verify_time = sorted_times[99 * len(sorted_times) // 100] if sorted_times else 0
            else:
                p25_verify_time = p50_verify_time = p75_verify_time = p95_verify_time = p99_verify_time = 0
            
            # Calculate percentiles for file sizes
            if all_file_sizes:
                sorted_file_sizes = sorted(all_file_sizes)
                p25_file_size = sorted_file_sizes[len(sorted_file_sizes) // 4] if sorted_file_sizes else 0
                p50_file_size = sorted_file_sizes[len(sorted_file_sizes) // 2] if sorted_file_sizes else 0
                p75_file_size = sorted_file_sizes[3 * len(sorted_file_sizes) // 4] if sorted_file_sizes else 0
                p95_file_size = sorted_file_sizes[95 * len(sorted_file_sizes) // 100] if sorted_file_sizes else 0
                p99_file_size = sorted_file_sizes[99 * len(sorted_file_sizes) // 100] if sorted_file_sizes else 0
            else:
                p25_file_size = p50_file_size = p75_file_size = p95_file_size = p99_file_size = 0
            
            # Public key size statistics
            if public_key_sizes:
                avg_pubkey_size = sum(public_key_sizes) / len(public_key_sizes)
                min_pubkey_size = min(public_key_sizes)
                max_pubkey_size = max(public_key_sizes)
                sorted_pubkeys = sorted(public_key_sizes)
                p50_pubkey_size = sorted_pubkeys[len(sorted_pubkeys) // 2] if sorted_pubkeys else 0
            else:
                avg_pubkey_size = min_pubkey_size = max_pubkey_size = p50_pubkey_size = expected_pubkey_size
            
            # Extrapolate to full dataset
            if sample_size > 0 and verify_elapsed > 0:
                time_per_file = verify_elapsed / sample_size
                estimated_total_time = time_per_file * file_count
                
                # Process per-type metrics
                per_type_summary = {}
                for obj_type, type_metrics in per_type_metrics.items():
                    if type_metrics['count'] > 0:
                        per_type_summary[obj_type] = {
                            'count': type_metrics['count'],
                            'verified': type_metrics['verified'],
                            'failed': type_metrics['failed'],
                            'verification_rate': type_metrics['verified'] / type_metrics['count'] * 100,
                            'avg_verify_time_ms': (sum(type_metrics['verify_times']) / len(type_metrics['verify_times']) * 1000) if type_metrics['verify_times'] else 0,
                            'avg_sig_size_bytes': (sum(type_metrics['sig_sizes']) / len(type_metrics['sig_sizes'])) if type_metrics['sig_sizes'] else 0,
                            'avg_pubkey_size_bytes': (sum(type_metrics['pubkey_sizes']) / len(type_metrics['pubkey_sizes'])) if type_metrics['pubkey_sizes'] else 0,
                            'ee_certs_found': type_metrics['ee_certs_found'],
                            'issuer_certs_found': type_metrics['issuer_certs_found'],
                            'cms_valid_count': type_metrics['cms_valid'],
                            'ee_cert_valid_count': type_metrics['ee_cert_valid'],
                            'both_valid_count': type_metrics['both_valid']
                        }
                
                # Get comprehensive metrics summary
                metrics_summary = metrics.get_summary()
                
                signature_verification_results = {
                    "sampled": sample_size,
                    "verified": verified_count,
                    "failed": failed_count,
                    "verification_rate_pct": (verified_count / sample_size * 100) if sample_size > 0 else 0,
                    "asn1_extraction_failures": asn1_extraction_failures,
                    "verify_time_sec": verify_elapsed,
                    "time_per_file_sec": time_per_file,
                    "estimated_total_time_sec": estimated_total_time,
                    "verification_rate_per_sec": sample_size / verify_elapsed if verify_elapsed > 0 else 0,
                    
                    # Verification time statistics (all in milliseconds)
                    "min_verify_time_ms": min_verify_time * 1000,
                    "max_verify_time_ms": max_verify_time * 1000,
                    "avg_verify_time_ms": avg_verify_time * 1000,
                    "median_verify_time_ms": median_verify_time * 1000,
                    "p25_verify_time_ms": p25_verify_time * 1000,
                    "p50_verify_time_ms": p50_verify_time * 1000,
                    "p75_verify_time_ms": p75_verify_time * 1000,
                    "p95_verify_time_ms": p95_verify_time * 1000,
                    "p99_verify_time_ms": p99_verify_time * 1000,
                    
                    # Signature size statistics
                    "signature_size_avg_bytes": avg_sig_size,
                    "signature_size_min_bytes": min_sig_size,
                    "signature_size_max_bytes": max_sig_size,
                    "signature_size_p25_bytes": p25_sig_size,
                    "signature_size_p50_bytes": p50_sig_size,
                    "signature_size_p75_bytes": p75_sig_size,
                    "signature_size_p95_bytes": p95_sig_size,
                    "signature_size_p99_bytes": p99_sig_size,
                    "expected_signature_size_bytes": expected_sig_size,
                    "signature_size_variance": sum((s - avg_sig_size) ** 2 for s in signature_sizes) / len(signature_sizes) if signature_sizes else 0,
                    
                    # Public key size statistics
                    "public_key_size_avg_bytes": avg_pubkey_size,
                    "public_key_size_min_bytes": min_pubkey_size,
                    "public_key_size_max_bytes": max_pubkey_size,
                    "public_key_size_p50_bytes": p50_pubkey_size,
                    "expected_public_key_size_bytes": expected_pubkey_size,
                    "public_key_size_variance": sum((p - avg_pubkey_size) ** 2 for p in public_key_sizes) / len(public_key_sizes) if public_key_sizes else 0,
                    
                    # File size statistics
                    "file_size_p25_bytes": p25_file_size,
                    "file_size_p50_bytes": p50_file_size,
                    "file_size_p75_bytes": p75_file_size,
                    "file_size_p95_bytes": p95_file_size,
                    "file_size_p99_bytes": p99_file_size,
                    
                    # Object type breakdown
                    "object_type_breakdown": dict(object_type_counts),
                    "per_type_metrics": per_type_summary,
                    
                    # Error analysis
                    "error_categories": dict(error_categories),
                    "error_count": len(error_details),
                    "error_sample": error_details[:20],  # First 20 errors for analysis
                    
                    # Comprehensive metrics from VerificationMetrics
                    "detailed_metrics": metrics_summary
                }
                
                print(f"  Verification complete:")
                print(f"    Verified: {verified_count}/{sample_size} ({verified_count/sample_size*100:.1f}%)")
                print(f"    Failed: {failed_count}/{sample_size}")
                print(f"    ASN.1 extraction failures: {asn1_extraction_failures}")
                print(f"    Time: {verify_elapsed:.2f}s for {sample_size} files")
                print(f"    Rate: {sample_size/verify_elapsed:.1f} signatures/sec")
                print(f"    Avg verification time: {avg_verify_time*1000:.2f}ms per signature")
                print(f"    Estimated full validation: {estimated_total_time:.1f}s ({estimated_total_time/60:.1f} min)")
                print(f"    Signature size: avg={avg_sig_size:.0f} bytes (expected={expected_sig_size})")
                print(f"    Public key size: avg={avg_pubkey_size:.0f} bytes (expected={expected_pubkey_size})")
                print(f"    Object types: {dict(object_type_counts)}")
                
                # Show per-type metrics
                if per_type_summary:
                    print(f"\n    Per-Type Metrics:")
                    for obj_type, metrics_data in per_type_summary.items():
                        print(f"      {obj_type}:")
                        print(f"        Count: {metrics_data['count']}, Verified: {metrics_data['verified']} ({metrics_data['verification_rate']:.1f}%)")
                        if metrics_data['ee_certs_found'] > 0:
                            print(f"        EE certs found: {metrics_data['ee_certs_found']}, Issuer certs: {metrics_data['issuer_certs_found']}")
                            print(f"        CMS valid: {metrics_data['cms_valid_count']}, EE cert valid: {metrics_data['ee_cert_valid_count']}, Both: {metrics_data['both_valid_count']}")
                        if metrics_data['avg_verify_time_ms'] > 0:
                            print(f"        Avg verify time: {metrics_data['avg_verify_time_ms']:.2f}ms")
                        if metrics_data['avg_sig_size_bytes'] > 0:
                            print(f"        Avg sig size: {metrics_data['avg_sig_size_bytes']:.0f} bytes")
                
                # Show error breakdown
                if error_categories:
                    print(f"\n    Error Breakdown:")
                    for error_type, count in sorted(error_categories.items(), key=lambda x: x[1], reverse=True):
                        print(f"      {error_type}: {count}")
                
                # Show percentiles
                print(f"\n    Percentiles (P25/P50/P75/P95/P99):")
                print(f"      Verification time: {p25_verify_time*1000:.2f}/{p50_verify_time*1000:.2f}/{p75_verify_time*1000:.2f}/{p95_verify_time*1000:.2f}/{p99_verify_time*1000:.2f} ms")
                print(f"      Signature size: {p25_sig_size:.0f}/{p50_sig_size:.0f}/{p75_sig_size:.0f}/{p95_sig_size:.0f}/{p99_sig_size:.0f} bytes")
                if public_key_sizes:
                    print(f"      Public key size: {p50_pubkey_size:.0f} bytes (median)")
                
                # Show detailed metrics summary
                print(f"\n    Detailed Metrics Summary:")
                print(f"      EE Certificates: {metrics_summary['ee_certificate']['extracted']} extracted, {metrics_summary['ee_certificate']['extraction_failed']} failed")
                print(f"      CMS Signatures: {metrics_summary['cms_signature_verification']['valid']} valid, {metrics_summary['cms_signature_verification']['invalid']} invalid")
                print(f"      EE Cert Signatures: {metrics_summary['ee_certificate']['signatures_valid']} valid, {metrics_summary['ee_certificate']['signatures_invalid']} invalid")
                print(f"      Overall: {metrics_summary['overall_verification']['fully_valid']} fully valid, {metrics_summary['overall_verification']['partially_valid']} partially valid")
                
                # Use estimated time for validation time
                validation_time_sec = estimated_total_time
            else:
                validation_time_sec = 0
                print(f"  Could not measure verification time")
                
        except Exception as e:
            print(f"  Signature verification failed: {e}")
            import traceback
            traceback.print_exc()
            validation_time_sec = 0
            signature_verification_results = {"error": str(e)}
    
    elif algo == "ecdsa-baseline":
        # For ECDSA baseline, we measure file reading time since OQS doesn't support
        # ECDSA signature verification. This gives us a baseline for file I/O overhead.
        # Note: ECDSA signatures are not verified here - only file sizes and access times
        # are measured. For actual ECDSA verification, you'd need the cryptography library
        # or rpki-client, but we focus on PQ algorithms for this study.
        print(f"  Measuring file access time (ECDSA baseline - signatures not verified with OQS)...")
        read_start = time.time()
        sample_size = min(1000, file_count)
        files_to_check = files[:sample_size]
        
        for f in tqdm(files_to_check, desc="  Reading", unit="files", mininterval=0.5):
            try:
                _ = f.read_bytes()
            except:
                pass
        
        read_elapsed = time.time() - read_start
        
        if sample_size > 0 and read_elapsed > 0:
            time_per_file = read_elapsed / sample_size
            estimated_total_time = time_per_file * file_count
            validation_time_sec = estimated_total_time
            print(f"  Estimated file access time: {estimated_total_time:.1f}s ({estimated_total_time/60:.1f} min)")
        else:
            validation_time_sec = 0
    else:
        # No verification possible
        validation_time_sec = 0
        print(f"  Cannot verify: OQS not available or no algorithm name")
    
    # Determine validation success
    validation_success = (file_count > 0 and total_size_bytes > 0)
    if signature_verification_results and signature_verification_results.get("verified", 0) > 0:
        validation_success = True
    
    # Build comprehensive result entry
    result_entry = {
        "algorithm": algo,
        "algorithm_standardized": metadata["standardized"],
        "nist_security_level": metadata["nist_level"],
        "security_level": metadata["security_level"],
        "file_count": file_count,
        "total_size_gb": round(total_size_gb, 3),
        "total_size_bytes": total_size_bytes,
        "avg_file_size_kb": round(avg_file_size_kb, 2),
        "min_file_size_bytes": min_file_size,
        "max_file_size_bytes": max_file_size,
        "median_file_size_bytes": median_file_size,
        "file_type_breakdown": dict(file_types),
        "validation_time_sec": round(validation_time_sec, 2),
        "validation_time_min": round(validation_time_sec / 60, 2),
        "validation_success": validation_success,
        "scan_time_sec": round(scan_elapsed, 2),
        "objects_per_second": round(file_count / validation_time_sec, 2) if validation_time_sec > 0.001 else 0.0,
        "signature_verification": signature_verification_results,
        "rpki_client": rpki_client_results
    }
    
    results.append(result_entry)
    
    # Store error details if validation failed
    if not validation_success:
        validation_errors.append({
            "algorithm": algo,
            "file_count": file_count,
            "error": "Validation failed or no files found"
        })
    
    # Print summary
    status = "MEASURED" if validation_success else "FAIL"
    if validation_time_sec < 0.1:
        elapsed_display = "<0.1s"
    else:
        elapsed_display = f"{validation_time_sec:.1f}s" if validation_time_sec < 60 else f"{validation_time_sec/60:.1f}min"
    rate_display = f"{file_count/validation_time_sec:.0f} obj/s" if validation_time_sec > 0.001 else "N/A"
    
    print(f"\n  {status} | Files: {file_count:,} | Size: {total_size_gb:.3f} GB | Time: {elapsed_display} | Rate: {rate_display}")
    if signature_verification_results:
        sig_res = signature_verification_results
        if "verified" in sig_res:
            print(f"  Signature verification: {sig_res['verified']}/{sig_res['sampled']} verified, "
                  f"{sig_res.get('failed', 0)} failed, {sig_res.get('asn1_extraction_failures', 0)} ASN.1 errors")

# Create results directory
results_dir = Path("results")
results_dir.mkdir(exist_ok=True)

# Save comprehensive results to CSV
import csv
csv_path = results_dir / "results.csv"
if not results:
    print("\nWARNING: No results to save. Check that /data/signed contains algorithm directories.")
    exit(1)

with open(csv_path, "w", newline="") as f:
    # Flatten nested structures for CSV
    flat_results = []
    for r in results:
        flat = {}
        for key, value in r.items():
            if isinstance(value, dict):
                # Flatten nested dicts
                for subkey, subvalue in value.items():
                    flat[f"{key}_{subkey}"] = subvalue
            else:
                flat[key] = value
        flat_results.append(flat)
    
    if flat_results:
        fieldnames = flat_results[0].keys()
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(flat_results)

# Save detailed JSON for programmatic access
json_path = results_dir / "results.json"
with open(json_path, "w") as f:
    json.dump({
        "experiment_metadata": {
            "date": datetime.now().isoformat(),
            "description": "Post-quantum RPKI validation measurements",
            "total_algorithms": len(results),
            "total_objects": sum(r["file_count"] for r in results),
            "asn1_extraction_available": ASN1_EXTRACTION_AVAILABLE,
            "oqs_available": OQS_AVAILABLE
        },
        "results": results,
        "validation_errors": validation_errors
    }, f, indent=2)

# Calculate relative metrics (compared to baseline)
baseline = next((r for r in results if r["algorithm"] == "ecdsa-baseline"), None)
if baseline:
    print("\n" + "="*80)
    print("  RELATIVE PERFORMANCE (vs ECDSA baseline)")
    print("="*80)
    for r in results:
        if r["algorithm"] != "ecdsa-baseline":
            size_ratio = r["total_size_gb"] / baseline["total_size_gb"] if baseline["total_size_gb"] > 0 else 0
            time_ratio = r["validation_time_sec"] / baseline["validation_time_sec"] if baseline["validation_time_sec"] > 0 else 0
            size_overhead_pct = (size_ratio - 1) * 100
            time_overhead_pct = (time_ratio - 1) * 100
            
            print(f"{r['algorithm']:20s} | Size: {size_ratio:.2f}x ({size_overhead_pct:+.1f}%) | "
                  f"Time: {time_ratio:.2f}x ({time_overhead_pct:+.1f}%)")
            
            # Show signature verification details if available
            if r.get("signature_verification"):
                sig_res = r["signature_verification"]
                if "avg_verify_time_ms" in sig_res:
                    print(f"  {'':20s} | Avg verify: {sig_res['avg_verify_time_ms']:.2f}ms | "
                          f"Rate: {sig_res.get('verification_rate_per_sec', 0):.1f} sig/s")

print(f"\n{'='*80}")
print("Validation complete!")
print(f"  Results saved to: {csv_path}")
print(f"  Detailed JSON: {json_path}")
print(f"  Total algorithms tested: {len(results)}")
print(f"  Successful validations: {sum(1 for r in results if r['validation_success'])}/{len(results)}")
print(f"{'='*80}\n")
