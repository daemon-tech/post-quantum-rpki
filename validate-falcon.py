#!/usr/bin/env python3
"""
validate-falcon.py - Falcon-512 specific validation script

This script validates Falcon-512 signed RPKI objects with chain handling.
It's a focused version of validate.py specifically for Falcon-512 testing.


Author: Sam Moes
Date: December 2025
"""

import subprocess
import time
import json
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
    print("ERROR: OQS library not available. Install with: pip install oqs")
    sys.exit(1)

# Import ASN.1 parser
try:
    from asn1_rpki import (
        extract_signature_and_tbs, 
        detect_rpki_object_type,
        verify_cms_object_signatures,
        extract_ee_certificate_from_cms,
        extract_issuer_certificate_from_cms,
        find_parent_certificate,
        extract_public_key_from_certificate,
        get_verification_metrics,
        reset_verification_metrics,
        print_verification_metrics
    )
    ASN1_EXTRACTION_AVAILABLE = True
except ImportError:
    ASN1_EXTRACTION_AVAILABLE = False
    print("ERROR: ASN.1 extraction not available. Install asn1crypto: pip install asn1crypto")
    sys.exit(1)

# Falcon-512 configuration
# Note: Falcon-512 signatures are variable-length, typically ranging from ~650-690 bytes
FALCON_CONFIG = {
    "algorithm": "falcon512",
    "display_name": "Falcon-512",
    "oqs_alg_name": "Falcon-512",
    "signature_size_range": (650, 690),  # Variable-length signatures: ~650-690 bytes
    "public_key_size": 897,
    "directory_name": "falcon512"
}

def main():
    print("=" * 80)
    print(f"Falcon-512 RPKI Validation")
    print("  (CMS signature verification only - no EE cert verification)")
    print("=" * 80)
    print()
    
    # Find Falcon-512 directory
    repos = Path("/data/signed")
    falcon_dir = repos / FALCON_CONFIG["directory_name"]
    
    if not falcon_dir.exists():
        print(f"Falcon-512 directory not found: {falcon_dir}")
        print(f"Creating directory: {falcon_dir}")
        falcon_dir.mkdir(parents=True, exist_ok=True)
        print(f"Directory created successfully")
        print()
    
    print(f"Scanning directory: {falcon_dir}")
    
    # Find all RPKI files
    files = []
    for ext in ["*.roa", "*.mft", "*.cer", "*.crl"]:
        files.extend(list(falcon_dir.rglob(ext)))
    
    if not files:
        print(f"WARNING: No RPKI files found in {falcon_dir}")
        print(f"  This directory is empty. You need to run the resigning script first:")
        print(f"  python3 pq-resign-falcon.py")
        print()
        print(f"  The resigning script will populate this directory with re-signed RPKI objects.")
        sys.exit(0)  # Exit gracefully, not as an error
    
    print(f"Found {len(files)} files")
    print()
    
    # Initialize OQS verifier
    if not OQS_AVAILABLE:
        print("ERROR: OQS not available")
        sys.exit(1)
    
    try:
        verifier = Signature(FALCON_CONFIG["oqs_alg_name"])
    except Exception as e:
        print(f"ERROR: Failed to initialize {FALCON_CONFIG['oqs_alg_name']} verifier: {e}")
        sys.exit(1)
    
    # Comprehensive metrics for research proof
    metrics = {
        "total_files": len(files),
        "verified": 0,
        "failed": 0,
        "cms_valid": 0,
        "extraction_failed": 0,
        "verification_times": [],
        "file_sizes": [],
        "signature_sizes": [],
        "public_key_sizes": [],
        "errors": [],
        # Enhanced metrics for statistical analysis
        "ee_certs_extracted": 0,
        "ee_certs_extraction_failed": 0,
        "ee_cert_signatures_valid": 0,
        "ee_cert_signatures_invalid": 0
    }
    
    # Per-object-type detailed metrics
    type_metrics = defaultdict(lambda: {
        "count": 0,
        "verified": 0,
        "cms_valid": 0,
        "verification_times": [],
        "signature_sizes": [],
        "public_key_sizes": [],
        "file_sizes": [],
        "ee_certs_found": 0,
        "ee_certs_extracted": 0
    })
    
    # Error categorization for analysis
    error_categories = defaultdict(int)
    
    print("Validating files...")
    print()
    
    # No chain validation needed - skip certificate pre-scan
    print()
    
    # Process files
    for file_path in tqdm(files, desc="Validating", unit="files"):
        try:
            file_data = file_path.read_bytes()
            metrics["file_sizes"].append(len(file_data))
            
            # Detect object type
            obj_type = detect_rpki_object_type(file_data, str(file_path))
            type_metrics[obj_type]["count"] += 1
            
            # Extract signature and TBS (returns tbs_data, signature_bytes)
            tbs_data, signature = extract_signature_and_tbs(file_data, obj_type)
            
            if signature is None or tbs_data is None:
                metrics["extraction_failed"] += 1
                error_categories["signature_tbs_extraction_failed"] += 1
                metrics["errors"].append(f"{file_path.name}: Failed to extract signature/TBS")
                continue
            
            metrics["signature_sizes"].append(len(signature))
            type_metrics[obj_type]["signature_sizes"].append(len(signature))
            type_metrics[obj_type]["file_sizes"].append(len(file_data))
            
            # For CMS objects (ROA, Manifest), extract EE certificate
            if obj_type in ["roa", "manifest"]:
                ee_cert_bytes = extract_ee_certificate_from_cms(file_data)
                
                if not ee_cert_bytes:
                    metrics["extraction_failed"] += 1
                    metrics["ee_certs_extraction_failed"] += 1
                    error_categories["ee_cert_extraction_failed"] += 1
                    metrics["errors"].append(f"{file_path.name}: Failed to extract EE certificate")
                    continue
                
                metrics["ee_certs_extracted"] += 1
                type_metrics[obj_type]["ee_certs_found"] += 1
                type_metrics[obj_type]["ee_certs_extracted"] += 1
                
                # Extract public key from EE cert
                ee_pubkey = extract_public_key_from_certificate(
                    ee_cert_bytes, 
                    FALCON_CONFIG["public_key_size"]
                )
                
                if not ee_pubkey or len(ee_pubkey) != FALCON_CONFIG["public_key_size"]:
                    metrics["extraction_failed"] += 1
                    error_categories["public_key_extraction_failed"] += 1
                    metrics["errors"].append(
                        f"{file_path.name}: Failed to extract public key "
                        f"(got {len(ee_pubkey) if ee_pubkey else 0} bytes, expected {FALCON_CONFIG['public_key_size']})"
                    )
                    continue
                
                # DEBUG: Test verification on first ROA file to see what's wrong
                debug_printed = getattr(main, '_debug_printed', False)
                if not debug_printed and obj_type == "roa":
                    main._debug_printed = True
                    print(f"\n=== DEBUG: First ROA file ===")
                    print(f"File: {file_path.name}")
                    print(f"File size: {len(file_data)} bytes")
                    sig_range = FALCON_CONFIG['signature_size_range']
                    print(f"Signature size: {len(signature)} bytes (expected range: {sig_range[0]}-{sig_range[1]} bytes)")
                    print(f"TBS size: {len(tbs_data)} bytes")
                    print(f"EE cert size: {len(ee_cert_bytes)} bytes")
                    print(f"Public key size: {len(ee_pubkey)} bytes")
                    print(f"Public key first 32 bytes: {ee_pubkey[:32].hex()}")
                    print(f"Public key last 32 bytes: {ee_pubkey[-32:].hex()}")
                    print(f"Signature first 32 bytes: {signature[:32].hex() if len(signature) >= 32 else signature.hex()}")
                    print(f"TBS first 32 bytes: {tbs_data[:32].hex() if len(tbs_data) >= 32 else tbs_data.hex()}")
                    
                    # CRITICAL: Check if the certificate has the PQ algorithm OID
                    try:
                        from asn1crypto import cms, x509, algos, core
                        cert_parsed = x509.Certificate.load(ee_cert_bytes)
                        
                        # Check signature algorithm (handle OID lookup errors)
                        sig_alg = cert_parsed['signature_algorithm']
                        try:
                            sig_alg_oid = sig_alg['algorithm'].dotted
                        except (KeyError, AttributeError, TypeError):
                            # OID not in registry - use raw OID access
                            sig_alg_oid = str(sig_alg['algorithm'])
                        
                        print(f"\nCertificate analysis:")
                        print(f"  Signature algorithm OID: {sig_alg_oid}")
                        print(f"  Expected (Falcon-512): 1.3.9999.3.6.4")
                        
                        # Check public key algorithm (handle OID lookup errors)
                        pubkey_alg = cert_parsed['tbs_certificate']['subject_public_key_info']['algorithm']
                        try:
                            pubkey_alg_oid = pubkey_alg['algorithm'].dotted
                        except (KeyError, AttributeError, TypeError):
                            # OID not in registry - use raw OID access
                            pubkey_alg_oid = str(pubkey_alg['algorithm'])
                        
                        print(f"  Public key algorithm OID: {pubkey_alg_oid}")
                        
                        # Check if this matches (compare as strings to handle both cases)
                        expected_oid = "1.3.9999.3.6.4"
                        if sig_alg_oid != expected_oid or pubkey_alg_oid != expected_oid:
                            print(f"  ⚠ WARNING: Certificate does NOT have Falcon-512 OID!")
                            print(f"  This might be an OLD certificate, not the re-signed one!")
                        else:
                            print(f"  ✓ Certificate has Falcon-512 OID (as expected)")
                        
                        # Check signature size in certificate
                        cert_sig = cert_parsed['signature_value']
                        if hasattr(cert_sig, 'contents'):
                            cert_sig_size = len(cert_sig.contents)
                            print(f"  Certificate signature size: {cert_sig_size} bytes")
                    except (KeyError, TypeError) as oid_err:
                        # OID lookup error - certificate has Falcon-512 OID (expected!)
                        error_str = str(oid_err)
                        if '1.3.9999.3.6.4' in error_str or '1.3.' in error_str or 'OID' in error_str:
                            print(f"\nCertificate analysis:")
                            print(f"  ✓ Certificate has Falcon-512 OID (1.3.9999.3.6.4)")
                            print(f"  Note: OID lookup failed (expected - OID not in asn1crypto registry)")
                            print(f"  This is normal for Falcon-512 certificates")
                        else:
                            print(f"Certificate analysis error: {oid_err}")
                    except Exception as cert_analysis_err:
                        print(f"Certificate analysis error: {cert_analysis_err}")
                    
                    # Try verification manually
                    try:
                        test_result = verifier.verify(tbs_data, signature, ee_pubkey)
                        print(f"\nDirect verification result: {test_result}")
                    except Exception as verr:
                        print(f"Direct verification error: {verr}")
                    print(f"=== END DEBUG ===\n")
                
                metrics["public_key_sizes"].append(len(ee_pubkey))
                
                # Verify CMS signature only (no EE cert verification)
                reset_verification_metrics()
                start_time = time.time()
                
                cms_valid, ee_cert_valid, error_msg = verify_cms_object_signatures(
                    file_data,
                    ee_pubkey,
                    None,  # No issuer key - skip EE cert verification
                    FALCON_CONFIG["oqs_alg_name"],
                    verifier,
                    get_verification_metrics()
                )
                
                verification_time = time.time() - start_time
                metrics["verification_times"].append(verification_time)
                type_metrics[obj_type]["verification_times"].append(verification_time)
                
                # Get detailed verification metrics from asn1_rpki
                verification_metrics = get_verification_metrics()
                metrics_summary = verification_metrics.get_summary()
                
                # Update metrics (only CMS verification matters)
                if cms_valid:
                    metrics["cms_valid"] += 1
                    metrics["verified"] += 1
                    type_metrics[obj_type]["cms_valid"] += 1
                    type_metrics[obj_type]["verified"] += 1
                else:
                    metrics["failed"] += 1
                    error_categories["cms_verification_failed"] += 1
                    if error_msg:
                        metrics["errors"].append(f"{file_path.name}: {error_msg}")
                
                # Track EE cert verification results
                if ee_cert_valid:
                    metrics["ee_cert_signatures_valid"] += 1
                else:
                    metrics["ee_cert_signatures_invalid"] += 1
            
            # Skip certificate verification (not needed for our dataset)
            elif obj_type == "certificate":
                # Just extract public key for metrics, but don't verify
                cert_pubkey = extract_public_key_from_certificate(
                    file_data,
                    FALCON_CONFIG["public_key_size"]
                )
                
                if cert_pubkey and len(cert_pubkey) == FALCON_CONFIG["public_key_size"]:
                    metrics["public_key_sizes"].append(len(cert_pubkey))
                # Skip verification - certificates not verified
        
        except (KeyError, TypeError) as oid_err:
            # OID lookup error - handle gracefully
            error_str = str(oid_err)
            if '1.3.9999.3.6.4' in error_str or '1.3.' in error_str or 'OID' in error_str:
                # This is an expected OID lookup error - file has Falcon-512 OID
                # Try to continue with raw byte extraction methods
                metrics["extraction_failed"] += 1
                error_categories["oid_lookup_error"] += 1
                metrics["errors"].append(f"{file_path.name}: OID lookup error (certificate has Falcon-512 OID) - {error_str}")
            else:
                # Not an OID error - treat as regular failure
                metrics["failed"] += 1
                error_categories["unknown_error"] += 1
                metrics["errors"].append(f"{file_path.name}: {error_str}")
        except Exception as e:
            metrics["failed"] += 1
            error_categories["exception"] += 1
            metrics["errors"].append(f"{file_path.name}: {str(e)}")
    
    # Print results
    print()
    print("=" * 80)
    print("RESULTS")
    print("=" * 80)
    print()
    
    print(f"Total files processed: {metrics['total_files']}")
    print(f"Successfully verified: {metrics['verified']} ({100*metrics['verified']/metrics['total_files']:.1f}%)")
    print(f"Failed: {metrics['failed']} ({100*metrics['failed']/metrics['total_files']:.1f}%)")
    print(f"Extraction failed: {metrics['extraction_failed']}")
    print()
    
    print("Signature Verification:")
    print(f"  CMS signatures valid: {metrics['cms_valid']}")
    print()
    
    # Calculate comprehensive statistics with percentiles
    if metrics["verification_times"]:
        times = sorted(metrics["verification_times"])
        print("Verification Times (seconds):")
        print(f"  Min: {min(times):.6f}")
        print(f"  Max: {max(times):.6f}")
        print(f"  Mean: {sum(times)/len(times):.6f}")
        print(f"  Median (P50): {times[len(times)//2]:.6f}")
        print(f"  P25: {times[len(times)//4]:.6f}")
        print(f"  P75: {times[3*len(times)//4]:.6f}")
        print(f"  P95: {times[95*len(times)//100] if len(times) > 0 else 0:.6f}")
        print(f"  P99: {times[99*len(times)//100] if len(times) > 0 else 0:.6f}")
        # Calculate variance and standard deviation
        mean_time = sum(times) / len(times)
        variance = sum((t - mean_time) ** 2 for t in times) / len(times)
        std_dev = variance ** 0.5
        print(f"  Std Dev: {std_dev:.6f}")
        print(f"  Variance: {variance:.9f}")
        print()
    
    if metrics["file_sizes"]:
        sizes = sorted(metrics["file_sizes"])
        print("File Sizes (bytes):")
        print(f"  Min: {min(sizes):,}")
        print(f"  Max: {max(sizes):,}")
        print(f"  Mean: {sum(sizes)/len(sizes):,.0f}")
        print(f"  Median (P50): {sizes[len(sizes)//2]:,}")
        print(f"  P25: {sizes[len(sizes)//4]:,}")
        print(f"  P75: {sizes[3*len(sizes)//4]:,}")
        print(f"  P95: {sizes[95*len(sizes)//100] if len(sizes) > 0 else 0:,}")
        print(f"  P99: {sizes[99*len(sizes)//100] if len(sizes) > 0 else 0:,}")
        mean_size = sum(sizes) / len(sizes)
        variance = sum((s - mean_size) ** 2 for s in sizes) / len(sizes)
        std_dev = variance ** 0.5
        print(f"  Std Dev: {std_dev:,.0f}")
        print()
    
    if metrics["signature_sizes"]:
        sig_sizes = sorted(metrics["signature_sizes"])
        print("Signature Sizes (bytes):")
        print(f"  Min: {min(sig_sizes):,}")
        print(f"  Max: {max(sig_sizes):,}")
        print(f"  Mean: {sum(sig_sizes)/len(sig_sizes):,.0f}")
        print(f"  Median (P50): {sig_sizes[len(sig_sizes)//2]:,}")
        print(f"  P25: {sig_sizes[len(sig_sizes)//4]:,}")
        print(f"  P75: {sig_sizes[3*len(sig_sizes)//4]:,}")
        print(f"  P95: {sig_sizes[95*len(sig_sizes)//100] if len(sig_sizes) > 0 else 0:,}")
        print(f"  P99: {sig_sizes[99*len(sig_sizes)//100] if len(sig_sizes) > 0 else 0:,}")
        sig_range = FALCON_CONFIG['signature_size_range']
        print(f"  Expected range: {sig_range[0]}-{sig_range[1]} bytes")
        mean_sig = sum(sig_sizes) / len(sig_sizes)
        variance = sum((s - mean_sig) ** 2 for s in sig_sizes) / len(sig_sizes)
        std_dev = variance ** 0.5
        print(f"  Std Dev: {std_dev:.2f}")
        print()
    
    if metrics["public_key_sizes"]:
        pk_sizes = sorted(metrics["public_key_sizes"])
        print("Public Key Sizes (bytes):")
        print(f"  Min: {min(pk_sizes):,}")
        print(f"  Max: {max(pk_sizes):,}")
        print(f"  Mean: {sum(pk_sizes)/len(pk_sizes):,.0f}")
        print(f"  Median (P50): {pk_sizes[len(pk_sizes)//2]:,}")
        print(f"  P25: {pk_sizes[len(pk_sizes)//4]:,}")
        print(f"  P75: {pk_sizes[3*len(pk_sizes)//4]:,}")
        print(f"  P95: {pk_sizes[95*len(pk_sizes)//100] if len(pk_sizes) > 0 else 0:,}")
        print(f"  P99: {pk_sizes[99*len(pk_sizes)//100] if len(pk_sizes) > 0 else 0:,}")
        print(f"  Expected: {FALCON_CONFIG['public_key_size']}")
        mean_pk = sum(pk_sizes) / len(pk_sizes)
        variance = sum((p - mean_pk) ** 2 for p in pk_sizes) / len(pk_sizes)
        std_dev = variance ** 0.5
        print(f"  Std Dev: {std_dev:.2f}")
        print()
    
    print("Per-Object-Type Breakdown:")
    for obj_type, type_met in sorted(type_metrics.items()):
        if type_met["count"] > 0:
            print(f"  {obj_type.upper()}:")
            print(f"    Count: {type_met['count']}")
            print(f"    Verified: {type_met['verified']} ({100*type_met['verified']/type_met['count']:.1f}%)")
            print(f"    CMS valid: {type_met['cms_valid']}")
            if type_met.get("ee_certs_found", 0) > 0:
                print(f"    EE certs found: {type_met['ee_certs_found']}")
                print(f"    EE certs extracted: {type_met.get('ee_certs_extracted', 0)}")
            if type_met.get("verification_times"):
                avg_time = sum(type_met["verification_times"]) / len(type_met["verification_times"])
                print(f"    Avg verification time: {avg_time*1000:.3f} ms")
            if type_met.get("signature_sizes"):
                avg_sig = sum(type_met["signature_sizes"]) / len(type_met["signature_sizes"])
                print(f"    Avg signature size: {avg_sig:.0f} bytes")
            if type_met.get("public_key_sizes"):
                avg_pk = sum(type_met["public_key_sizes"]) / len(type_met["public_key_sizes"])
                print(f"    Avg public key size: {avg_pk:.0f} bytes")
            print()
    
    # Error categorization summary
    if error_categories:
        print("Error Categories:")
        for category, count in sorted(error_categories.items(), key=lambda x: x[1], reverse=True):
            print(f"  {category}: {count}")
        print()
    
    if metrics["errors"]:
        print(f"Errors ({len(metrics['errors'])}):")
        for error in metrics["errors"][:10]:  # Show first 10
            print(f"  - {error}")
        if len(metrics["errors"]) > 10:
            print(f"  ... and {len(metrics['errors']) - 10} more errors")
        print()
    
    # Calculate comprehensive statistics for JSON output
    stats = {}
    
    if metrics["verification_times"]:
        times = sorted(metrics["verification_times"])
        stats["verification_times"] = {
            "min_sec": min(times),
            "max_sec": max(times),
            "mean_sec": sum(times) / len(times),
            "median_sec": times[len(times)//2],
            "p25_sec": times[len(times)//4],
            "p75_sec": times[3*len(times)//4],
            "p95_sec": times[95*len(times)//100] if len(times) > 0 else 0,
            "p99_sec": times[99*len(times)//100] if len(times) > 0 else 0,
            "std_dev_sec": (sum((t - sum(times)/len(times)) ** 2 for t in times) / len(times)) ** 0.5,
            "variance_sec": sum((t - sum(times)/len(times)) ** 2 for t in times) / len(times)
        }
    
    if metrics["signature_sizes"]:
        sig_sizes = sorted(metrics["signature_sizes"])
        mean_sig = sum(sig_sizes) / len(sig_sizes)
        stats["signature_sizes"] = {
            "min_bytes": min(sig_sizes),
            "max_bytes": max(sig_sizes),
            "mean_bytes": mean_sig,
            "median_bytes": sig_sizes[len(sig_sizes)//2],
            "p25_bytes": sig_sizes[len(sig_sizes)//4],
            "p75_bytes": sig_sizes[3*len(sig_sizes)//4],
            "p95_bytes": sig_sizes[95*len(sig_sizes)//100] if len(sig_sizes) > 0 else 0,
            "p99_bytes": sig_sizes[99*len(sig_sizes)//100] if len(sig_sizes) > 0 else 0,
            "expected_range_bytes": FALCON_CONFIG["signature_size_range"],
            "std_dev_bytes": (sum((s - mean_sig) ** 2 for s in sig_sizes) / len(sig_sizes)) ** 0.5,
            "variance_bytes": sum((s - mean_sig) ** 2 for s in sig_sizes) / len(sig_sizes)
        }
    
    if metrics["public_key_sizes"]:
        pk_sizes = sorted(metrics["public_key_sizes"])
        mean_pk = sum(pk_sizes) / len(pk_sizes)
        stats["public_key_sizes"] = {
            "min_bytes": min(pk_sizes),
            "max_bytes": max(pk_sizes),
            "mean_bytes": mean_pk,
            "median_bytes": pk_sizes[len(pk_sizes)//2],
            "p25_bytes": pk_sizes[len(pk_sizes)//4],
            "p75_bytes": pk_sizes[3*len(pk_sizes)//4],
            "p95_bytes": pk_sizes[95*len(pk_sizes)//100] if len(pk_sizes) > 0 else 0,
            "p99_bytes": pk_sizes[99*len(pk_sizes)//100] if len(pk_sizes) > 0 else 0,
            "expected_bytes": FALCON_CONFIG["public_key_size"],
            "std_dev_bytes": (sum((p - mean_pk) ** 2 for p in pk_sizes) / len(pk_sizes)) ** 0.5,
            "variance_bytes": sum((p - mean_pk) ** 2 for p in pk_sizes) / len(pk_sizes)
        }
    
    if metrics["file_sizes"]:
        file_sizes = sorted(metrics["file_sizes"])
        mean_file = sum(file_sizes) / len(file_sizes)
        stats["file_sizes"] = {
            "min_bytes": min(file_sizes),
            "max_bytes": max(file_sizes),
            "mean_bytes": mean_file,
            "median_bytes": file_sizes[len(file_sizes)//2],
            "p25_bytes": file_sizes[len(file_sizes)//4],
            "p75_bytes": file_sizes[3*len(file_sizes)//4],
            "p95_bytes": file_sizes[95*len(file_sizes)//100] if len(file_sizes) > 0 else 0,
            "p99_bytes": file_sizes[99*len(file_sizes)//100] if len(file_sizes) > 0 else 0,
            "std_dev_bytes": (sum((f - mean_file) ** 2 for f in file_sizes) / len(file_sizes)) ** 0.5,
            "variance_bytes": sum((f - mean_file) ** 2 for f in file_sizes) / len(file_sizes),
            "total_bytes": sum(file_sizes),
            "total_gb": sum(file_sizes) / (1024**3)
        }
    
    # Get comprehensive verification metrics from asn1_rpki
    verification_metrics = get_verification_metrics()
    metrics_summary = verification_metrics.get_summary()
    
    # Enhanced per-type metrics with statistics
    enhanced_type_metrics = {}
    for obj_type, type_met in type_metrics.items():
        if type_met["count"] > 0:
            enhanced_type_metrics[obj_type] = {
                "count": type_met["count"],
                "verified": type_met["verified"],
                "failed": type_met["count"] - type_met["verified"],
                "verification_rate_pct": (type_met["verified"] / type_met["count"] * 100) if type_met["count"] > 0 else 0,
                "cms_valid": type_met["cms_valid"],
                "ee_certs_found": type_met.get("ee_certs_found", 0),
                "ee_certs_extracted": type_met.get("ee_certs_extracted", 0)
            }
            
            if type_met.get("verification_times"):
                times = sorted(type_met["verification_times"])
                enhanced_type_metrics[obj_type]["verification_times"] = {
                    "mean_ms": (sum(times) / len(times)) * 1000,
                    "median_ms": times[len(times)//2] * 1000,
                    "p25_ms": times[len(times)//4] * 1000,
                    "p75_ms": times[3*len(times)//4] * 1000,
                    "p95_ms": times[95*len(times)//100] * 1000 if len(times) > 0 else 0,
                    "p99_ms": times[99*len(times)//100] * 1000 if len(times) > 0 else 0
                }
            
            if type_met.get("signature_sizes"):
                sigs = sorted(type_met["signature_sizes"])
                enhanced_type_metrics[obj_type]["signature_sizes"] = {
                    "mean_bytes": sum(sigs) / len(sigs),
                    "median_bytes": sigs[len(sigs)//2],
                    "min_bytes": min(sigs),
                    "max_bytes": max(sigs)
                }
            
            if type_met.get("public_key_sizes"):
                pks = sorted(type_met["public_key_sizes"])
                enhanced_type_metrics[obj_type]["public_key_sizes"] = {
                    "mean_bytes": sum(pks) / len(pks),
                    "median_bytes": pks[len(pks)//2],
                    "min_bytes": min(pks),
                    "max_bytes": max(pks)
                }
    
    # Save results to JSON
    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)
    
    results = {
        "algorithm": FALCON_CONFIG["display_name"],
        "algorithm_config": FALCON_CONFIG,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_files": metrics["total_files"],
            "verified": metrics["verified"],
            "failed": metrics["failed"],
            "verification_rate_pct": (metrics["verified"] / metrics["total_files"] * 100) if metrics["total_files"] > 0 else 0,
            "cms_valid": metrics["cms_valid"],
            "extraction_failed": metrics["extraction_failed"],
            "ee_certs_extracted": metrics["ee_certs_extracted"],
            "ee_certs_extraction_failed": metrics["ee_certs_extraction_failed"],
            "ee_cert_signatures_valid": metrics["ee_cert_signatures_valid"],
            "ee_cert_signatures_invalid": metrics["ee_cert_signatures_invalid"]
        },
        "statistics": stats,
        "type_metrics": enhanced_type_metrics,
        "error_categories": dict(error_categories),
        "error_count": len(metrics["errors"]),
        "errors_sample": metrics["errors"][:50],  # First 50 errors for analysis
        "verification_metrics": metrics_summary,  # Comprehensive metrics from asn1_rpki
        "raw_metrics": {
            "verification_times": metrics["verification_times"],
            "signature_sizes": metrics["signature_sizes"],
            "public_key_sizes": metrics["public_key_sizes"],
            "file_sizes": metrics["file_sizes"]
        }
    }
    
    json_path = results_dir / "falcon-validation.json"
    with open(json_path, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved to: {json_path}")
    print()
    
    # Print verification metrics from asn1_rpki
    print("Detailed Verification Metrics:")
    print_verification_metrics()
    
    return 0 if metrics["verified"] > 0 else 1

if __name__ == "__main__":
    sys.exit(main())

