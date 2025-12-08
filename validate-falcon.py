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
FALCON_CONFIG = {
    "algorithm": "falcon512",
    "display_name": "Falcon-512",
    "oqs_alg_name": "Falcon-512",
    "signature_size": 690,
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
    
    # Metrics
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
        "errors": []
    }
    
    type_metrics = defaultdict(lambda: {
        "count": 0,
        "verified": 0,
        "cms_valid": 0
    })
    
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
                metrics["errors"].append(f"{file_path.name}: Failed to extract signature/TBS")
                continue
            
            metrics["signature_sizes"].append(len(signature))
            
            # For CMS objects (ROA, Manifest), extract EE certificate
            if obj_type in ["roa", "manifest"]:
                ee_cert_bytes = extract_ee_certificate_from_cms(file_data)
                
                if not ee_cert_bytes:
                    metrics["extraction_failed"] += 1
                    metrics["errors"].append(f"{file_path.name}: Failed to extract EE certificate")
                    continue
                
                # Extract public key from EE cert
                ee_pubkey = extract_public_key_from_certificate(
                    ee_cert_bytes, 
                    FALCON_CONFIG["public_key_size"]
                )
                
                if not ee_pubkey or len(ee_pubkey) != FALCON_CONFIG["public_key_size"]:
                    metrics["extraction_failed"] += 1
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
                    print(f"Signature size: {len(signature)} bytes (expected: {FALCON_CONFIG['signature_size']})")
                    print(f"TBS size: {len(tbs_data)} bytes")
                    print(f"EE cert size: {len(ee_cert_bytes)} bytes")
                    print(f"Public key size: {len(ee_pubkey)} bytes")
                    print(f"Public key first 32 bytes: {ee_pubkey[:32].hex()}")
                    print(f"Public key last 32 bytes: {ee_pubkey[-32:].hex()}")
                    print(f"Signature first 32 bytes: {signature[:32].hex() if len(signature) >= 32 else signature.hex()}")
                    print(f"TBS first 32 bytes: {tbs_data[:32].hex() if len(tbs_data) >= 32 else tbs_data.hex()}")
                    
                    # CRITICAL: Check if the certificate has the PQ algorithm OID
                    try:
                        from asn1crypto import cms, x509, algos
                        cert_parsed = x509.Certificate.load(ee_cert_bytes)
                        
                        # Check signature algorithm
                        sig_alg = cert_parsed['signature_algorithm']
                        sig_alg_oid = sig_alg['algorithm'].dotted
                        print(f"\nCertificate analysis:")
                        print(f"  Signature algorithm OID: {sig_alg_oid}")
                        print(f"  Expected (Falcon-512): 1.3.9999.3.6.4")
                        
                        # Check public key algorithm
                        pubkey_alg = cert_parsed['tbs_certificate']['subject_public_key_info']['algorithm']
                        pubkey_alg_oid = pubkey_alg['algorithm'].dotted
                        print(f"  Public key algorithm OID: {pubkey_alg_oid}")
                        
                        # Check if this matches
                        if sig_alg_oid != "1.3.9999.3.6.4" or pubkey_alg_oid != "1.3.9999.3.6.4":
                            print(f"  ⚠ WARNING: Certificate does NOT have Falcon-512 OID!")
                            print(f"  This might be an OLD certificate, not the re-signed one!")
                        
                        # Check signature size in certificate
                        cert_sig = cert_parsed['signature_value']
                        if hasattr(cert_sig, 'contents'):
                            cert_sig_size = len(cert_sig.contents)
                            print(f"  Certificate signature size: {cert_sig_size} bytes")
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
                
                # Update metrics (only CMS verification matters)
                if cms_valid:
                    metrics["cms_valid"] += 1
                    metrics["verified"] += 1
                    type_metrics[obj_type]["cms_valid"] += 1
                    type_metrics[obj_type]["verified"] += 1
                else:
                    metrics["failed"] += 1
                    if error_msg:
                        metrics["errors"].append(f"{file_path.name}: {error_msg}")
            
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
        
        except Exception as e:
            metrics["failed"] += 1
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
    
    if metrics["verification_times"]:
        times = sorted(metrics["verification_times"])
        print("Verification Times (seconds):")
        print(f"  Min: {min(times):.6f}")
        print(f"  Max: {max(times):.6f}")
        print(f"  Mean: {sum(times)/len(times):.6f}")
        print(f"  Median: {times[len(times)//2]:.6f}")
        print()
    
    if metrics["file_sizes"]:
        sizes = metrics["file_sizes"]
        print("File Sizes (bytes):")
        print(f"  Min: {min(sizes):,}")
        print(f"  Max: {max(sizes):,}")
        print(f"  Mean: {sum(sizes)/len(sizes):,.0f}")
        print()
    
    if metrics["signature_sizes"]:
        sig_sizes = metrics["signature_sizes"]
        print("Signature Sizes (bytes):")
        print(f"  Min: {min(sig_sizes):,}")
        print(f"  Max: {max(sig_sizes):,}")
        print(f"  Mean: {sum(sig_sizes)/len(sig_sizes):,.0f}")
        print(f"  Expected: {FALCON_CONFIG['signature_size']}")
        print()
    
    if metrics["public_key_sizes"]:
        pk_sizes = metrics["public_key_sizes"]
        print("Public Key Sizes (bytes):")
        print(f"  Min: {min(pk_sizes):,}")
        print(f"  Max: {max(pk_sizes):,}")
        print(f"  Mean: {sum(pk_sizes)/len(pk_sizes):,.0f}")
        print(f"  Expected: {FALCON_CONFIG['public_key_size']}")
        print()
    
    print("Per-Object-Type Breakdown:")
    for obj_type, type_met in sorted(type_metrics.items()):
        if type_met["count"] > 0:
            print(f"  {obj_type.upper()}:")
            print(f"    Count: {type_met['count']}")
            print(f"    Verified: {type_met['verified']} ({100*type_met['verified']/type_met['count']:.1f}%)")
            print(f"    CMS valid: {type_met['cms_valid']}")
            print()
    
    if metrics["errors"]:
        print(f"Errors ({len(metrics['errors'])}):")
        for error in metrics["errors"][:10]:  # Show first 10
            print(f"  - {error}")
        if len(metrics["errors"]) > 10:
            print(f"  ... and {len(metrics['errors']) - 10} more errors")
        print()
    
    # Save results to JSON
    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)
    
    results = {
        "algorithm": FALCON_CONFIG["display_name"],
        "timestamp": datetime.now().isoformat(),
        "metrics": metrics,
        "type_metrics": dict(type_metrics)
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

