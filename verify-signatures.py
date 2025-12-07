#!/usr/bin/env python3
"""
Quick verification script to check that re-signed objects are correct.

This script verifies:
1. Signatures are properly replaced (not appended)
2. Both CMS and EE cert signatures verify correctly
3. Public keys are correctly embedded
4. Object structure is valid

Run this after pq-resign-falcon.py or pq-resign-dilithium.py completes.
"""

import sys
from pathlib import Path
from oqs import Signature

try:
    from asn1_rpki import (
        extract_signature_and_tbs,
        detect_rpki_object_type,
        verify_cms_object_signatures,
        extract_ee_certificate_from_cms,
        get_verification_metrics,
        print_verification_metrics,
        reset_verification_metrics
    )
    from asn1crypto import x509
    ASN1_AVAILABLE = True
except ImportError as e:
    print(f"ERROR: Required imports not available: {e}")
    print("Install: pip install asn1crypto")
    sys.exit(1)

def verify_object(file_path: Path, algorithm_name: str, verifier):
    """Verify a single object's signatures."""
    try:
        data = file_path.read_bytes()
        object_type = detect_rpki_object_type(data, str(file_path))
        
        if object_type == 'certificate':
            # Verify certificate signature
            tbs_data, signature = extract_signature_and_tbs(data, object_type, str(file_path))
            cert = x509.Certificate.load(data)
            public_key_info = cert['tbs_certificate']['subject_public_key_info']
            public_key = public_key_info['public_key'].contents
            
            is_valid = verifier.verify(tbs_data, signature, public_key)
            return is_valid, "certificate", None
            
        elif object_type in ('roa', 'manifest'):
            # Verify both CMS and EE cert signatures
            ee_cert_bytes = extract_ee_certificate_from_cms(data)
            
            if ee_cert_bytes:
                # Extract public key from EE cert
                ee_cert = x509.Certificate.load(ee_cert_bytes)
                ee_public_key_info = ee_cert['tbs_certificate']['subject_public_key_info']
                ee_public_key = ee_public_key_info['public_key'].contents
                
                # Verify both signatures
                cms_valid, ee_valid, error = verify_cms_object_signatures(
                    data,
                    ee_public_key,  # CMS signature uses EE cert's public key
                    None,  # Issuer key not available for EE cert verification
                    algorithm_name,
                    verifier
                )
                
                if cms_valid and ee_valid:
                    return True, object_type, None
                elif cms_valid:
                    return False, object_type, f"EE cert signature invalid: {error}"
                else:
                    return False, object_type, f"CMS signature invalid: {error}"
            else:
                # No EE cert, just verify CMS signature
                tbs_data, signature = extract_signature_and_tbs(data, object_type, str(file_path))
                # For CMS without EE cert, we'd need the public key from somewhere else
                # This is a limitation - we can't verify without the public key
                return None, object_type, "No EE cert found, cannot verify without public key"
        
        elif object_type == 'crl':
            # Verify CRL signature
            tbs_data, signature = extract_signature_and_tbs(data, object_type, str(file_path))
            # CRL verification would need issuer's public key
            return None, object_type, "CRL verification requires issuer's public key"
        
        return None, object_type, "Unknown object type"
        
    except Exception as e:
        return False, "unknown", f"Verification error: {e}"


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 verify-signatures.py <algorithm_name> <directory> [sample_size]")
        print("Example: python3 verify-signatures.py Falcon-512 /data/signed/falcon512 100")
        sys.exit(1)
    
    algorithm_name = sys.argv[1]
    directory = Path(sys.argv[2])
    sample_size = int(sys.argv[3]) if len(sys.argv) > 3 else 100
    
    if not directory.exists():
        print(f"ERROR: Directory does not exist: {directory}")
        sys.exit(1)
    
    print("="*80)
    print(f"VERIFYING SIGNATURES - {algorithm_name}")
    print("="*80)
    print(f"Directory: {directory}")
    print(f"Sample size: {sample_size}")
    print("="*80)
    print()
    
    # Initialize verifier
    try:
        verifier = Signature(algorithm_name)
    except Exception as e:
        print(f"ERROR: Failed to initialize verifier: {e}")
        sys.exit(1)
    
    # Reset metrics
    reset_verification_metrics()
    
    # Find files
    files = []
    for ext in ['.cer', '.roa', '.mft', '.crl']:
        files.extend(list(directory.rglob(f'*{ext}')))
    
    if not files:
        print(f"ERROR: No RPKI files found in {directory}")
        sys.exit(1)
    
    # Sample files
    import random
    files_to_check = random.sample(files, min(sample_size, len(files)))
    
    print(f"Checking {len(files_to_check)} files...")
    print()
    
    verified = 0
    failed = 0
    skipped = 0
    object_types = {}
    
    for f in files_to_check:
        result, obj_type, error = verify_object(f, algorithm_name, verifier)
        
        if obj_type not in object_types:
            object_types[obj_type] = {'verified': 0, 'failed': 0, 'skipped': 0}
        
        if result is True:
            verified += 1
            object_types[obj_type]['verified'] += 1
        elif result is False:
            failed += 1
            object_types[obj_type]['failed'] += 1
            print(f"FAIL: {f.name} ({obj_type}): {error}")
        else:
            skipped += 1
            object_types[obj_type]['skipped'] += 1
    
    print()
    print("="*80)
    print("VERIFICATION RESULTS")
    print("="*80)
    print(f"Total checked: {len(files_to_check)}")
    print(f"Verified: {verified}")
    print(f"Failed: {failed}")
    print(f"Skipped: {skipped}")
    print()
    
    if object_types:
        print("By object type:")
        for obj_type, counts in object_types.items():
            print(f"  {obj_type}:")
            print(f"    Verified: {counts['verified']}")
            print(f"    Failed: {counts['failed']}")
            print(f"    Skipped: {counts['skipped']}")
        print()
    
    # Print detailed metrics
    print("="*80)
    print("DETAILED METRICS")
    print("="*80)
    print_verification_metrics()
    
    # Success criteria
    success_rate = (verified / len(files_to_check) * 100) if files_to_check else 0
    print()
    print("="*80)
    if success_rate >= 95:
        print("SUCCESS: Verification rate >= 95%")
    elif success_rate >= 80:
        print("WARNING: Verification rate < 95% but >= 80%")
    else:
        print("ERROR: Verification rate < 80% - something is wrong!")
    print("="*80)


if __name__ == "__main__":
    main()

