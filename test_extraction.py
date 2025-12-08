#!/usr/bin/env python3
"""
Test extraction by creating a known-good certificate and seeing what we extract.
"""

from oqs import Signature
from asn1crypto import x509, core, keys, algos
from asn1_rpki import (
    bytes_to_bitstring_tuple, 
    extract_public_key_from_certificate,
    extract_signature_and_tbs,
    replace_certificate_signature
)
import sys

def test():
    print("=" * 80)
    print("REVERSE TEST: Create certificate, then extract and verify")
    print("=" * 80)
    print()
    
    # Create signer
    signer = Signature("Falcon-512")
    keypair = signer.generate_keypair()
    if isinstance(keypair, tuple):
        public_key = keypair[0]
        private_key = keypair[1]
    else:
        public_key = keypair
        private_key = None
    
    print(f"Original public key:")
    print(f"  Size: {len(public_key)} bytes")
    print(f"  First 32 bytes: {public_key[:32].hex()}")
    print(f"  Last 32 bytes: {public_key[-32:].hex()}")
    print()
    
    # Create certificate with this key
    tbs_cert = x509.TbsCertificate({
        'version': 'v3',
        'serial_number': 1,
        'signature': algos.SignedDigestAlgorithm({
            'algorithm': algos.SignedDigestAlgorithmId('1.3.9999.3.1.1'),
            'parameters': core.Null()
        }),
        'issuer': x509.Name.build({'common_name': 'Test CA'}),
        'validity': x509.Validity({
            'not_before': x509.Time({'utc_time': core.UTCTime('20250101000000Z')}),
            'not_after': x509.Time({'utc_time': core.UTCTime('20251231235959Z')})
        }),
        'subject': x509.Name.build({'common_name': 'Test EE'}),
        'subject_public_key_info': keys.PublicKeyInfo({
            'algorithm': keys.PublicKeyAlgorithm({
                'algorithm': keys.PublicKeyAlgorithmId('1.3.9999.3.1.1'),
                'parameters': core.Null()
            }),
            'public_key': core.BitString(bytes_to_bitstring_tuple(public_key))
        })
    })
    
    tbs_data = tbs_cert.dump()
    signature = signer.sign(tbs_data)
    
    print(f"Signature:")
    print(f"  Size: {len(signature)} bytes (expected: 690)")
    print(f"  First 32 bytes: {signature[:32].hex()}")
    print()
    
    # Create certificate using replace_certificate_signature (same as resigning)
    cert_bytes = replace_certificate_signature(
        b'\x30\x82\x01\x00',  # Dummy - will be replaced
        signature,
        public_key,
        algorithm_name="Falcon-512"
    )
    
    # Actually, let's create it properly
    cert = x509.Certificate({
        'tbs_certificate': tbs_cert,
        'signature_algorithm': algos.SignedDigestAlgorithm({
            'algorithm': algos.SignedDigestAlgorithmId('1.3.9999.3.1.1'),
            'parameters': core.Null()
        }),
        'signature_value': core.OctetBitString(signature)
    })
    cert_bytes = cert.dump()
    
    print(f"Certificate created:")
    print(f"  Size: {len(cert_bytes)} bytes")
    print()
    
    # Now extract and see what we get
    print("EXTRACTION TEST:")
    print("-" * 80)
    
    # Extract signature and TBS
    extracted_tbs, extracted_sig = extract_signature_and_tbs(cert_bytes, 'certificate')
    print(f"Extracted TBS: {len(extracted_tbs)} bytes (original: {len(tbs_data)})")
    print(f"Extracted signature: {len(extracted_sig)} bytes (original: {len(signature)})")
    
    if extracted_tbs == tbs_data:
        print("  ✓ TBS matches")
    else:
        print("  ✗ TBS mismatch!")
        print(f"    Original first 32: {tbs_data[:32].hex()}")
        print(f"    Extracted first 32: {extracted_tbs[:32].hex()}")
    
    if extracted_sig == signature:
        print("  ✓ Signature matches")
    else:
        print("  ✗ Signature mismatch!")
        print(f"    Original first 32: {signature[:32].hex()}")
        print(f"    Extracted first 32: {extracted_sig[:32].hex()}")
    
    # Extract public key
    extracted_pubkey = extract_public_key_from_certificate(cert_bytes, 897)
    if extracted_pubkey:
        print(f"Extracted public key: {len(extracted_pubkey)} bytes")
        print(f"  First 32 bytes: {extracted_pubkey[:32].hex()}")
        print(f"  Last 32 bytes: {extracted_pubkey[-32:].hex()}")
        
        if extracted_pubkey == public_key:
            print("  ✓ Public key matches!")
        else:
            print("  ✗ Public key mismatch!")
            print(f"    Original first 32: {public_key[:32].hex()}")
            print(f"    Extracted first 32: {extracted_pubkey[:32].hex()}")
    else:
        print("  ✗ Failed to extract public key")
    
    # Test verification
    print()
    print("VERIFICATION TEST:")
    print("-" * 80)
    
    verifier = Signature("Falcon-512")
    
    # Verify with original
    result_orig = verifier.verify(tbs_data, signature, public_key)
    print(f"Original key + original sig + original TBS: {result_orig}")
    
    if extracted_pubkey and extracted_sig and extracted_tbs:
        result_ext = verifier.verify(extracted_tbs, extracted_sig, extracted_pubkey)
        print(f"Extracted key + extracted sig + extracted TBS: {result_ext}")
        
        # Cross-test
        result_cross1 = verifier.verify(tbs_data, signature, extracted_pubkey)
        print(f"Original TBS + original sig + extracted key: {result_cross1}")
        
        result_cross2 = verifier.verify(extracted_tbs, extracted_sig, public_key)
        print(f"Extracted TBS + extracted sig + original key: {result_cross2}")

if __name__ == "__main__":
    test()

