#!/usr/bin/env python3
"""
Test script to verify if signing is correct or if validation is wrong.
Creates a test certificate, signs it, then tries to extract and verify.
"""

from oqs import Signature
from asn1crypto import x509, core, keys, algos
from asn1_rpki import bytes_to_bitstring_tuple, extract_public_key_from_certificate, extract_signature_and_tbs
import sys

def test_signing_and_extraction():
    print("=" * 80)
    print("Testing Signing vs Validation")
    print("=" * 80)
    print()
    
    # Initialize Falcon-512
    try:
        signer = Signature("Falcon-512")
        print("✓ Initialized Falcon-512 signer")
    except Exception as e:
        print(f"✗ Failed to initialize signer: {e}")
        return False
    
    # Generate keypair
    try:
        keypair = signer.generate_keypair()
        if isinstance(keypair, tuple) and len(keypair) >= 2:
            public_key = keypair[0]
            private_key = keypair[1]
        else:
            public_key = keypair[0] if isinstance(keypair, tuple) else keypair
            private_key = None
        print(f"✓ Generated keypair")
        print(f"  Public key size: {len(public_key)} bytes (expected: 897)")
        print(f"  Public key first 32 bytes: {public_key[:32].hex()}")
        print(f"  Public key last 32 bytes: {public_key[-32:].hex()}")
    except Exception as e:
        print(f"✗ Failed to generate keypair: {e}")
        return False
    
    # Create a simple test certificate
    try:
        # Create TBS certificate
        tbs_cert = x509.TbsCertificate({
            'version': 'v3',
            'serial_number': 1,
            'signature': algos.SignedDigestAlgorithm({
                'algorithm': algos.SignedDigestAlgorithmId('1.3.9999.3.1.1'),  # Falcon-512 OID
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
        
        # Sign the TBS
        tbs_data = tbs_cert.dump()
        signature = signer.sign(tbs_data)
        
        print(f"✓ Created test certificate")
        print(f"  TBS size: {len(tbs_data)} bytes")
        print(f"  Signature size: {len(signature)} bytes (expected: 690)")
        print(f"  Signature first 32 bytes: {signature[:32].hex()}")
        
        # Create full certificate
        cert = x509.Certificate({
            'tbs_certificate': tbs_cert,
            'signature_algorithm': algos.SignedDigestAlgorithm({
                'algorithm': algos.SignedDigestAlgorithmId('1.3.9999.3.1.1'),
                'parameters': core.Null()
            }),
            'signature_value': core.OctetBitString(signature)
        })
        
        cert_bytes = cert.dump()
        print(f"  Certificate size: {len(cert_bytes)} bytes")
        print()
        
    except Exception as e:
        print(f"✗ Failed to create certificate: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test extraction
    print("Testing Extraction:")
    print("-" * 80)
    
    # Extract signature and TBS
    try:
        extracted_tbs, extracted_sig = extract_signature_and_tbs(cert_bytes, 'certificate')
        print(f"✓ Extracted signature and TBS")
        print(f"  Extracted TBS size: {len(extracted_tbs)} bytes (original: {len(tbs_data)})")
        print(f"  Extracted signature size: {len(extracted_sig)} bytes (original: {len(signature)})")
        
        if extracted_tbs != tbs_data:
            print(f"  ⚠ TBS mismatch! First 32 bytes:")
            print(f"    Original: {tbs_data[:32].hex()}")
            print(f"    Extracted: {extracted_tbs[:32].hex()}")
        else:
            print(f"  ✓ TBS matches")
        
        if extracted_sig != signature:
            print(f"  ⚠ Signature mismatch! First 32 bytes:")
            print(f"    Original: {signature[:32].hex()}")
            print(f"    Extracted: {extracted_sig[:32].hex()}")
        else:
            print(f"  ✓ Signature matches")
    except Exception as e:
        print(f"✗ Failed to extract signature/TBS: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Extract public key
    try:
        extracted_pubkey = extract_public_key_from_certificate(cert_bytes, 897)
        if extracted_pubkey:
            print(f"✓ Extracted public key")
            print(f"  Extracted size: {len(extracted_pubkey)} bytes (original: {len(public_key)})")
            print(f"  Extracted first 32 bytes: {extracted_pubkey[:32].hex()}")
            print(f"  Original first 32 bytes: {public_key[:32].hex()}")
            
            if extracted_pubkey == public_key:
                print(f"  ✓ Public key matches!")
            else:
                print(f"  ✗ Public key mismatch!")
        else:
            print(f"✗ Failed to extract public key")
            return False
    except Exception as e:
        print(f"✗ Failed to extract public key: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test verification
    print()
    print("Testing Verification:")
    print("-" * 80)
    
    try:
        verifier = Signature("Falcon-512")
        
        # Verify with original key
        result_original = verifier.verify(tbs_data, signature, public_key)
        print(f"Verification with original key: {result_original}")
        
        # Verify with extracted key
        result_extracted = verifier.verify(extracted_tbs, extracted_sig, extracted_pubkey)
        print(f"Verification with extracted key: {result_extracted}")
        
        if result_original and result_extracted:
            print("✓ Both verifications passed!")
            return True
        else:
            print("✗ Verification failed!")
            return False
    except Exception as e:
        print(f"✗ Verification error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_signing_and_extraction()
    sys.exit(0 if success else 1)

