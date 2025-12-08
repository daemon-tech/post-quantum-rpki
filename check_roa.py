#!/usr/bin/env python3
"""Quick check of a ROA file structure"""

from pathlib import Path
from asn1crypto import cms, x509, core
from asn1_rpki import extract_signature_and_tbs, extract_ee_certificate_from_cms, extract_public_key_from_certificate

# Find first ROA file
falcon_dir = Path("/data/signed/falcon512")
roa_files = list(falcon_dir.rglob("*.roa"))

if not roa_files:
    print("No ROA files found")
    exit(1)

roa_file = roa_files[0]
print(f"Checking: {roa_file.name}")
print("=" * 80)

# Read file
with open(roa_file, 'rb') as f:
    data = f.read()

print(f"File size: {len(data)} bytes")
print()

# Parse CMS
try:
    cms_obj = cms.ContentInfo.load(data)
    signed_data = cms_obj['content']
    print("✓ CMS structure valid")
    
    # Check signer info
    if len(signed_data['signer_infos']) > 0:
        signer_info = signed_data['signer_infos'][0]
        print(f"✓ SignerInfo found")
        
        # Check digest algorithm
        if 'digest_algorithm' in signer_info:
            digest_alg = signer_info['digest_algorithm']
            alg_oid = digest_alg['algorithm'].dotted
            print(f"  Digest algorithm OID: {alg_oid}")
            print(f"  Expected (Falcon-512): 1.3.9999.3.6.4")
            if alg_oid == "1.3.9999.3.6.4":
                print("  ✓ Correct OID")
            else:
                print("  ✗ Wrong OID")
        
        # Check signature - use proper extraction method
        if 'signature' in signer_info:
            sig_obj = signer_info['signature']
            # Use the same extraction method as extract_signature_and_tbs
            try:
                sig_dump = sig_obj.dump()
                # OctetString dump: [0x04][length][data]
                if len(sig_dump) >= 3 and sig_dump[0] == 0x04:
                    idx = 1
                    len_byte = sig_dump[idx]
                    idx += 1
                    if (len_byte & 0x80) == 0:
                        sig_length = len_byte
                    else:
                        len_bytes = len_byte & 0x7F
                        if 0 < len_bytes <= 4 and idx + len_bytes <= len(sig_dump):
                            sig_length = int.from_bytes(sig_dump[idx:idx+len_bytes], 'big')
                            idx += len_bytes
                        else:
                            sig_length = 0
                    if idx + sig_length <= len(sig_dump):
                        signature_bytes = sig_dump[idx:idx+sig_length]
                        sig_size = len(signature_bytes)
                    else:
                        sig_size = len(sig_obj.contents) if hasattr(sig_obj, 'contents') else len(bytes(sig_obj))
                else:
                    sig_size = len(sig_obj.contents) if hasattr(sig_obj, 'contents') else len(bytes(sig_obj))
            except:
                sig_size = len(sig_obj.contents) if hasattr(sig_obj, 'contents') else len(bytes(sig_obj))
            
            print(f"  Signature size: {sig_size} bytes (expected: 690)")
            print(f"  Signature dump size: {len(sig_obj.dump())} bytes")
            if sig_size == 690:
                print("  ✓ Correct signature size")
            else:
                print("  ✗ Wrong signature size")
                if sig_size == 653:
                    print("    ⚠ Signature appears truncated (653 vs 690 bytes)")
    
    # Check certificates
    if 'certificates' in signed_data and len(signed_data['certificates']) > 0:
        print(f"✓ Certificates found: {len(signed_data['certificates'])}")
        
        # Extract EE cert
        ee_cert_bytes = extract_ee_certificate_from_cms(data)
        if ee_cert_bytes:
            print(f"✓ EE certificate extracted: {len(ee_cert_bytes)} bytes")
            
            # Parse certificate
            cert = x509.Certificate.load(ee_cert_bytes)
            
            # Check signature algorithm
            sig_alg_oid = cert['signature_algorithm']['algorithm'].dotted
            print(f"  Certificate signature OID: {sig_alg_oid}")
            if sig_alg_oid == "1.3.9999.3.6.4":
                print("  ✓ Correct signature OID")
            else:
                print("  ✗ Wrong signature OID")
            
            # Check public key algorithm
            pubkey_alg_oid = cert['tbs_certificate']['subject_public_key_info']['algorithm']['algorithm'].dotted
            print(f"  Public key algorithm OID: {pubkey_alg_oid}")
            if pubkey_alg_oid == "1.3.9999.3.6.4":
                print("  ✓ Correct public key OID")
            else:
                print("  ✗ Wrong public key OID (this is the known issue)")
            
            # Try to extract public key
            pubkey = extract_public_key_from_certificate(ee_cert_bytes, 897)
            if pubkey:
                print(f"  Public key extracted: {len(pubkey)} bytes (expected: 897)")
                if len(pubkey) == 897:
                    print("  ✓ Correct public key size")
                else:
                    print("  ✗ Wrong public key size")
            else:
                print("  ✗ Failed to extract public key")
        else:
            print("✗ Failed to extract EE certificate")
    else:
        print("✗ No certificates found")
    
    # Extract TBS and signature
    try:
        tbs_data, signature = extract_signature_and_tbs(data, 'roa')
        print(f"\n✓ TBS extracted: {len(tbs_data)} bytes")
        print(f"✓ Signature extracted: {len(signature)} bytes")
        
        if len(tbs_data) < 200:
            print("  ⚠ TBS seems small (might be incomplete)")
        if len(signature) != 690:
            print(f"  ⚠ Signature size mismatch (got {len(signature)}, expected 690)")
    except Exception as e:
        print(f"✗ Failed to extract TBS/signature: {e}")
    
except Exception as e:
    print(f"✗ Error parsing CMS: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 80)

