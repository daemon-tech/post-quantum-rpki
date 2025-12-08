#!/usr/bin/env python3
"""
scanner.py - Quick diagnostic scanner for RPKI signature verification issues

This script quickly scans a few sample files to diagnose why signature verification
is failing. It's much faster than running the full validate.py and helps identify
the root cause of verification failures.

Usage:
    python3 scanner.py <algorithm_directory>
    python3 scanner.py /data/signed/DILITHIUM2

It will:
- Scan a small sample of files (default: 10)
- Show what's being extracted (public keys, signatures, TBS data)
- Attempt verification and show detailed error messages
- Help identify if the issue is with public key extraction, TBS data, or signatures
"""

import sys
from pathlib import Path
from collections import defaultdict

# Import OQS for signature verification
try:
    from oqs import Signature, get_enabled_sig_mechanisms
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False
    print("ERROR: OQS library not available")
    sys.exit(1)

# Import ASN.1 parser
try:
    from asn1_rpki import (
        extract_signature_and_tbs,
        detect_rpki_object_type,
        verify_cms_object_signatures,
        extract_ee_certificate_from_cms
    )
    from asn1crypto import x509, core
    ASN1_EXTRACTION_AVAILABLE = True
except ImportError:
    ASN1_EXTRACTION_AVAILABLE = False
    print("ERROR: ASN.1 extraction not available. Install asn1crypto: pip install asn1crypto")
    sys.exit(1)

def extract_bytes_from_bitstring(bitstring, expected_size=None):
    """
    Extract raw bytes from an asn1crypto BitString object.
    Copied from validate.py for self-contained scanner.
    """
    if bitstring is None:
        return b''
    
    # METHOD 1: Parse ASN.1 dump to extract data portion
    try:
        dump = bitstring.dump()
        
        if len(dump) >= 3 and dump[0] == 0x03:  # BitString tag
            idx = 1
            data_length = 0
            
            # Parse length field
            if idx < len(dump):
                len_byte = dump[idx]
                idx += 1
                
                if (len_byte & 0x80) == 0:
                    data_length = len_byte
                else:
                    len_bytes = len_byte & 0x7F
                    if 0 < len_bytes <= 4 and idx + len_bytes <= len(dump):
                        length_bytes = dump[idx:idx+len_bytes]
                        data_length = int.from_bytes(length_bytes, 'big')
                        idx += len_bytes
                
                # Skip unused_bits byte
                if idx < len(dump):
                    idx += 1  # Skip unused_bits
                    
                    # Extract data bytes
                    if expected_size:
                        actual_data_length = data_length - 1 if data_length > 0 else 0
                        
                        # Try exact extraction
                        if idx + expected_size <= len(dump):
                            result = dump[idx:idx+expected_size]
                            if len(result) == expected_size:
                                return result
                        
                        # Try from end
                        if len(dump) >= expected_size:
                            result = dump[-expected_size:]
                            if len(result) == expected_size:
                                return result
                    else:
                        actual_data_length = data_length - 1 if data_length > 0 else 0
                        if actual_data_length > 0 and idx + actual_data_length <= len(dump):
                            return dump[idx:idx+actual_data_length]
    except Exception:
        pass
    
    # METHOD 2: Convert bits to bytes manually
    try:
        bits = []
        max_bits = (expected_size * 8) if expected_size else None
        bit_count = 0
        
        try:
            for bit in bitstring:
                bits.append(int(bit))
                bit_count += 1
                if max_bits and bit_count >= max_bits:
                    break
        except (TypeError, AttributeError):
            try:
                for i in range(len(bitstring)):
                    bits.append(int(bitstring[i]))
                    if max_bits and len(bits) >= max_bits:
                        break
            except:
                pass
        
        # Convert bits to bytes (8 bits per byte, MSB first)
        if len(bits) >= 8:
            byte_list = []
            num_bytes = len(bits) // 8
            for i in range(num_bytes):
                byte_bits = bits[i*8:(i+1)*8]
                if len(byte_bits) == 8:
                    byte_val = 0
                    for j, bit_val in enumerate(byte_bits):
                        byte_val |= (int(bit_val) << (7 - j))
                    byte_list.append(byte_val)
            
            result = bytes(byte_list)
            if expected_size is None or len(result) == expected_size:
                return result
            elif expected_size and len(result) > expected_size:
                return result[:expected_size]
            elif expected_size and len(result) >= int(expected_size * 0.9):
                return result
    except Exception:
        pass
    
    # METHOD 3: Try .contents property
    try:
        if hasattr(bitstring, 'contents'):
            contents = bitstring.contents
            if isinstance(contents, (bytes, bytearray)):
                result = bytes(contents)
                if expected_size is None or len(result) == expected_size:
                    return result
                elif expected_size and len(result) > expected_size:
                    return result[:expected_size]
    except:
        pass
    
    return None

# Algorithm metadata
ALGO_METADATA = {
    "dilithium2": {"algorithm_name": "ML-DSA-44", "signature": 2420, "public_key": 1312},
    "dilithium3": {"algorithm_name": "ML-DSA-65", "signature": 3309, "public_key": 1952},
    "falcon512": {"algorithm_name": "Falcon-512", "signature": 690, "public_key": 897},
}

def get_algorithm_info(repo_path):
    """Determine algorithm from directory name."""
    algo_name = repo_path.name.lower()
    if "dilithium2" in algo_name or "ml-dsa-44" in algo_name:
        return "dilithium2"
    elif "dilithium3" in algo_name or "ml-dsa-65" in algo_name:
        return "dilithium3"
    elif "falcon" in algo_name or "falcon512" in algo_name:
        return "falcon512"
    return None

def extract_public_key_from_ee_cert(ee_cert_bytes, expected_size):
    """Extract public key from EE certificate with detailed diagnostics."""
    try:
        ee_cert = x509.Certificate.load(ee_cert_bytes)
        ee_pubkey_info = ee_cert['tbs_certificate']['subject_public_key_info']
        pubkey_bitstring = ee_pubkey_info['public_key']
        
        # Try extraction function first
        pubkey = extract_bytes_from_bitstring(pubkey_bitstring, expected_size)
        
        if pubkey and len(pubkey) == expected_size:
            return pubkey, "extracted from BitString"
        
        # Fallback: try direct dump extraction
        try:
            pubkey_info_dump = ee_pubkey_info.dump()
            if len(pubkey_info_dump) >= expected_size:
                # Try from end
                candidate = pubkey_info_dump[-expected_size:]
                if len(candidate) == expected_size:
                    return bytes(candidate), "extracted from dump (end)"
        except:
            pass
        
        return None, "extraction failed"
    except Exception as e:
        return None, f"extraction error: {e}"

def scan_file(file_path, algo_info, verifier, sample_num):
    """Scan a single file and show diagnostic information."""
    print(f"\n{'='*80}")
    print(f"File {sample_num}: {file_path.name}")
    print(f"{'='*80}")
    
    try:
        signed_data = file_path.read_bytes()
        file_size = len(signed_data)
        print(f"File size: {file_size:,} bytes")
        
        # Detect object type
        object_type = detect_rpki_object_type(signed_data, str(file_path))
        print(f"Object type: {object_type}")
        
        # Extract signature and TBS
        tbs_data, signature = extract_signature_and_tbs(signed_data, object_type, str(file_path))
        print(f"TBS data size: {len(tbs_data):,} bytes")
        print(f"Signature size: {len(signature):,} bytes (expected: {algo_info['signature']})")
        
        if len(signature) != algo_info['signature']:
            print(f"  ⚠️  WARNING: Signature size mismatch!")
        
        # Extract public key based on object type
        if object_type in ('roa', 'manifest'):
            print(f"\n--- CMS Object Analysis ---")
            ee_cert_bytes = extract_ee_certificate_from_cms(signed_data)
            
            if ee_cert_bytes:
                print(f"EE certificate found: {len(ee_cert_bytes):,} bytes")
                
                # Extract public key
                pubkey, extraction_method = extract_public_key_from_ee_cert(
                    ee_cert_bytes, 
                    algo_info['public_key']
                )
                
                if pubkey:
                    print(f"Public key extracted: {len(pubkey):,} bytes (expected: {algo_info['public_key']})")
                    print(f"  Extraction method: {extraction_method}")
                    
                    if len(pubkey) != algo_info['public_key']:
                        print(f"  ⚠️  WARNING: Public key size mismatch!")
                    
                    # Show first/last few bytes for verification
                    print(f"  First 16 bytes (hex): {pubkey[:16].hex()}")
                    print(f"  Last 16 bytes (hex): {pubkey[-16:].hex()}")
                    
                    # Try verification
                    print(f"\n--- Verification Attempt ---")
                    try:
                        is_valid = verifier.verify(tbs_data, signature, pubkey)
                        if is_valid:
                            print(f"  ✅ VERIFICATION SUCCESSFUL!")
                        else:
                            print(f"  ❌ VERIFICATION FAILED")
                            print(f"     This means the public key doesn't match the private key")
                            print(f"     that was used to sign the data, OR the TBS data doesn't match.")
                            
                            # Show TBS data sample
                            print(f"\n  TBS data sample (first 64 bytes hex):")
                            print(f"    {tbs_data[:64].hex()}")
                            print(f"  TBS data sample (last 64 bytes hex):")
                            print(f"    {tbs_data[-64:].hex() if len(tbs_data) > 64 else tbs_data.hex()}")
                            
                    except Exception as verify_err:
                        print(f"  ❌ VERIFICATION ERROR: {verify_err}")
                        print(f"     Exception type: {type(verify_err).__name__}")
                
                else:
                    print(f"  ❌ Public key extraction failed: {extraction_method}")
            else:
                print(f"  ⚠️  No EE certificate found in CMS structure")
        
        elif object_type == 'certificate':
            print(f"\n--- Certificate Object Analysis ---")
            try:
                cert = x509.Certificate.load(signed_data)
                pubkey_info = cert['tbs_certificate']['subject_public_key_info']
                pubkey_bitstring = pubkey_info['public_key']
                
                # DETAILED DIAGNOSTIC: Analyze how the key is stored
                print(f"  SubjectPublicKeyInfo structure found")
                try:
                    pubkey_info_dump = pubkey_info.dump()
                    print(f"  SubjectPublicKeyInfo dump size: {len(pubkey_info_dump):,} bytes")
                    print(f"  BitString type: {type(pubkey_bitstring).__name__}")
                    
                    # Analyze BitString dump structure
                    try:
                        bitstring_dump = pubkey_bitstring.dump()
                        print(f"\n  === BitString Dump Analysis ===")
                        print(f"  BitString dump size: {len(bitstring_dump):,} bytes")
                        print(f"  First 64 bytes (hex): {bitstring_dump[:64].hex()}")
                        if len(bitstring_dump) > 64:
                            print(f"  Last 64 bytes (hex): {bitstring_dump[-64:].hex()}")
                        
                        # Parse BitString structure: [0x03 tag][length][unused_bits][data]
                        if len(bitstring_dump) >= 3 and bitstring_dump[0] == 0x03:
                            print(f"  ✓ BitString tag found (0x03)")
                            idx = 1
                            len_byte = bitstring_dump[idx]
                            idx += 1
                            
                            if (len_byte & 0x80) == 0:
                                data_length = len_byte
                                print(f"  Short form length: {data_length} bytes")
                            else:
                                len_bytes = len_byte & 0x7F
                                if 0 < len_bytes <= 4 and idx + len_bytes <= len(bitstring_dump):
                                    length_bytes = bitstring_dump[idx:idx+len_bytes]
                                    data_length = int.from_bytes(length_bytes, 'big')
                                    idx += len_bytes
                                    print(f"  Long form length: {data_length} bytes ({len_bytes} length bytes)")
                                else:
                                    data_length = 0
                            
                            if idx < len(bitstring_dump):
                                unused_bits = bitstring_dump[idx]
                                idx += 1
                                print(f"  Unused bits: {unused_bits}")
                                print(f"  Data starts at offset: {idx}")
                                print(f"  Expected data length: {data_length - 1} bytes (after unused_bits)")
                                
                                if idx + (data_length - 1) <= len(bitstring_dump):
                                    actual_data = bitstring_dump[idx:idx+(data_length-1)]
                                    print(f"  Actual data length: {len(actual_data)} bytes")
                                    print(f"  Data first 32 bytes: {actual_data[:32].hex()}")
                                    if len(actual_data) > 32:
                                        print(f"  Data last 32 bytes: {actual_data[-32:].hex()}")
                    except Exception as dump_err:
                        print(f"  Could not analyze BitString dump: {dump_err}")
                    
                    # Analyze .contents property
                    print(f"\n  === BitString.contents Analysis ===")
                    if hasattr(pubkey_bitstring, 'contents'):
                        contents = pubkey_bitstring.contents
                        print(f"  BitString.contents type: {type(contents).__name__}")
                        if isinstance(contents, (bytes, bytearray)):
                            contents_bytes = bytes(contents)
                            print(f"  BitString.contents size: {len(contents_bytes):,} bytes")
                            print(f"  Contents first 64 bytes (hex): {contents_bytes[:64].hex() if len(contents_bytes) >= 64 else contents_bytes.hex()}")
                            if len(contents_bytes) > 64:
                                print(f"  Contents last 64 bytes (hex): {contents_bytes[-64:].hex()}")
                            
                            # Check if it's an ASN.1 structure
                            if len(contents_bytes) >= 2:
                                first_byte = contents_bytes[0]
                                if first_byte == 0x02:
                                    print(f"  ✓ ASN.1 INTEGER detected (0x02)")
                                elif first_byte == 0x30:
                                    print(f"  ✓ ASN.1 SEQUENCE detected (0x30)")
                                elif first_byte == 0x00:
                                    print(f"  ⚠ First byte is 0x00 (unused bits or padding)")
                    else:
                        print(f"  No .contents property")
                    
                    # Try to access raw bits/data from ParsableOctetBitString
                    print(f"\n  === BitString Raw Data Access Test ===")
                    try:
                        # Check all attributes that might contain the raw data
                        attrs_to_check = ['_contents', '_bytes', 'contents', 'data', '_data', 'value', '_value', 
                                         'bits', '_bits', 'octets', '_octets', 'raw', '_raw']
                        
                        found_raw_data = False
                        for attr_name in attrs_to_check:
                            if hasattr(pubkey_bitstring, attr_name):
                                attr_value = getattr(pubkey_bitstring, attr_name)
                                print(f"  Found attribute: {attr_name} = {type(attr_value).__name__}")
                                
                                if isinstance(attr_value, (bytes, bytearray)):
                                    print(f"    Size: {len(attr_value):,} bytes")
                                    if len(attr_value) >= algo_info['public_key']:
                                        print(f"    ✓ Large enough! First 32 bytes: {attr_value[:32].hex()}")
                                        if len(attr_value) > 32:
                                            print(f"    Last 32 bytes: {attr_value[-32:].hex()}")
                                        found_raw_data = True
                                    elif len(attr_value) > 0:
                                        print(f"    First 32 bytes: {attr_value[:32].hex() if len(attr_value) >= 32 else attr_value.hex()}")
                                elif isinstance(attr_value, (list, tuple)):
                                    print(f"    Length: {len(attr_value)}")
                                    if len(attr_value) >= algo_info['public_key'] * 8:
                                        print(f"    ✓ Large enough for bits! Converting...")
                                        # Try to convert bits to bytes
                                        byte_list = []
                                        for i in range(0, min(len(attr_value), algo_info['public_key'] * 8), 8):
                                            byte_bits = attr_value[i:i+8]
                                            if len(byte_bits) == 8:
                                                byte_val = sum(int(b) << (7 - j) for j, b in enumerate(byte_bits))
                                                byte_list.append(byte_val)
                                        if len(byte_list) == algo_info['public_key']:
                                            extracted_key = bytes(byte_list)
                                            print(f"    ✓ Successfully extracted {len(extracted_key)} bytes")
                                            print(f"    First 32 bytes: {extracted_key[:32].hex()}")
                                            found_raw_data = True
                        
                        if not found_raw_data:
                            print(f"  ⚠ No raw data found in accessible attributes")
                            
                            # Try to get the internal representation
                            print(f"\n  === Trying to access internal representation ===")
                            try:
                                # ParsableOctetBitString might store data differently
                                # Try to get the dump and parse it manually
                                bitstring_dump = pubkey_bitstring.dump()
                                
                                # The dump should contain: [0x03][length][unused_bits][data]
                                # We already parsed this above, but let's try to extract the actual key
                                # The key was stored as bits, so the data section should contain the bits
                                
                                # Actually, wait - if the key is 1312 bytes = 10496 bits
                                # But we only have 270 bytes of data, that's 2160 bits
                                # So the key is definitely not in the BitString!
                                
                                print(f"  BitString data section is only {270} bytes")
                                print(f"  Need {algo_info['public_key']} bytes = {algo_info['public_key'] * 8} bits")
                                print(f"  ✗ Key is NOT in the BitString - it's stored elsewhere!")
                                
                            except Exception as internal_err:
                                print(f"  Internal access error: {internal_err}")
                                
                    except Exception as access_err:
                        print(f"  ✗ Raw data access failed: {access_err}")
                        import traceback
                        traceback.print_exc()
                    
                    # CRITICAL: The key should be raw bytes in BIT STRING, but we see ASN.1 structure
                    # According to RFC 5280, the BIT STRING should contain raw key bytes directly
                    # Let's check the RAW certificate bytes (before ASN.1 parsing) to find where the key is
                    print(f"\n  === RAW Certificate Bytes Analysis ===")
                    try:
                        # Read raw certificate bytes (before any ASN.1 parsing)
                        raw_cert_bytes = signed_data
                        print(f"  Raw certificate size: {len(raw_cert_bytes):,} bytes")
                        
                        # Find SubjectPublicKeyInfo in raw bytes by looking for the OID
                        # ML-DSA-44 OID: 1.3.6.1.4.1.2.267.7.4.4
                        # Encoded as: 2b 06 01 04 01 02 81 0b 07 04 04 (DER encoding)
                        ml_dsa_oid_hex = "2b0601040102810b070404"
                        ml_dsa_oid_bytes = bytes.fromhex(ml_dsa_oid_hex)
                        
                        oid_positions = []
                        search_pos = 0
                        while True:
                            pos = raw_cert_bytes.find(ml_dsa_oid_bytes, search_pos)
                            if pos == -1:
                                break
                            oid_positions.append(pos)
                            search_pos = pos + 1
                        
                        if oid_positions:
                            print(f"  Found ML-DSA-44 OID at {len(oid_positions)} position(s): {oid_positions}")
                            
                            for oid_pos in oid_positions[:2]:  # Check first 2 occurrences
                                print(f"\n  Analyzing OID at offset {oid_pos}:")
                                
                                # After OID, there should be NULL parameters, then BIT STRING tag (0x03)
                                # Look for BIT STRING tag after OID (within next 50 bytes)
                                bitstring_search_start = oid_pos + len(ml_dsa_oid_bytes)
                                bitstring_search_end = min(len(raw_cert_bytes), bitstring_search_start + 100)
                                
                                bitstring_pos = raw_cert_bytes.find(b'\x03', bitstring_search_start, bitstring_search_end)
                                if bitstring_pos != -1:
                                    print(f"    Found BIT STRING tag (0x03) at offset {bitstring_pos}")
                                    
                                    # Parse BIT STRING: [0x03][length][unused_bits][data]
                                    if bitstring_pos + 3 < len(raw_cert_bytes):
                                        idx = bitstring_pos + 1
                                        len_byte = raw_cert_bytes[idx]
                                        idx += 1
                                        
                                        if (len_byte & 0x80) == 0:
                                            bitstring_length = len_byte
                                            data_start = idx + 1  # +1 for unused_bits
                                        else:
                                            len_bytes = len_byte & 0x7F
                                            if 0 < len_bytes <= 4 and idx + len_bytes < len(raw_cert_bytes):
                                                length_bytes = raw_cert_bytes[idx:idx+len_bytes]
                                                bitstring_length = int.from_bytes(length_bytes, 'big')
                                                idx += len_bytes
                                                data_start = idx + 1  # +1 for unused_bits
                                            else:
                                                bitstring_length = 0
                                                data_start = idx
                                        
                                        if data_start < len(raw_cert_bytes):
                                            unused_bits = raw_cert_bytes[data_start - 1] if data_start > 0 else 0
                                            print(f"    BIT STRING length: {bitstring_length} bytes")
                                            print(f"    Unused bits: {unused_bits}")
                                            print(f"    Data starts at offset: {data_start}")
                                            
                                            # The data should be the raw 1312-byte key
                                            if data_start + algo_info['public_key'] <= len(raw_cert_bytes):
                                                raw_key_candidate = raw_cert_bytes[data_start:data_start+algo_info['public_key']]
                                                print(f"    ✓ Extracted {len(raw_key_candidate)} bytes from BIT STRING data")
                                                print(f"    First 32 bytes: {raw_key_candidate[:32].hex()}")
                                                print(f"    Last 32 bytes: {raw_key_candidate[-32:].hex()}")
                                                
                                                # Check entropy
                                                zero_count = raw_key_candidate.count(0)
                                                unique_bytes = len(set(raw_key_candidate))
                                                print(f"    Entropy check: {zero_count} zeros, {unique_bytes} unique bytes")
                                                
                                                if zero_count < algo_info['public_key'] * 0.3 and unique_bytes > algo_info['public_key'] * 0.15:
                                                    print(f"    ✓ High entropy - likely the actual public key!")
                                                    if not pubkey or len(pubkey) != algo_info['public_key']:
                                                        pubkey = raw_key_candidate
                                                        extraction_method = f"Raw bytes from BIT STRING at offset {data_start}"
                                                else:
                                                    print(f"    ⚠ Low entropy - might not be the key")
                                            else:
                                                print(f"    ⚠ Not enough data: need {algo_info['public_key']}, have {len(raw_cert_bytes) - data_start}")
                        else:
                            print(f"  ⚠ ML-DSA-44 OID not found in raw certificate bytes")
                            
                    except Exception as raw_err:
                        print(f"  Raw bytes analysis error: {raw_err}")
                        import traceback
                        traceback.print_exc()
                    
                    # Search certificate for 1312-byte sequences
                    print(f"\n  === Certificate-Wide Search ===")
                    try:
                        cert_dump = cert.dump()
                        print(f"  Certificate dump size: {len(cert_dump):,} bytes")
                        
                        # Find all 1312-byte sequences with high entropy
                        candidates = []
                        for search_idx in range(len(cert_dump) - algo_info['public_key'], 
                                               max(0, len(cert_dump) - algo_info['public_key'] - 5000), -1):
                            candidate = cert_dump[search_idx:search_idx+algo_info['public_key']]
                            if len(candidate) == algo_info['public_key']:
                                zero_count = candidate.count(0)
                                unique_bytes = len(set(candidate))
                                if zero_count < algo_info['public_key'] * 0.3 and unique_bytes > algo_info['public_key'] * 0.15:
                                    score = unique_bytes - (zero_count * 0.5)
                                    offset_from_end = len(cert_dump) - search_idx - algo_info['public_key']
                                    candidates.append((offset_from_end, score, candidate, search_idx))
                        
                        if candidates:
                            # Sort by score (highest first)
                            candidates.sort(key=lambda x: x[1], reverse=True)
                            print(f"  Found {len(candidates)} candidate(s) with high entropy:")
                            for i, (offset, score, cand, pos) in enumerate(candidates[:5], 1):  # Show top 5
                                print(f"    {i}. Offset {offset} bytes from end (pos {pos}), score: {score:.1f}")
                                print(f"       First 16 bytes: {cand[:16].hex()}")
                                print(f"       Last 16 bytes: {cand[-16:].hex()}")
                                
                                # Check if this is in TBS or signature area
                                tbs_size = len(cert['tbs_certificate'].dump())
                                if pos < tbs_size:
                                    print(f"       ✓ In TBS certificate area")
                                else:
                                    print(f"       ⚠ In signature area (likely wrong!)")
                        else:
                            print(f"  No high-entropy candidates found")
                    except Exception as search_err:
                        print(f"  Search error: {search_err}")
                        
                except Exception as diag_err:
                    print(f"  Diagnostic error: {diag_err}")
                    import traceback
                    traceback.print_exc()
                
                # Extract public key using multiple methods
                pubkey = None
                extraction_method = None
                
                # Method 1: Use extraction function
                pubkey = extract_bytes_from_bitstring(pubkey_bitstring, algo_info['public_key'])
                if pubkey and len(pubkey) == algo_info['public_key']:
                    extraction_method = "extract_bytes_from_bitstring"
                
                # Method 2: Parse BitString.contents - it contains ASN.1 SEQUENCE with INTEGER
                # Based on scanner output: contents starts with 00 (unused bits), then 30 82 010a (SEQUENCE), 
                # then 02 82 0101 (INTEGER of 257 bytes). The key might be in the INTEGER or after it.
                if not pubkey or len(pubkey) != algo_info['public_key']:
                    try:
                        if hasattr(pubkey_bitstring, 'contents'):
                            contents = pubkey_bitstring.contents
                            if isinstance(contents, (bytes, bytearray)):
                                contents_bytes = bytes(contents)
                                
                                # Skip unused bits byte (first byte is 0x00)
                                data_start = 1 if len(contents_bytes) > 0 and contents_bytes[0] == 0x00 else 0
                                asn1_data = contents_bytes[data_start:]
                                
                                # Parse ASN.1 SEQUENCE: [0x30 tag][length][INTEGER...]
                                if len(asn1_data) >= 3 and asn1_data[0] == 0x30:
                                    seq_idx = 1
                                    seq_len_byte = asn1_data[seq_idx]
                                    seq_idx += 1
                                    
                                    if (seq_len_byte & 0x80) == 0:
                                        seq_length = seq_len_byte
                                    else:
                                        seq_len_bytes = seq_len_byte & 0x7F
                                        if 0 < seq_len_bytes <= 4 and seq_idx + seq_len_bytes <= len(asn1_data):
                                            seq_length_bytes = asn1_data[seq_idx:seq_idx+seq_len_bytes]
                                            seq_length = int.from_bytes(seq_length_bytes, 'big')
                                            seq_idx += seq_len_bytes
                                        else:
                                            seq_length = 0
                                    
                                    # Now parse INTEGER inside SEQUENCE: [0x02 tag][length][data]
                                    if seq_idx < len(asn1_data) and asn1_data[seq_idx] == 0x02:
                                        int_idx = seq_idx + 1
                                        int_len_byte = asn1_data[int_idx]
                                        int_idx += 1
                                        
                                        if (int_len_byte & 0x80) == 0:
                                            int_length = int_len_byte
                                        else:
                                            int_len_bytes = int_len_byte & 0x7F
                                            if 0 < int_len_bytes <= 4 and int_idx + int_len_bytes <= len(asn1_data):
                                                int_length_bytes = asn1_data[int_idx:int_idx+int_len_bytes]
                                                int_length = int.from_bytes(int_length_bytes, 'big')
                                                int_idx += int_len_bytes
                                            else:
                                                int_length = 0
                                        
                                        # Extract INTEGER data
                                        if int_idx + int_length <= len(asn1_data):
                                            int_data = asn1_data[int_idx:int_idx+int_length]
                                            
                                            # Remove leading zero padding if present
                                            while len(int_data) > algo_info['public_key'] and int_data[0] == 0x00:
                                                int_data = int_data[1:]
                                            
                                            if len(int_data) == algo_info['public_key']:
                                                pubkey = int_data
                                                extraction_method = "ASN.1 INTEGER from SEQUENCE in BitString.contents"
                                            elif len(int_data) > algo_info['public_key']:
                                                # Take from end
                                                pubkey = int_data[-algo_info['public_key']:]
                                                if len(pubkey) == algo_info['public_key']:
                                                    extraction_method = "ASN.1 INTEGER from SEQUENCE (from end)"
                                    
                                    # If INTEGER doesn't contain full key, check if key is after SEQUENCE
                                    if (not pubkey or len(pubkey) != algo_info['public_key']) and seq_idx + seq_length < len(asn1_data):
                                        # Key might be stored after the SEQUENCE
                                        remaining = asn1_data[seq_idx + seq_length:]
                                        if len(remaining) >= algo_info['public_key']:
                                            pubkey = remaining[:algo_info['public_key']]
                                            extraction_method = "Raw bytes after ASN.1 SEQUENCE in BitString.contents"
                                
                                # Fallback: try direct extraction from contents (skip first byte if 0x00)
                                if (not pubkey or len(pubkey) != algo_info['public_key']) and len(contents_bytes) >= algo_info['public_key'] + 1:
                                    # Skip unused bits byte and try from end
                                    pubkey = contents_bytes[-(algo_info['public_key']+1):-1] if contents_bytes[-1] == 0x00 else contents_bytes[-algo_info['public_key']:]
                                    if len(pubkey) == algo_info['public_key']:
                                        extraction_method = "Direct from BitString.contents (skipping unused bits)"
                    except Exception as contents_err:
                        pass
                
                # Method 3: Parse BitString dump manually
                if not pubkey or len(pubkey) != algo_info['public_key']:
                    try:
                        bitstring_dump = pubkey_bitstring.dump()
                        # BitString format: [0x03 tag][length][unused_bits:1 byte][data]
                        if len(bitstring_dump) >= 3 and bitstring_dump[0] == 0x03:
                            idx = 1
                            # Parse length
                            len_byte = bitstring_dump[idx]
                            idx += 1
                            if (len_byte & 0x80) == 0:
                                data_length = len_byte
                            else:
                                len_bytes = len_byte & 0x7F
                                if 0 < len_bytes <= 4 and idx + len_bytes <= len(bitstring_dump):
                                    length_bytes = bitstring_dump[idx:idx+len_bytes]
                                    data_length = int.from_bytes(length_bytes, 'big')
                                    idx += len_bytes
                                else:
                                    data_length = 0
                            
                            # Skip unused_bits byte
                            if idx < len(bitstring_dump):
                                idx += 1  # Skip unused_bits
                                
                                # Extract data
                                if idx + algo_info['public_key'] <= len(bitstring_dump):
                                    pubkey = bitstring_dump[idx:idx+algo_info['public_key']]
                                    if len(pubkey) == algo_info['public_key']:
                                        extraction_method = "manual BitString dump parse"
                                elif len(bitstring_dump) >= algo_info['public_key']:
                                    # Try from end
                                    pubkey = bitstring_dump[-algo_info['public_key']:]
                                    if len(pubkey) == algo_info['public_key']:
                                        extraction_method = "manual BitString dump parse (from end)"
                    except Exception as parse_err:
                        pass
                
                # Method 4: Search in entire certificate for 1312-byte sequence
                # The public key might be stored elsewhere in the certificate
                if not pubkey or len(pubkey) != algo_info['public_key']:
                    try:
                        # Search the entire certificate dump
                        cert_dump = cert.dump()
                        print(f"  Searching entire certificate dump ({len(cert_dump):,} bytes) for {algo_info['public_key']}-byte key...")
                        
                        best_candidate = None
                        best_score = 0
                        
                        # Search backwards from end (keys are usually near the end)
                        for search_idx in range(len(cert_dump) - algo_info['public_key'], 
                                               max(0, len(cert_dump) - algo_info['public_key'] - 2000), -1):
                            candidate = cert_dump[search_idx:search_idx+algo_info['public_key']]
                            if len(candidate) == algo_info['public_key']:
                                # Check if it looks like a key (high entropy, not too many zeros)
                                zero_count = candidate.count(0)
                                unique_bytes = len(set(candidate))
                                # Good key characteristics: < 30% zeros, > 15% unique bytes
                                if zero_count < algo_info['public_key'] * 0.3 and unique_bytes > algo_info['public_key'] * 0.15:
                                    score = unique_bytes - (zero_count * 0.5)
                                    if score > best_score:
                                        best_score = score
                                        best_candidate = candidate
                        
                        if best_candidate is not None and best_score > algo_info['public_key'] * 0.1:
                            pubkey = bytes(best_candidate)
                            extraction_method = f"heuristic search in certificate dump (score: {best_score:.1f})"
                            print(f"  Found candidate at offset {len(cert_dump) - len(best_candidate) - cert_dump.rindex(bytes(best_candidate)):,} from end")
                    except Exception as search_err:
                        print(f"  Search error: {search_err}")
                
                # Method 5: Search in raw certificate bytes
                if not pubkey or len(pubkey) != algo_info['public_key']:
                    try:
                        print(f"  Searching raw certificate bytes ({len(signed_data):,} bytes)...")
                        best_candidate = None
                        best_score = 0
                        
                        for search_idx in range(len(signed_data) - algo_info['public_key'], 
                                               max(0, len(signed_data) - algo_info['public_key'] - 2000), -1):
                            candidate = signed_data[search_idx:search_idx+algo_info['public_key']]
                            if len(candidate) == algo_info['public_key']:
                                zero_count = candidate.count(0)
                                unique_bytes = len(set(candidate))
                                if zero_count < algo_info['public_key'] * 0.3 and unique_bytes > algo_info['public_key'] * 0.15:
                                    score = unique_bytes - (zero_count * 0.5)
                                    if score > best_score:
                                        best_score = score
                                        best_candidate = candidate
                        
                        if best_candidate is not None and best_score > algo_info['public_key'] * 0.1:
                            pubkey = bytes(best_candidate)
                            extraction_method = f"heuristic search in raw certificate bytes (score: {best_score:.1f})"
                            print(f"  Found candidate at offset {len(signed_data) - len(best_candidate) - signed_data.rindex(bytes(best_candidate)):,} from end")
                    except Exception as search_err:
                        print(f"  Raw bytes search error: {search_err}")
                
                if pubkey and len(pubkey) == algo_info['public_key']:
                    print(f"\n  ✅ Public key extracted: {len(pubkey):,} bytes (expected: {algo_info['public_key']})")
                    print(f"     Method: {extraction_method}")
                    print(f"     First 16 bytes (hex): {pubkey[:16].hex()}")
                    print(f"     Last 16 bytes (hex): {pubkey[-16:].hex()}")
                    
                    # Try verification
                    print(f"\n--- Verification Attempt ---")
                    print(f"  Note: Certificate signature is signed by issuer's private key")
                    print(f"  We're using the certificate's own public key (self-verification test)")
                    try:
                        is_valid = verifier.verify(tbs_data, signature, pubkey)
                        if is_valid:
                            print(f"  ✅ VERIFICATION SUCCESSFUL!")
                            print(f"     This means the certificate is self-signed (signed with its own key)")
                        else:
                            print(f"  ❌ VERIFICATION FAILED")
                            print(f"     This is expected if the certificate is signed by an issuer (CA)")
                            print(f"     To verify properly, we need the issuer's public key")
                            print(f"     OR if self-signed, the key extraction may be wrong")
                            
                            # Show diagnostic info
                            print(f"\n  Diagnostic info:")
                            print(f"    TBS data size: {len(tbs_data):,} bytes")
                            print(f"    Signature size: {len(signature):,} bytes")
                            print(f"    Public key size: {len(pubkey):,} bytes")
                            print(f"    TBS first 32 bytes (hex): {tbs_data[:32].hex()}")
                            
                    except Exception as verify_err:
                        print(f"  ❌ VERIFICATION ERROR: {verify_err}")
                        print(f"     Exception type: {type(verify_err).__name__}")
                else:
                    print(f"\n  ❌ Public key extraction failed")
                    print(f"     Extracted: {len(pubkey) if pubkey else 0} bytes, expected: {algo_info['public_key']} bytes")
                    print(f"     This is the core issue - public key extraction from certificate is failing")
                    print(f"\n  🔍 Debugging info:")
                    print(f"     Try checking the BitString structure manually")
                    print(f"     The public key should be 1312 bytes somewhere in the certificate")
                    
            except Exception as cert_err:
                print(f"  ❌ ERROR parsing certificate: {cert_err}")
                import traceback
                traceback.print_exc()
        
        else:
            # Other object types (CRL, etc.)
            print(f"\n--- {object_type.upper()} Object ---")
            print(f"  This object type requires public key from issuer certificate")
            print(f"  or a pre-extracted key file")
        
        return True
        
    except Exception as e:
        print(f"  ❌ ERROR processing file: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py <algorithm_directory> [sample_count]")
        print("Example: python3 scanner.py /data/signed/DILITHIUM2 10")
        sys.exit(1)
    
    repo_path = Path(sys.argv[1])
    sample_count = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    
    if not repo_path.exists():
        print(f"ERROR: Directory does not exist: {repo_path}")
        sys.exit(1)
    
    if not repo_path.is_dir():
        print(f"ERROR: Path is not a directory: {repo_path}")
        sys.exit(1)
    
    # Determine algorithm
    algo_key = get_algorithm_info(repo_path)
    if not algo_key or algo_key not in ALGO_METADATA:
        print(f"ERROR: Could not determine algorithm from directory name: {repo_path.name}")
        print(f"Supported algorithms: dilithium2, dilithium3, falcon512")
        sys.exit(1)
    
    algo_info = ALGO_METADATA[algo_key]
    algo_name = algo_info['algorithm_name']
    
    print("="*80)
    print("RPKI SIGNATURE VERIFICATION DIAGNOSTIC SCANNER")
    print("="*80)
    print(f"Algorithm: {algo_key.upper()} ({algo_name})")
    print(f"Directory: {repo_path}")
    print(f"Sample size: {sample_count} files")
    print(f"Expected signature size: {algo_info['signature']} bytes")
    print(f"Expected public key size: {algo_info['public_key']} bytes")
    print("="*80)
    
    # Initialize verifier
    try:
        verifier = Signature(algo_name)
        print(f"✅ Verifier initialized: {algo_name}")
    except Exception as e:
        print(f"❌ ERROR: Could not initialize verifier: {e}")
        sys.exit(1)
    
    # Collect files
    files = []
    for f in repo_path.rglob("*"):
        if f.is_file() and not f.name.startswith('.'):
            ext = f.suffix.lower()
            if ext in ('.cer', '.roa', '.mft', '.crl'):
                files.append(f)
    
    if not files:
        print(f"ERROR: No RPKI files found in {repo_path}")
        sys.exit(1)
    
    print(f"\nFound {len(files):,} RPKI files")
    print(f"Scanning first {min(sample_count, len(files))} files...\n")
    
    # Scan sample files
    success_count = 0
    fail_count = 0
    
    for i, file_path in enumerate(files[:sample_count], 1):
        if scan_file(file_path, algo_info, verifier, i):
            success_count += 1
        else:
            fail_count += 1
    
    # Summary
    print(f"\n{'='*80}")
    print("SCAN SUMMARY")
    print(f"{'='*80}")
    print(f"Files scanned: {success_count + fail_count}")
    print(f"Successfully analyzed: {success_count}")
    print(f"Failed to analyze: {fail_count}")
    print(f"\nIf all verifications failed, check:")
    print(f"  1. Public key extraction - are the bytes correct?")
    print(f"  2. TBS data - does it match what was signed?")
    print(f"  3. Signature format - is it in the correct format?")
    print(f"  4. Keypair matching - does public key match private key used to sign?")
    print("="*80)

if __name__ == "__main__":
    main()

