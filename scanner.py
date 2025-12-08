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
                
                # DIAGNOSTIC: Show what we're working with
                print(f"  SubjectPublicKeyInfo structure found")
                try:
                    pubkey_info_dump = pubkey_info.dump()
                    print(f"  SubjectPublicKeyInfo dump size: {len(pubkey_info_dump):,} bytes")
                    print(f"  BitString type: {type(pubkey_bitstring).__name__}")
                    
                    # Try to get BitString dump
                    try:
                        bitstring_dump = pubkey_bitstring.dump()
                        print(f"  BitString dump size: {len(bitstring_dump):,} bytes")
                        print(f"  BitString first 32 bytes (hex): {bitstring_dump[:32].hex()}")
                        if len(bitstring_dump) > 32:
                            print(f"  BitString last 32 bytes (hex): {bitstring_dump[-32:].hex()}")
                    except Exception as dump_err:
                        print(f"  Could not dump BitString: {dump_err}")
                    
                    # Try .contents property
                    if hasattr(pubkey_bitstring, 'contents'):
                        contents = pubkey_bitstring.contents
                        print(f"  BitString.contents type: {type(contents).__name__}")
                        if isinstance(contents, (bytes, bytearray)):
                            print(f"  BitString.contents size: {len(contents):,} bytes")
                            print(f"  BitString.contents first 32 bytes (hex): {contents[:32].hex() if len(contents) >= 32 else contents.hex()}")
                except Exception as diag_err:
                    print(f"  Diagnostic error: {diag_err}")
                
                # Extract public key using multiple methods
                pubkey = None
                extraction_method = None
                
                # Method 1: Use extraction function
                pubkey = extract_bytes_from_bitstring(pubkey_bitstring, algo_info['public_key'])
                if pubkey and len(pubkey) == algo_info['public_key']:
                    extraction_method = "extract_bytes_from_bitstring"
                
                # Method 2: Try .contents directly
                if not pubkey or len(pubkey) != algo_info['public_key']:
                    try:
                        if hasattr(pubkey_bitstring, 'contents'):
                            contents = pubkey_bitstring.contents
                            if isinstance(contents, (bytes, bytearray)):
                                contents_bytes = bytes(contents)
                                if len(contents_bytes) >= algo_info['public_key']:
                                    # Try from end (most likely)
                                    pubkey = contents_bytes[-algo_info['public_key']:]
                                    if len(pubkey) == algo_info['public_key']:
                                        extraction_method = "BitString.contents (from end)"
                                    # Try from start
                                    elif len(contents_bytes) == algo_info['public_key']:
                                        pubkey = contents_bytes
                                        extraction_method = "BitString.contents (exact)"
                    except:
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
                
                # Method 4: Search in pubkey_info_dump
                if not pubkey or len(pubkey) != algo_info['public_key']:
                    try:
                        pubkey_info_dump = pubkey_info.dump()
                        if len(pubkey_info_dump) >= algo_info['public_key']:
                            # Search for the key (should be near the end)
                            for search_idx in range(len(pubkey_info_dump) - algo_info['public_key'], 
                                                   max(0, len(pubkey_info_dump) - algo_info['public_key'] - 100), -1):
                                candidate = pubkey_info_dump[search_idx:search_idx+algo_info['public_key']]
                                if len(candidate) == algo_info['public_key']:
                                    # Check if it looks like a key (high entropy)
                                    zero_count = candidate.count(0)
                                    unique_bytes = len(set(candidate))
                                    if zero_count < algo_info['public_key'] * 0.3 and unique_bytes > algo_info['public_key'] * 0.15:
                                        pubkey = bytes(candidate)
                                        extraction_method = "heuristic search in SubjectPublicKeyInfo dump"
                                        break
                    except:
                        pass
                
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

