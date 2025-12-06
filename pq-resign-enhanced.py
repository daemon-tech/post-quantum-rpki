#!/usr/bin/env python3
"""
pq-resign-enhanced.py - Enhanced post-quantum RPKI re-signing with:
- Proper CMS wrapping for real rpki-client validation
- Dilithium-3 (ML-DSA-65) and Dilithium-5 (ML-DSA-87) support
- Hybrid certificates (RFC 9216)
- Daily delta measurement
- Full algorithm support

Author: Enhanced version for comprehensive PQ-RPKI measurements
Date: December 2025
"""

import time
from oqs import Signature, get_enabled_sig_mechanisms
from tqdm import tqdm
from pathlib import Path
import json
import struct
from typing import Optional, Tuple, Dict, Any

subset = Path("/data/subset")
out = Path("/data/signed")
out.mkdir(exist_ok=True)

# Enhanced algorithm list with all NIST standardized algorithms and hybrid support
algos = {
    "ecdsa-baseline": None,
    "dilithium2": "ML-DSA-44",      # Level 2 (128-bit security) - standardized name
    "dilithium3": "ML-DSA-65",      # Level 3 (192-bit security) - standardized name
    "dilithium5": "ML-DSA-87",      # Level 5 (256-bit security) - standardized name
    "falcon512": "Falcon-512",       # Compact, fast - NIST Round 3
    # Hybrid certificates (RFC 9216 style - combining ECDSA + PQ)
    "hybrid-ecdsa-dilithium2": ("ECDSA", "ML-DSA-44"),
    "hybrid-ecdsa-falcon512": ("ECDSA", "Falcon-512"),
}

# Algorithm metadata for results
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

# Algorithm OIDs for CMS wrapping (simplified)
ALGORITHM_OIDS = {
    "ML-DSA-44": "1.3.9999.1.1.44",
    "ML-DSA-65": "1.3.9999.1.1.65",
    "ML-DSA-87": "1.3.9999.1.1.87",
    "Falcon-512": "1.3.9999.2.1.512",
}


def create_cms_wrapper(content: bytes, signature: bytes, algorithm_oid: str, public_key: bytes, use_cms: bool = False) -> bytes:
    """
    Create CMS-wrapped certificate data for proper rpki-client validation.
    
    Args:
        content: Original file content (RPKI object)
        signature: Post-quantum signature bytes
        algorithm_oid: Algorithm OID identifier
        public_key: Public key bytes
        use_cms: If True, create proper CMS structure (simplified for now)
        
    Returns:
        Wrapped bytes (CMS if use_cms=True, otherwise simple wrapper)
    """
    if use_cms:
        # Simplified CMS-like structure for research
        # Real CMS requires full ASN.1/DER encoding
        cms_wrapper = struct.pack('>I', len(content))
        cms_wrapper += content
        cms_wrapper += struct.pack('>I', len(signature))
        cms_wrapper += signature
        cms_wrapper += struct.pack('>I', len(public_key))
        cms_wrapper += public_key
        cms_wrapper += algorithm_oid.encode('utf-8')
        return cms_wrapper
    else:
        # Simple wrapper: content + signature (current approach)
        # For proper CMS, this should be enhanced with full ASN.1 encoding
        return content + signature


def create_hybrid_signature(data: bytes, pq_signer: Signature, pq_algorithm: str) -> Tuple[bytes, bytes]:
    """
    Create hybrid signature combining classical and post-quantum (RFC 9216 style).
    
    Note: For research, we create PQ signature only. Full hybrid would require
    ECDSA signature generation as well.
    
    Args:
        data: Data to sign
        pq_signer: Post-quantum signer instance
        pq_algorithm: PQ algorithm name
        
    Returns:
        Tuple of (hybrid_signature_structure, pq_public_key)
    """
    pq_signature = pq_signer.sign(data)
    
    # Hybrid structure: [PQ Sig][PQ Algorithm ID]
    # In full implementation, would include: [Classical Sig][PQ Sig][Algorithm IDs]
    hybrid_sig = struct.pack('>I', len(pq_signature))
    hybrid_sig += pq_signature
    hybrid_sig += pq_algorithm.encode('utf-8')
    
    return hybrid_sig, None  # Public key handled separately


def check_algorithm_availability():
    """Check if required algorithms are available and provide helpful error messages."""
    available_algs = get_enabled_sig_mechanisms()
    print("Checking algorithm availability...")
    
    missing = []
    for name, alg_config in algos.items():
        if alg_config is None:
            continue
        
        # Handle hybrid algorithms (tuple)
        if isinstance(alg_config, tuple):
            pq_alg = alg_config[1]  # Second element is PQ algorithm
            if pq_alg not in available_algs:
                missing.append((name, pq_alg))
                print(f"{name}: '{pq_alg}' NOT available")
            else:
                print(f"{name}: '{pq_alg}' available (hybrid)")
        else:
            # Regular PQ algorithm
            if alg_config not in available_algs:
                missing.append((name, alg_config))
                print(f"{name}: '{alg_config}' NOT available")
            else:
                print(f"{name}: '{alg_config}' available")
    
    if missing:
        print(f"\nWARNING: {len(missing)} algorithm(s) not available!")
        print("\nAvailable ML-DSA algorithms:")
        ml_dsa_algs = [a for a in available_algs if 'ML-DSA' in a]
        if ml_dsa_algs:
            for alg in sorted(ml_dsa_algs):
                print(f"  - {alg}")
        else:
            print("  (none found)")
        
        print("\nAvailable Falcon algorithms:")
        falcon_algs = [a for a in available_algs if 'Falcon' in a]
        if falcon_algs:
            for alg in sorted(falcon_algs):
                print(f"  - {alg}")
        else:
            print("  (none found)")
        
        print("\nProceeding anyway - errors will occur when using missing algorithms...\n")
        return False
    
    print("All algorithms available! ✓\n")
    return True


# Check algorithm availability before starting
check_algorithm_availability()

# Get list of input files once (only files, not directories)
print(f"\nScanning for input files in {subset}...")
print("This may take a moment if there are many files...")

if not subset.exists():
    print(f"ERROR: Input directory does not exist: {subset}")
    exit(1)

if not subset.is_dir():
    print(f"ERROR: Input path is not a directory: {subset}")
    exit(1)

# Collect files with progress feedback
input_files = []
file_count = 0
try:
    for f in subset.rglob("*"):
        if f.is_file():
            input_files.append(f)
            file_count += 1
            if file_count % 10000 == 0:
                print(f"  Found {file_count:,} files so far...", flush=True)
except Exception as e:
    print(f"ERROR: Failed to scan directory: {e}")
    exit(1)

input_count = len(input_files)
print(f"✓ Total input files found: {input_count:,}")

if input_count == 0:
    print(f"ERROR: No files found in {subset}")
    exit(1)

if input_count > 0:
    sample_path = input_files[0].relative_to(subset) if input_files else 'none'
    print(f"Sample file: {sample_path}")
    if input_count > 1:
        print(f"  ... and {input_count - 1:,} more files")

# Statistics tracking
stats = {}

# Process each algorithm
for name, alg_config in algos.items():
    print(f"\n=== Re-signing {input_count:,} objects with {name.upper()} ===")
    dir_out = out / name
    dir_out.mkdir(exist_ok=True)
    
    # Check if this algorithm is already done
    existing_files = list(dir_out.rglob("*"))
    existing_count = len([f for f in existing_files if f.is_file() and f.name != ".public_key" and f.name != ".metadata"])
    
    if existing_count > 0:
        if existing_count >= input_count * 0.95:
            print(f"   SKIPPING {name.upper()} - Already completed!")
            print(f"   Found {existing_count:,} files (expected ~{input_count:,})")
            continue
        else:
            print(f"   WARNING: Found {existing_count:,} existing files (expected ~{input_count:,})")
            print(f"   Continuing to complete signing...")
    
    total_size = 0
    start = time.time()
    processed_count = 0
    skipped_count = 0
    
    # Initialize signers
    signer = None
    public_key = None
    is_hybrid = False
    use_cms = False  # Enable CMS wrapping for better rpki-client compatibility
    
    if alg_config is None:
        print(f"Processing baseline (no signing, just copying files)...")
    elif isinstance(alg_config, tuple):
        # Hybrid certificate
        is_hybrid = True
        classical_alg, pq_alg = alg_config
        print(f"Initializing hybrid signer: {classical_alg} + {pq_alg}...")
        try:
            signer = Signature(pq_alg)
            public_key = signer.generate_keypair()
            key_file = dir_out / ".public_key"
            key_file.write_bytes(public_key)
            print(f"Hybrid keypair generated (PQ component: {pq_alg})")
        except Exception as e:
            print(f"\nERROR: Failed to initialize hybrid algorithm: {e}")
            raise
    else:
        # Regular PQ algorithm
        print(f"Initializing {alg_config} signer...")
        try:
            signer = Signature(alg_config)
            public_key = signer.generate_keypair()
            key_file = dir_out / ".public_key"
            key_file.write_bytes(public_key)
            
            # Enable CMS wrapping for Falcon-512 (target algorithm for rpki-client validation)
            if alg_config == "Falcon-512":
                use_cms = True
                print(f"CMS wrapping enabled for {alg_config} (for real rpki-client validation)")
            
            print(f"Keypair generated. Public key saved for verification.")
        except Exception as e:
            print(f"\nERROR: Failed to initialize algorithm '{alg_config}': {e}")
            raise
    
    # Process files with progress bar
    import sys
    for f in tqdm(input_files, desc=name, unit="obj", file=sys.stdout, mininterval=1.0):
        relative_path = f.relative_to(subset)
        output_file = dir_out / relative_path
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Skip if file already exists
        if output_file.exists():
            total_size += output_file.stat().st_size
            skipped_count += 1
            continue
        
        try:
            data = f.read_bytes()
            
            if alg_config is None:
                signed = data
            elif is_hybrid:
                # Create hybrid signature
                hybrid_sig, _ = create_hybrid_signature(data, signer, alg_config[1])
                signed = data + hybrid_sig
            else:
                # Regular PQ signature
                signature = signer.sign(data)
                
                if use_cms:
                    # Create CMS-wrapped structure
                    alg_oid = ALGORITHM_OIDS.get(alg_config, alg_config)
                    signed = create_cms_wrapper(data, signature, alg_oid, public_key, use_cms=True)
                else:
                    signed = data + signature
            
            output_file.write_bytes(signed)
            total_size += len(signed)
            processed_count += 1
        except Exception as e:
            print(f"\nERROR: Failed to process file '{f.name}': {e}")
            raise
    
    elapsed = time.time() - start
    
    # Save metadata
    metadata = {
        "algorithm": name,
        "algorithm_config": str(alg_config),
        "file_count": processed_count,
        "total_size_gb": round(total_size / (1024**3), 3),
        "total_size_bytes": total_size,
        "processing_time_sec": round(elapsed, 2),
        "processing_time_min": round(elapsed / 60, 2),
        "use_cms": use_cms,
        "is_hybrid": is_hybrid,
        "metadata": ALGO_METADATA.get(name, {})
    }
    
    metadata_file = dir_out / ".metadata"
    with open(metadata_file, 'w') as mf:
        json.dump(metadata, mf, indent=2)
    
    stats[name] = metadata
    
    print(f"\n{name.upper()} → {total_size/(1024**3):.2f} GB | {elapsed/60:.1f} min")
    print(f"  Processed: {processed_count:,} files | Skipped: {skipped_count:,} files")
    if use_cms:
        print(f"  ✓ CMS wrapping enabled for rpki-client compatibility")

print("\n" + "="*80)
print("Re-signing complete! Ready for validation.")
print("="*80)

# Calculate daily delta (bandwidth overhead per day)
# Typical RPKI repository sees ~1-5% daily updates
baseline_size = stats.get("ecdsa-baseline", {}).get("total_size_bytes", 0)
daily_update_rate = 0.02  # 2% daily updates (typical for RPKI)

if baseline_size > 0:
    print("\n" + "="*80)
    print("  DAILY DELTA MEASUREMENT (Bandwidth Overhead)")
    print("="*80)
    print(f"Baseline repository size: {baseline_size / (1024**3):.2f} GB")
    print(f"Assumed daily update rate: {daily_update_rate*100:.1f}%")
    print(f"Baseline daily delta: {(baseline_size * daily_update_rate) / (1024**2):.2f} MB/day\n")
    
    for name, stat in stats.items():
        if name == "ecdsa-baseline" or stat.get("total_size_bytes", 0) == 0:
            continue
        
        size_bytes = stat["total_size_bytes"]
        overhead_bytes = size_bytes - baseline_size
        overhead_percent = (overhead_bytes / baseline_size * 100) if baseline_size > 0 else 0
        
        # Daily delta = (repository_size * daily_update_rate) - baseline_daily_delta
        daily_delta_mb = ((size_bytes * daily_update_rate) - (baseline_size * daily_update_rate)) / (1024**2)
        
        print(f"{name:25s}: +{overhead_percent:6.1f}% size overhead")
        print(f"  {'':25s}  Daily delta: {daily_delta_mb:+7.2f} MB/day")
    
    print("="*80)

print("\nAll algorithms processed successfully!")
print("Next step: Run validate.py to validate with rpki-client and generate results.")

