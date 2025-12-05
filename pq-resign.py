# pq-resign.py FIXED for liboqs 0.15.0 (standard names)
import time
from oqs import Signature, get_enabled_sig_mechanisms
from tqdm import tqdm
from pathlib import Path

subset = Path("/data/subset")
out = Path("/data/signed")
out.mkdir(exist_ok=True)

# Standard names from liboqs (per docs ML-DSA-44 for Level 2, Falcon-512)
algos = {
    "ecdsa-baseline": None,
    "dilithium2": "ML-DSA-44",      # Level 2 (128-bit security) - standardized name
    "falcon512": "Falcon-512"        # Compact, fast
}

def check_algorithm_availability():
    """Check if required algorithms are available and provide helpful error messages."""
    available_algs = get_enabled_sig_mechanisms()
    print("Checking algorithm availability...")
    
    missing = []
    for name, alg in algos.items():
        if alg is None:
            continue
        if alg not in available_algs:
            missing.append((name, alg))
            print(f"{name}: '{alg}' NOT available")
        else:
            print(f"{name}: '{alg}' available")
    
    if missing:
        print(f"\nWARNING: {len(missing)} algorithm(s) not available!")
        print("\nAvailable ML-DSA algorithms:")
        ml_dsa_algs = [a for a in available_algs if 'ML-DSA' in a]
        if ml_dsa_algs:
            for alg in sorted(ml_dsa_algs):
                print(f"  - {alg}")
        else:
            print("  (none found)")
        
        print("\nTo fix this, you may need to:")
        print("  1. Rebuild liboqs with ML-DSA support enabled")
        print("  2. Reinstall the Python 'oqs' package after rebuilding liboqs")
        print("  3. Check your Docker container's liboqs installation")
        print("\nProceeding anyway - errors will occur when using missing algorithms...\n")
        return False
    
    print("All algorithms available! ✓\n")
    return True

# Check algorithm availability before starting
check_algorithm_availability()

# Get list of input files once (only files, not directories)
# Handle both flat and nested directory structures
print(f"\nScanning for input files in {subset}...")
print("This may take a moment if there are many files...")

# Use a more efficient approach - check if directory exists first
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
            # Show progress every 10000 files
            if file_count % 10000 == 0:
                print(f"  Found {file_count:,} files so far...", flush=True)
except Exception as e:
    print(f"ERROR: Failed to scan directory: {e}")
    exit(1)

input_count = len(input_files)
print(f"✓ Total input files found: {input_count:,}")

if input_count == 0:
    print(f"ERROR: No files found in {subset}")
    print(f"Please check that the subset directory contains files.")
    exit(1)
    
# Show sample of file paths for debugging
if input_count > 0:
    sample_path = input_files[0].relative_to(subset) if input_files else 'none'
    print(f"Sample file: {sample_path}")
    if input_count > 1:
        print(f"  ... and {input_count - 1:,} more files")

for name, alg in algos.items():
    print(f"\n=== Re-signing {input_count:,} objects with {name.upper()} ===")
    dir_out = out / name
    dir_out.mkdir(exist_ok=True)
    
    # Check if this algorithm is already done
    existing_files = list(dir_out.rglob("*"))
    existing_count = len([f for f in existing_files if f.is_file()])
    
    if existing_count > 0:
        if existing_count >= input_count * 0.95:  # Allow 5% tolerance
            print(f"   SKIPPING {name.upper()} - Already completed!")
            print(f"   Found {existing_count:,} files (expected ~{input_count:,})")
            print(f"   Output directory: {dir_out}")
            continue
        else:
            print(f"   WARNING: Found {existing_count:,} existing files (expected ~{input_count:,})")
            print(f"   Continuing to complete signing...")
    
    total_size = 0
    start = time.time()
    processed_count = 0
    skipped_count = 0
    
    # Create signer once per algorithm (reuse for all files for efficiency)
    signer = None
    public_key = None
    if alg is not None:
        print(f"Initializing {alg} signer...")
        try:
            signer = Signature(alg)
            # Generate keypair - this sets the secret_key internally
            # For research purposes, we use the same keypair for all files
            public_key = signer.generate_keypair()
            # Save public key to file for later verification
            key_file = dir_out / ".public_key"
            key_file.write_bytes(public_key)
            print(f"Keypair generated. Public key saved for verification.")
            print(f"Starting to process files...")
        except Exception as e:
            print(f"\nERROR: Failed to initialize algorithm '{alg}': {e}")
            print(f"Available signature algorithms may not include '{alg}'.")
            print("Please check that liboqs was compiled with support for this algorithm.")
            raise
    else:
        print(f"Processing baseline (no signing, just copying files)...")
    
    # Process files with progress bar
    import sys
    for f in tqdm(input_files, desc=name, unit="obj", file=sys.stdout, mininterval=1.0):
        # Preserve directory structure if files are nested
        relative_path = f.relative_to(subset)
        output_file = dir_out / relative_path
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Skip if file already exists (resume capability)
        if output_file.exists():
            total_size += output_file.stat().st_size
            skipped_count += 1
            continue
        
        try:
            data = f.read_bytes()
            if alg is None:
                signed = data
            else:
                # Sign the data - secret_key is used internally after generate_keypair()
                signature = signer.sign(data)
                signed = data + signature  # real full-file signature
            
            output_file.write_bytes(signed)
            total_size += len(signed)
            processed_count += 1
        except Exception as e:
            print(f"\nERROR: Failed to process file '{f.name}': {e}")
            raise
    
    elapsed = time.time() - start
    print(f"\n{name.upper()} → {total_size/(1024**3):.2f} GB | {elapsed/60:.1f} min")
    print(f"  Processed: {processed_count:,} files | Skipped: {skipped_count:,} files")

print("\nRe-signing complete! Ready for validation.")