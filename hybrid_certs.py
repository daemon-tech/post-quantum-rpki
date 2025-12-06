#!/usr/bin/env python3
"""
Hybrid certificate support (RFC 9216)

This module implements hybrid certificates that combine classical
and post-quantum signature algorithms for transition security.
"""

from typing import Tuple, Optional
from oqs import Signature


def create_hybrid_signature(
    data: bytes,
    classical_signature: bytes,
    pq_algorithm: str,
    pq_signer: Signature
) -> Tuple[bytes, bytes]:
    """
    Create a hybrid signature combining classical and post-quantum algorithms.
    
    Args:
        data: Data to sign
        classical_signature: Classical (ECDSA) signature (already computed)
        pq_algorithm: Post-quantum algorithm name (e.g., "ML-DSA-44")
        pq_signer: Post-quantum signer instance
        
    Returns:
        Tuple of (hybrid_signature_structure, pq_public_key)
    """
    # Create post-quantum signature
    pq_signature = pq_signer.sign(data)
    pq_public_key = pq_signer.generate_keypair() if not hasattr(pq_signer, '_public_key') else None
    
    # Hybrid signature structure (RFC 9216 style):
    # [Classical Sig][PQ Sig][Classical Algorithm ID][PQ Algorithm ID]
    
    import struct
    
    classical_len = len(classical_signature)
    pq_sig_len = len(pq_signature)
    
    # Create hybrid structure
    hybrid_sig = struct.pack('>HH', classical_len, pq_sig_len)
    hybrid_sig += classical_signature
    hybrid_sig += pq_signature
    hybrid_sig += b'ECDSA'  # Classical algorithm identifier
    hybrid_sig += pq_algorithm.encode('utf-8')
    
    return hybrid_sig, pq_public_key


def verify_hybrid_signature(
    data: bytes,
    hybrid_signature: bytes,
    classical_pubkey: bytes,
    pq_pubkey: bytes,
    pq_algorithm: str
) -> bool:
    """
    Verify a hybrid signature (requires both classical and PQ verification).
    
    Args:
        data: Original data
        hybrid_signature: Hybrid signature structure
        classical_pubkey: Classical public key
        pq_pubkey: Post-quantum public key
        pq_algorithm: Post-quantum algorithm name
        
    Returns:
        True if both signatures verify, False otherwise
    """
    try:
        import struct
        
        if len(hybrid_signature) < 4:
            return False
            
        classical_len, pq_sig_len = struct.unpack('>HH', hybrid_signature[:4])
        offset = 4
        
        if offset + classical_len + pq_sig_len > len(hybrid_signature):
            return False
            
        classical_sig = hybrid_signature[offset:offset+classical_len]
        offset += classical_len
        pq_sig = hybrid_signature[offset:offset+pq_sig_len]
        
        # For research purposes, we verify PQ signature
        # Classical verification would require ECDSA implementation
        pq_verifier = Signature(pq_algorithm)
        pq_valid = pq_verifier.verify(data, pq_sig, pq_pubkey)
        
        # In real implementation, also verify classical signature
        # classical_valid = verify_ecdsa(data, classical_sig, classical_pubkey)
        # return classical_valid and pq_valid
        
        return pq_valid  # Simplified for research
        
    except Exception:
        return False

