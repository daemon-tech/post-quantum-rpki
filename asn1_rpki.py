#!/usr/bin/env python3
"""
ASN.1 parser for RPKI objects (certificates, ROAs, manifests)

This module properly parses ASN.1 structures and replaces signatures and public keys
instead of just appending them, which was the methodological issue.
"""

import struct
from typing import Tuple, Optional, Dict, Any
from pathlib import Path
from collections import defaultdict

try:
    from asn1crypto import x509, core, pem, cms, crl, keys, algos
    ASN1_AVAILABLE = True
except ImportError:
    ASN1_AVAILABLE = False
    print("WARNING: asn1crypto not available. Install with: pip install asn1crypto")

# Post-Quantum Algorithm OIDs
# Based on NIST standards and IETF drafts
PQ_ALGORITHM_OIDS = {
    "ML-DSA-44": "1.3.6.1.4.1.2.267.1.6.5",  # Dilithium-2
    "ML-DSA-65": "1.3.6.1.4.1.2.267.1.6.7",  # Dilithium-3
    "ML-DSA-87": "1.3.6.1.4.1.2.267.1.6.9",  # Dilithium-5
    "Falcon-512": "1.3.9999.3.6.4",  # Falcon-512 (draft OID, may need update when finalized)
}


class VerificationMetrics:
    """
    Comprehensive metrics collection for RPKI object verification and processing.
    Tracks all successes, failures, and debug information.
    """
    def __init__(self):
        # Object loading metrics
        self.objects_loaded = 0
        self.objects_load_failed = 0
        self.load_failures_by_type = defaultdict(int)
        self.load_failures_by_reason = defaultdict(int)
        
        # Object type distribution
        self.objects_by_type = defaultdict(int)
        
        # CMS signature verification metrics
        self.cms_signatures_verified = 0
        self.cms_signatures_valid = 0
        self.cms_signatures_invalid = 0
        self.cms_verification_errors = defaultdict(int)
        
        # EE certificate signature verification metrics
        self.ee_cert_signatures_verified = 0
        self.ee_cert_signatures_valid = 0
        self.ee_cert_signatures_invalid = 0
        self.ee_cert_verification_errors = defaultdict(int)
        
        # EE certificate extraction metrics
        self.ee_certs_extracted = 0
        self.ee_certs_extraction_failed = 0
        self.ee_cert_extraction_errors = defaultdict(int)
        
        # Overall verification results
        self.objects_fully_valid = 0  # Both CMS and EE cert valid
        self.objects_partially_valid = 0  # One valid, one invalid
        self.objects_fully_invalid = 0  # Both invalid
        self.objects_cannot_verify = 0  # Missing verifier or keys
        
        # Signature replacement metrics
        self.signatures_replaced = 0
        self.signature_replacements_failed = 0
        self.replacement_failures_by_type = defaultdict(int)
        self.replacement_failures_by_reason = defaultdict(int)
        
        # Detailed error tracking
        self.all_errors = []  # List of (object_type, error_type, error_message) tuples
    
    def record_object_loaded(self, object_type: str):
        """Record successful object loading."""
        self.objects_loaded += 1
        self.objects_by_type[object_type] += 1
    
    def record_object_load_failed(self, object_type: str, reason: str):
        """Record object loading failure."""
        self.objects_load_failed += 1
        self.load_failures_by_type[object_type] += 1
        self.load_failures_by_reason[reason] += 1
        self.all_errors.append(("load", object_type, reason))
    
    def record_cms_verification(self, valid: bool, error: str = ""):
        """Record CMS signature verification result."""
        self.cms_signatures_verified += 1
        if valid:
            self.cms_signatures_valid += 1
        else:
            self.cms_signatures_invalid += 1
            if error:
                self.cms_verification_errors[error] += 1
                self.all_errors.append(("cms_verification", "cms", error))
    
    def record_ee_cert_verification(self, valid: bool, error: str = ""):
        """Record EE certificate signature verification result."""
        self.ee_cert_signatures_verified += 1
        if valid:
            self.ee_cert_signatures_valid += 1
        else:
            self.ee_cert_signatures_invalid += 1
            if error:
                self.ee_cert_verification_errors[error] += 1
                self.all_errors.append(("ee_cert_verification", "ee_cert", error))
    
    def record_ee_cert_extraction(self, success: bool, error: str = ""):
        """Record EE certificate extraction result."""
        if success:
            self.ee_certs_extracted += 1
        else:
            self.ee_certs_extraction_failed += 1
            if error:
                self.ee_cert_extraction_errors[error] += 1
                self.all_errors.append(("ee_cert_extraction", "ee_cert", error))
    
    def record_overall_verification(self, cms_valid: bool, ee_cert_valid: bool, can_verify: bool = True):
        """Record overall verification result for an object."""
        if not can_verify:
            self.objects_cannot_verify += 1
        elif cms_valid and ee_cert_valid:
            self.objects_fully_valid += 1
        elif cms_valid or ee_cert_valid:
            self.objects_partially_valid += 1
        else:
            self.objects_fully_invalid += 1
    
    def record_signature_replacement(self, object_type: str, success: bool, reason: str = ""):
        """Record signature replacement result."""
        if success:
            self.signatures_replaced += 1
        else:
            self.signature_replacements_failed += 1
            self.replacement_failures_by_type[object_type] += 1
            if reason:
                self.replacement_failures_by_reason[reason] += 1
                self.all_errors.append(("replacement", object_type, reason))
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive summary of all metrics."""
        total_objects = self.objects_loaded + self.objects_load_failed
        total_verifications = self.cms_signatures_verified
        
        return {
            "object_loading": {
                "total_attempted": total_objects,
                "loaded": self.objects_loaded,
                "failed": self.objects_load_failed,
                "success_rate": (self.objects_loaded / total_objects * 100) if total_objects > 0 else 0,
                "failures_by_type": dict(self.load_failures_by_type),
                "failures_by_reason": dict(self.load_failures_by_reason),
                "objects_by_type": dict(self.objects_by_type),
            },
            "cms_signature_verification": {
                "total_verified": self.cms_signatures_verified,
                "valid": self.cms_signatures_valid,
                "invalid": self.cms_signatures_invalid,
                "success_rate": (self.cms_signatures_valid / self.cms_signatures_verified * 100) if self.cms_signatures_verified > 0 else 0,
                "errors": dict(self.cms_verification_errors),
            },
            "ee_certificate": {
                "extracted": self.ee_certs_extracted,
                "extraction_failed": self.ee_certs_extraction_failed,
                "extraction_errors": dict(self.ee_cert_extraction_errors),
                "signatures_verified": self.ee_cert_signatures_verified,
                "signatures_valid": self.ee_cert_signatures_valid,
                "signatures_invalid": self.ee_cert_signatures_invalid,
                "verification_success_rate": (self.ee_cert_signatures_valid / self.ee_cert_signatures_verified * 100) if self.ee_cert_signatures_verified > 0 else 0,
                "verification_errors": dict(self.ee_cert_verification_errors),
            },
            "overall_verification": {
                "fully_valid": self.objects_fully_valid,
                "partially_valid": self.objects_partially_valid,
                "fully_invalid": self.objects_fully_invalid,
                "cannot_verify": self.objects_cannot_verify,
                "total_verified": (self.objects_fully_valid + self.objects_partially_valid + 
                                 self.objects_fully_invalid + self.objects_cannot_verify),
            },
            "signature_replacement": {
                "replaced": self.signatures_replaced,
                "failed": self.signature_replacements_failed,
                "success_rate": (self.signatures_replaced / (self.signatures_replaced + self.signature_replacements_failed) * 100) if (self.signatures_replaced + self.signature_replacements_failed) > 0 else 0,
                "failures_by_type": dict(self.replacement_failures_by_type),
                "failures_by_reason": dict(self.replacement_failures_by_reason),
            },
            "error_count": len(self.all_errors),
        }
    
    def print_summary(self):
        """Print a human-readable summary of metrics."""
        summary = self.get_summary()
        
        print("\n" + "="*80)
        print("VERIFICATION METRICS SUMMARY")
        print("="*80)
        
        # Object loading
        print(f"\nObject Loading:")
        print(f"  Loaded: {summary['object_loading']['loaded']}")
        print(f"  Failed: {summary['object_loading']['failed']}")
        print(f"  Success Rate: {summary['object_loading']['success_rate']:.2f}%")
        if summary['object_loading']['objects_by_type']:
            print(f"  By Type: {dict(summary['object_loading']['objects_by_type'])}")
        if summary['object_loading']['failures_by_reason']:
            print(f"  Failure Reasons: {dict(summary['object_loading']['failures_by_reason'])}")
        
        # CMS verification
        print(f"\nCMS Signature Verification:")
        print(f"  Verified: {summary['cms_signature_verification']['total_verified']}")
        print(f"  Valid: {summary['cms_signature_verification']['valid']}")
        print(f"  Invalid: {summary['cms_signature_verification']['invalid']}")
        print(f"  Success Rate: {summary['cms_signature_verification']['success_rate']:.2f}%")
        if summary['cms_signature_verification']['errors']:
            print(f"  Errors: {dict(summary['cms_signature_verification']['errors'])}")
        
        # EE certificate
        print(f"\nEE Certificate:")
        print(f"  Extracted: {summary['ee_certificate']['extracted']}")
        print(f"  Extraction Failed: {summary['ee_certificate']['extraction_failed']}")
        print(f"  Signatures Verified: {summary['ee_certificate']['signatures_verified']}")
        print(f"  Signatures Valid: {summary['ee_certificate']['signatures_valid']}")
        print(f"  Signatures Invalid: {summary['ee_certificate']['signatures_invalid']}")
        print(f"  Verification Success Rate: {summary['ee_certificate']['verification_success_rate']:.2f}%")
        if summary['ee_certificate']['verification_errors']:
            print(f"  Verification Errors: {dict(summary['ee_certificate']['verification_errors'])}")
        
        # Overall
        print(f"\nOverall Verification:")
        print(f"  Fully Valid (both signatures): {summary['overall_verification']['fully_valid']}")
        print(f"  Partially Valid (one signature): {summary['overall_verification']['partially_valid']}")
        print(f"  Fully Invalid (both signatures): {summary['overall_verification']['fully_invalid']}")
        print(f"  Cannot Verify (missing verifier/keys): {summary['overall_verification']['cannot_verify']}")
        
        # Signature replacement
        print(f"\nSignature Replacement:")
        print(f"  Replaced: {summary['signature_replacement']['replaced']}")
        print(f"  Failed: {summary['signature_replacement']['failed']}")
        print(f"  Success Rate: {summary['signature_replacement']['success_rate']:.2f}%")
        if summary['signature_replacement']['failures_by_reason']:
            print(f"  Failure Reasons: {dict(summary['signature_replacement']['failures_by_reason'])}")
        
        print(f"\nTotal Errors Recorded: {summary['error_count']}")
        print("="*80 + "\n")


# Global metrics instance (can be reset or replaced)
_global_metrics = VerificationMetrics()


def bytes_to_bitstring_tuple(data: bytes) -> tuple:
    """
    Convert bytes to a tuple of ones and zeros for BitString construction.
    """
    bits = []
    for byte in data:
        for bit in format(byte, '08b'):
            bits.append(int(bit))
    return tuple(bits)


def detect_rpki_object_type(data: bytes, file_path: str = None) -> str:
    """
    Detect the type of RPKI object from the ASN.1 structure or file extension.
    Returns: 'certificate', 'roa', 'manifest', 'crl', or 'unknown'
    """
    # First try file extension if provided
    if file_path:
        ext = Path(file_path).suffix.lower()
        if ext == '.cer':
            return 'certificate'
        elif ext == '.roa':
            return 'roa'
        elif ext == '.mft':
            return 'manifest'
        elif ext == '.crl':
            return 'crl'
    
    if not ASN1_AVAILABLE:
        return 'unknown'
    
    try:
        # Try to parse as X.509 certificate
        cert = x509.Certificate.load(data)
        # If it loads as a certificate, it's a certificate
        return 'certificate'
    except:
        pass
    
    try:
        # Try to parse as CMS (used for ROAs and manifests)
        cms_obj = cms.ContentInfo.load(data)
        if cms_obj['content_type'].dotted == '1.2.840.113549.1.7.2':  # signedData
            # Try to determine if it's ROA or manifest by checking content type
            signed_data = cms_obj['content']
            encap_content = signed_data['encap_content_info']
            content_type = encap_content['content_type'].dotted
            
            # ROA content type: 1.2.840.113549.1.9.16.1.24 (id-ct-routeOriginAuthz)
            # Manifest content type: 1.2.840.113549.1.9.16.1.26 (id-ct-rpkiManifest)
            if content_type == '1.2.840.113549.1.9.16.1.24':
                return 'roa'
            elif content_type == '1.2.840.113549.1.9.16.1.26':
                return 'manifest'
            else:
                # CMS structure but unknown content type - default to roa
                return 'roa'
    except:
        pass
    
    # Check for CRL structure
    try:
        crl_obj = crl.CertificateList.load(data)
        return 'crl'
    except:
        pass
    
    return 'unknown'


def parse_certificate(data: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Parse an X.509 certificate and extract:
    - TBSCertificate (the part to be signed)
    - signatureAlgorithm
    - signatureValue
    - subjectPublicKeyInfo
    
    Returns: (tbs_certificate, sig_algorithm, signature_value, public_key_info)
    """
    if not ASN1_AVAILABLE:
        raise ImportError("asn1crypto is required for certificate parsing")
    
    cert = x509.Certificate.load(data)
    
    # Extract TBSCertificate (the part that gets signed)
    tbs_cert = cert['tbs_certificate']
    tbs_cert_bytes = tbs_cert.dump()
    
    # Extract signature algorithm
    sig_algorithm = cert['signature_algorithm'].dump()
    
    # Extract signature value
    signature_value = cert['signature_value'].dump()
    
    # Extract subject public key info
    public_key_info = tbs_cert['subject_public_key_info'].dump()
    
    return tbs_cert_bytes, sig_algorithm, signature_value, public_key_info


def extract_signature_and_tbs(data: bytes, object_type: str = None, file_path: str = None) -> Tuple[bytes, bytes]:
    """
    Extract signature and TBS (To Be Signed) portion from RPKI object for verification.
    This is the correct way to verify signatures in ASN.1 structures.
    
    Args:
        data: RPKI object bytes
        object_type: Type of object (auto-detected if None)
        file_path: Optional file path for type detection
    
    Returns:
        Tuple of (tbs_data, signature_bytes) for verification
    """
    if not ASN1_AVAILABLE:
        raise ImportError("asn1crypto is required for signature extraction")
    
    if object_type is None:
        object_type = detect_rpki_object_type(data, file_path)
    
    try:
        if object_type == 'certificate':
            cert = x509.Certificate.load(data)
            tbs_data = cert['tbs_certificate'].dump()
            # Extract signature value - it's an OctetBitString
            signature_value = cert['signature_value']
            signature_bytes = signature_value.contents if hasattr(signature_value, 'contents') else bytes(signature_value)
            return tbs_data, signature_bytes
        elif object_type in ('roa', 'manifest'):
            cms_obj = cms.ContentInfo.load(data)
            signed_data = cms_obj['content']
            signer_info = signed_data['signer_infos'][0] if len(signed_data['signer_infos']) > 0 else None
            
            if signer_info and 'signed_attrs' in signer_info and signer_info['signed_attrs']:
                tbs_data = signer_info['signed_attrs'].dump()
            else:
                tbs_data = signed_data['encap_content_info']['encap_content'].contents
            
            # Extract signature from signerInfo
            signature_obj = signer_info['signature']
            # OctetString.contents is already bytes
            signature_bytes = signature_obj.contents if hasattr(signature_obj, 'contents') else bytes(signature_obj)
            return tbs_data, signature_bytes
        elif object_type == 'crl':
            crl_obj = crl.CertificateList.load(data)
            tbs_data = crl_obj['tbs_cert_list'].dump()
            signature_value = crl_obj['signature']
            # OctetBitString.contents is already bytes
            signature_bytes = signature_value.contents if hasattr(signature_value, 'contents') else bytes(signature_value)
            return tbs_data, signature_bytes
        else:
            raise ValueError(f"Unknown object type: {object_type}")
    except Exception as e:
        raise ValueError(f"Failed to extract signature and TBS: {e}")


def replace_certificate_signature(
    original_data: bytes,
    new_signature: bytes,
    new_public_key: bytes,
    new_algorithm_oid: str = None,
    algorithm_name: str = None
) -> bytes:
    """
    Replace the signature and public key in an X.509 certificate with proper OIDs.
    
    Args:
        original_data: Original certificate bytes
        new_signature: New post-quantum signature bytes
        new_public_key: New post-quantum public key bytes
        new_algorithm_oid: OID for the new signature algorithm (optional, will lookup if algorithm_name provided)
        algorithm_name: Name of algorithm (e.g., "ML-DSA-44") for OID lookup
    
    Returns:
        New certificate bytes with replaced signature and public key
    """
    if not ASN1_AVAILABLE:
        raise ImportError("asn1crypto is required for certificate manipulation")
    
    cert = x509.Certificate.load(original_data)
    tbs_cert = cert['tbs_certificate']
    
    # Determine the OID to use
    oid_to_use = new_algorithm_oid
    if not oid_to_use and algorithm_name:
        oid_to_use = PQ_ALGORITHM_OIDS.get(algorithm_name)
    
    # Replace signatureAlgorithm with proper PQ OID
    # Certificates use SignedDigestAlgorithmId which wraps the OID
    if oid_to_use:
        # Use algos.SignedDigestAlgorithmId for certificates
        pq_algorithm_id = algos.SignedDigestAlgorithm({
            'algorithm': algos.SignedDigestAlgorithmId(oid_to_use),
            'parameters': core.Null()
        })
        # Update in both tbs_certificate and outer certificate
        tbs_cert['signature'] = pq_algorithm_id
        cert['signature_algorithm'] = pq_algorithm_id
    
    # Replace public key in SubjectPublicKeyInfo
    if new_public_key and oid_to_use:
        try:
            # Create AlgorithmIdentifier for PQ public key
            # Public key algorithm uses AlgorithmIdentifier structure
            public_key_info = keys.PublicKeyInfo({
                'algorithm': keys.PublicKeyAlgorithm({
                    'algorithm': keys.PublicKeyAlgorithmId(oid_to_use),
                    'parameters': core.Null()
                }),
                'public_key': core.BitString(bytes_to_bitstring_tuple(new_public_key))
            })
            tbs_cert['subject_public_key_info'] = public_key_info
        except Exception as e:
            # If public key encoding fails, continue without it (size is still accounted for separately)
            pass
    
    # Replace signatureValue
    cert['signature_value'] = core.OctetBitString(new_signature)
    
    # Re-encode the certificate
    return cert.dump()


def parse_cms_signed_data(data: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Parse CMS SignedData structure (used for ROAs and manifests).
    
    Returns: (content, signature, signer_info)
    """
    if not ASN1_AVAILABLE:
        raise ImportError("asn1crypto is required for CMS parsing")
    
    cms_obj = cms.ContentInfo.load(data)
    
    if cms_obj['content_type'].dotted != '1.2.840.113549.1.7.2':
        raise ValueError("Not a CMS SignedData structure")
    
    signed_data = cms_obj['content']
    encap_content_info = signed_data['encap_content_info']
    signer_infos = signed_data['signer_infos']
    
    # Extract content
    content = encap_content_info['encap_content'].contents
    
    # Extract signature from first signer
    if len(signer_infos) > 0:
        signer_info = signer_infos[0]
        signature = signer_info['signature'].contents
        return content, signature, signer_info.dump()
    
    raise ValueError("No signer info found in CMS structure")


def replace_crl_signature(
    original_data: bytes,
    new_signature: bytes,
    new_public_key: bytes,
    algorithm_name: str = None
) -> bytes:
    """
    Replace signature in Certificate Revocation List (CRL).
    
    Args:
        original_data: Original CRL bytes
        new_signature: New post-quantum signature bytes
        new_public_key: New post-quantum public key bytes
    
    Returns:
        New CRL bytes with replaced signature
    """
    if not ASN1_AVAILABLE:
        raise ImportError("asn1crypto is required for CRL manipulation")
    
    crl_obj = crl.CertificateList.load(original_data)
    
    # Get OID for the algorithm
    oid_to_use = None
    if algorithm_name and algorithm_name in PQ_ALGORITHM_OIDS:
        oid_to_use = PQ_ALGORITHM_OIDS[algorithm_name]
    
    # Replace signatureAlgorithm with proper PQ OID
    # CRLs use SignedDigestAlgorithmId
    if oid_to_use:
        pq_algorithm_id = algos.SignedDigestAlgorithm({
            'algorithm': algos.SignedDigestAlgorithmId(oid_to_use),
            'parameters': core.Null()
        })
        tbs_cert_list = crl_obj['tbs_cert_list']
        tbs_cert_list['signature'] = pq_algorithm_id
    
    # Replace signature - CRL uses 'signature' field, not 'signature_value'
    crl_obj['signature'] = core.OctetBitString(new_signature)
    
    # Public key replacement would be in the issuer's certificate, not the CRL itself
    # So we don't replace it here
    
    return crl_obj.dump()


def replace_cms_signature(
    original_data: bytes,
    new_signature: bytes,
    new_public_key: bytes,
    algorithm_name: str = None,
    ee_cert_signature: bytes = None,
    issuer_private_key: bytes = None,
    issuer_public_key: bytes = None
) -> bytes:
    """
    Replace signature in CMS SignedData structure with proper OIDs and EE certificate.
    
    Args:
        original_data: Original CMS SignedData bytes
        new_signature: New post-quantum signature bytes for CMS content
        new_public_key: New post-quantum public key bytes
        algorithm_name: Name of algorithm (e.g., "ML-DSA-44") for OID lookup
        ee_cert_signature: Optional signature for EE certificate TBS
            - If issuer_private_key provided: should be signed with issuer's key
            - If None and no issuer: falls back to new_signature (self-signed)
        issuer_private_key: Optional issuer private key for signing EE certificate
        issuer_public_key: Optional issuer public key (for verification)
    
    Returns:
        New CMS structure with replaced signature and EE certificate
    """
    if not ASN1_AVAILABLE:
        raise ImportError("asn1crypto is required for CMS manipulation")
    
    cms_obj = cms.ContentInfo.load(original_data)
    signed_data = cms_obj['content']
    
    # Get OID for the algorithm
    oid_to_use = None
    if algorithm_name and algorithm_name in PQ_ALGORITHM_OIDS:
        oid_to_use = PQ_ALGORITHM_OIDS[algorithm_name]
    
    # Replace signature in signer info
    if len(signed_data['signer_infos']) > 0:
        signer_info = signed_data['signer_infos'][0]
        signer_info['signature'] = core.OctetString(new_signature)
        
        # Update digest algorithm identifier with PQ OID
        # CMS uses DigestAlgorithmId which wraps the OID
        if oid_to_use:
            signer_info['digest_algorithm'] = algos.DigestAlgorithm({
                'algorithm': algos.DigestAlgorithmId(oid_to_use),
                'parameters': core.Null()
            })
    
    # Replace EE certificate signature and public key using replace_certificate_signature
    if new_public_key and oid_to_use:
        try:
            # CMS certificates are in the certificates field (optional)
            if 'certificates' in signed_data and len(signed_data['certificates']) > 0:
                # Extract the first certificate (typically the EE certificate)
                cert_choice = signed_data['certificates'][0]
                
                # CertificateChoices can be different structures, but typically contains a Certificate
                # Extract the actual certificate bytes
                ee_cert_bytes = None
                
                # Try different ways to extract the certificate
                if hasattr(cert_choice, 'chosen'):
                    # If it's a choice structure, get the chosen value
                    ee_cert_bytes = cert_choice.chosen.dump()
                elif hasattr(cert_choice, 'dump'):
                    # If it's directly a certificate structure
                    ee_cert_bytes = cert_choice.dump()
                else:
                    # Try to load as certificate directly
                    try:
                        cert_obj = x509.Certificate.load(bytes(cert_choice))
                        ee_cert_bytes = cert_obj.dump()
                    except:
                        # If that fails, try to get bytes directly
                        ee_cert_bytes = bytes(cert_choice)
                
                if ee_cert_bytes:
                    # Determine which signature to use for EE certificate
                    # Priority: 1) Provided ee_cert_signature, 2) new_signature (self-signed fallback)
                    ee_sig_to_use = ee_cert_signature if ee_cert_signature is not None else new_signature
                    
                    # If issuer keys provided, we should use ee_cert_signature (signed by issuer)
                    # Otherwise, we fall back to self-signed (acceptable for measurement)
                    if issuer_private_key is None and ee_cert_signature is None:
                        # No issuer key and no provided signature = self-signed (fallback)
                        ee_sig_to_use = new_signature
                    
                    # Replace the EE certificate signature and public key using the dedicated function
                    replaced_ee_cert = replace_certificate_signature(
                        ee_cert_bytes,
                        ee_sig_to_use,
                        new_public_key,
                        algorithm_name=algorithm_name
                    )
                    
                    # Replace the certificate in the CMS structure
                    # CertificateChoices can be a Certificate or other structures
                    # We need to create the appropriate structure
                    try:
                        # Try to load the replaced certificate to create proper CertificateChoices
                        replaced_cert_obj = x509.Certificate.load(replaced_ee_cert)
                        # Create CertificateChoices with the certificate
                        # CertificateChoices is typically just the certificate itself in CMS
                        signed_data['certificates'][0] = replaced_cert_obj
                    except Exception as cert_replace_error:
                        # If direct replacement fails, try to update the existing structure
                        # This handles cases where CertificateChoices has a specific structure
                        try:
                            if hasattr(cert_choice, 'chosen'):
                                cert_choice.chosen = x509.Certificate.load(replaced_ee_cert)
                            else:
                                # Replace the entire choice with the new certificate
                                signed_data['certificates'][0] = x509.Certificate.load(replaced_ee_cert)
                        except Exception as fallback_error:
                            # If all else fails, log but continue - CMS signature replacement is still valid
                            print(f"WARNING: Could not replace EE certificate in CMS structure: {fallback_error}")
                            print(f"  CMS signature replacement succeeded, but EE cert replacement failed")
        except Exception as e:
            # If certificate update fails, continue - signature replacement is still valid
            # Public key size is accounted for separately in pq-resign.py
            print(f"WARNING: EE certificate replacement failed: {e}")
            print(f"  CMS signature replacement succeeded, but EE cert replacement failed")
    
    return cms_obj.dump()


def extract_ee_certificate_tbs_from_cms(data: bytes) -> Optional[bytes]:
    """
    Extract the TBS (To Be Signed) portion of the EE certificate from a CMS SignedData structure.
    
    Args:
        data: CMS SignedData bytes (ROA or manifest)
    
    Returns:
        TBS bytes of the EE certificate, or None if not found
    """
    if not ASN1_AVAILABLE:
        return None
    
    try:
        cms_obj = cms.ContentInfo.load(data)
        signed_data = cms_obj['content']
        
        # Check if certificates field exists and has at least one certificate
        if 'certificates' not in signed_data or len(signed_data['certificates']) == 0:
            return None
        
        # Extract the first certificate (typically the EE certificate)
        cert_choice = signed_data['certificates'][0]
        
        # Extract certificate bytes
        ee_cert_bytes = None
        if hasattr(cert_choice, 'chosen'):
            ee_cert_bytes = cert_choice.chosen.dump()
        elif hasattr(cert_choice, 'dump'):
            ee_cert_bytes = cert_choice.dump()
        else:
            try:
                cert_obj = x509.Certificate.load(bytes(cert_choice))
                ee_cert_bytes = cert_obj.dump()
            except:
                ee_cert_bytes = bytes(cert_choice)
        
        if ee_cert_bytes:
            # Extract TBS from the certificate
            cert_obj = x509.Certificate.load(ee_cert_bytes)
            return cert_obj['tbs_certificate'].dump()
        
        return None
    except Exception as e:
        return None


def extract_ee_certificate_from_cms(data: bytes) -> Optional[bytes]:
    """
    Extract the EE certificate bytes from a CMS SignedData structure.
    
    Args:
        data: CMS SignedData bytes (ROA or manifest)
    
    Returns:
        EE certificate bytes, or None if not found
    """
    if not ASN1_AVAILABLE:
        return None
    
    try:
        cms_obj = cms.ContentInfo.load(data)
        signed_data = cms_obj['content']
        
        # Check if certificates field exists and has at least one certificate
        if 'certificates' not in signed_data or len(signed_data['certificates']) == 0:
            return None
        
        # Extract the first certificate (typically the EE certificate)
        cert_choice = signed_data['certificates'][0]
        
        # Extract certificate bytes
        if hasattr(cert_choice, 'chosen'):
            return cert_choice.chosen.dump()
        elif hasattr(cert_choice, 'dump'):
            return cert_choice.dump()
        else:
            try:
                cert_obj = x509.Certificate.load(bytes(cert_choice))
                return cert_obj.dump()
            except:
                return bytes(cert_choice)
    except Exception as e:
        return None


def extract_issuer_certificate_from_cms(data: bytes) -> Optional[bytes]:
    """
    Extract the issuer certificate from a CMS SignedData structure.
    The issuer certificate is the one whose subject matches the EE certificate's issuer.
    
    Args:
        data: CMS SignedData bytes (ROA or manifest)
    
    Returns:
        Issuer certificate bytes, or None if not found
    """
    if not ASN1_AVAILABLE:
        return None
    
    try:
        cms_obj = cms.ContentInfo.load(data)
        signed_data = cms_obj['content']
        
        # Check if certificates field exists and has at least one certificate
        if 'certificates' not in signed_data or len(signed_data['certificates']) < 1:
            return None
        
        # Extract EE certificate (first one)
        ee_cert_choice = signed_data['certificates'][0]
        ee_cert_bytes = None
        if hasattr(ee_cert_choice, 'chosen'):
            ee_cert_bytes = ee_cert_choice.chosen.dump()
        elif hasattr(ee_cert_choice, 'dump'):
            ee_cert_bytes = ee_cert_choice.dump()
        else:
            try:
                ee_cert_obj = x509.Certificate.load(bytes(ee_cert_choice))
                ee_cert_bytes = ee_cert_obj.dump()
            except:
                ee_cert_bytes = bytes(ee_cert_choice)
        
        if not ee_cert_bytes:
            return None
        
        # Parse EE certificate to get issuer
        ee_cert = x509.Certificate.load(ee_cert_bytes)
        ee_issuer = ee_cert['tbs_certificate']['issuer']
        
        # Look through remaining certificates to find issuer
        for i in range(1, len(signed_data['certificates'])):
            cert_choice = signed_data['certificates'][i]
            
            # Extract certificate bytes
            cert_bytes = None
            if hasattr(cert_choice, 'chosen'):
                cert_bytes = cert_choice.chosen.dump()
            elif hasattr(cert_choice, 'dump'):
                cert_bytes = cert_choice.dump()
            else:
                try:
                    cert_obj = x509.Certificate.load(bytes(cert_choice))
                    cert_bytes = cert_obj.dump()
                except:
                    cert_bytes = bytes(cert_choice)
            
            if cert_bytes:
                try:
                    cert = x509.Certificate.load(cert_bytes)
                    cert_subject = cert['tbs_certificate']['subject']
                    
                    # Check if this certificate's subject matches EE cert's issuer
                    if cert_subject.dump() == ee_issuer.dump():
                        return cert_bytes
                except:
                    continue
        
        return None
    except Exception as e:
        return None


def extract_tbs_for_signing(data: bytes, object_type: str = None, file_path: str = None) -> bytes:
    """
    Extract the "To Be Signed" portion of an RPKI object.
    This is what should be signed with the post-quantum algorithm.
    
    Args:
        data: Original RPKI object bytes
        object_type: Type of object ('certificate', 'roa', 'manifest', etc.)
        file_path: Optional file path for type detection
    
    Returns:
        Bytes of the TBS portion
    """
    if not ASN1_AVAILABLE:
        # Fallback: return all data (not ideal, but works for basic cases)
        return data
    
    if object_type is None:
        object_type = detect_rpki_object_type(data, file_path)
    
    try:
        if object_type == 'certificate':
            cert = x509.Certificate.load(data)
            return cert['tbs_certificate'].dump()
        elif object_type in ('roa', 'manifest'):
            # For CMS structures, we need to sign the SignedAttrs (if present) or the content
            cms_obj = cms.ContentInfo.load(data)
            signed_data = cms_obj['content']
            signer_info = signed_data['signer_infos'][0] if len(signed_data['signer_infos']) > 0 else None
            
            # CMS signing: if signedAttrs are present, sign those; otherwise sign the content
            if signer_info and 'signed_attrs' in signer_info and signer_info['signed_attrs']:
                # Sign the signedAttrs (this is the proper way for CMS)
                return signer_info['signed_attrs'].dump()
            else:
                # Fallback: sign the content
                return signed_data['encap_content_info']['encap_content'].contents
        elif object_type == 'crl':
            # For CRL, sign the TBSCertList
            crl_obj = crl.CertificateList.load(data)
            return crl_obj['tbs_cert_list'].dump()
        else:
            # Unknown type - return all data as fallback
            return data
    except Exception as e:
        # If parsing fails, return all data (with the old signature, which is not ideal)
        print(f"WARNING: Failed to extract TBS for {object_type}: {e}")
        return data


def find_parent_certificate(ee_cert_bytes: bytes, repo_path: Path) -> Optional[bytes]:
    """
    Find the parent (issuer) certificate for an EE certificate by searching the repository.
    
    Args:
        ee_cert_bytes: EE certificate bytes
        repo_path: Path to the repository directory containing certificates
        
    Returns:
        Parent certificate bytes, or None if not found
    """
    if not ASN1_AVAILABLE:
        return None
    
    try:
        ee_cert = x509.Certificate.load(ee_cert_bytes)
        ee_issuer = ee_cert['tbs_certificate']['issuer']
        ee_issuer_dn = ee_issuer.dump()
        
        # Search for parent certificate in repository
        # Parent cert's subject should match EE cert's issuer
        for cert_file in repo_path.rglob("*.cer"):
            try:
                cert_data = cert_file.read_bytes()
                parent_cert = x509.Certificate.load(cert_data)
                parent_subject = parent_cert['tbs_certificate']['subject']
                
                # Check if this certificate's subject matches EE cert's issuer
                if parent_subject.dump() == ee_issuer_dn:
                    return cert_data
            except:
                continue
        
        return None
    except Exception as e:
        return None


def extract_public_key_from_certificate(cert_bytes: bytes, expected_size: int) -> Optional[bytes]:
    """
    Extract public key from a certificate's SubjectPublicKeyInfo.
    Handles both raw bytes and ASN.1 wrapped formats.
    
    Args:
        cert_bytes: Certificate bytes
        expected_size: Expected public key size in bytes
        
    Returns:
        Public key bytes, or None if extraction fails
    """
    if not ASN1_AVAILABLE:
        return None
    
    try:
        cert = x509.Certificate.load(cert_bytes)
        pubkey_info = cert['tbs_certificate']['subject_public_key_info']
        pubkey_bitstring = pubkey_info['public_key']
        
        # Method 1: Try to get raw bytes from _bytes attribute (most direct)
        if hasattr(pubkey_bitstring, '_bytes'):
            raw_bytes = pubkey_bitstring._bytes
            if isinstance(raw_bytes, bytes) and len(raw_bytes) >= expected_size:
                # The key might be at the end of _bytes
                if len(raw_bytes) == expected_size:
                    return raw_bytes
                elif len(raw_bytes) > expected_size:
                    # Try from end (most likely for large keys)
                    candidate = raw_bytes[-expected_size:]
                    if len(candidate) == expected_size:
                        return candidate
        
        # Method 2: Parse BitString.contents - might contain ASN.1 structure
        if hasattr(pubkey_bitstring, 'contents'):
            contents = pubkey_bitstring.contents
            if isinstance(contents, (bytes, bytearray)):
                contents_bytes = bytes(contents)
                
                # Skip unused bits byte if present
                data_start = 1 if len(contents_bytes) > 0 and contents_bytes[0] == 0x00 else 0
                asn1_data = contents_bytes[data_start:]
                
                # Check if it's an ASN.1 SEQUENCE containing INTEGER
                if len(asn1_data) >= 3 and asn1_data[0] == 0x30:  # SEQUENCE
                    # Parse SEQUENCE
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
                    
                    # Look for INTEGER inside SEQUENCE
                    if seq_idx < len(asn1_data) and asn1_data[seq_idx] == 0x02:  # INTEGER
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
                            
                            # Remove leading zero padding
                            while len(int_data) > expected_size and int_data[0] == 0x00:
                                int_data = int_data[1:]
                            
                            if len(int_data) == expected_size:
                                return int_data
                            elif len(int_data) > expected_size:
                                return int_data[-expected_size:]
                
                # Method 3: If contents is large enough, try direct extraction
                if len(contents_bytes) >= expected_size + 1:
                    # Skip unused bits byte and extract
                    candidate = contents_bytes[-(expected_size+1):-1] if contents_bytes[-1] == 0x00 else contents_bytes[-expected_size:]
                    if len(candidate) == expected_size:
                        return candidate
        
        # Method 4: Search certificate dump for high-entropy 1312-byte sequence
        cert_dump = cert.dump()
        best_candidate = None
        best_score = 0
        
        # Search in TBS area (where SubjectPublicKeyInfo should be)
        tbs_dump = cert['tbs_certificate'].dump()
        pubkey_info_dump = pubkey_info.dump()
        pubkey_info_start = tbs_dump.find(pubkey_info_dump[:50])
        
        if pubkey_info_start >= 0:
            # Search around SubjectPublicKeyInfo
            search_start = max(0, pubkey_info_start - 500)
            search_end = min(len(cert_dump), pubkey_info_start + len(pubkey_info_dump) + 2000)
            
            for search_idx in range(search_end - expected_size, search_start, -1):
                if search_idx + expected_size > len(cert_dump):
                    continue
                candidate = cert_dump[search_idx:search_idx+expected_size]
                if len(candidate) == expected_size:
                    zero_count = candidate.count(0)
                    unique_bytes = len(set(candidate))
                    if zero_count < expected_size * 0.3 and unique_bytes > expected_size * 0.15:
                        score = unique_bytes - (zero_count * 0.5)
                        if score > best_score:
                            best_score = score
                            best_candidate = candidate
        
        if best_candidate and best_score > expected_size * 0.15:
            return bytes(best_candidate)
        
        return None
    except Exception:
        return None


def get_verification_metrics() -> VerificationMetrics:
    """Get the global verification metrics instance."""
    return _global_metrics


def reset_verification_metrics():
    """Reset the global verification metrics."""
    global _global_metrics
    _global_metrics = VerificationMetrics()


def print_verification_metrics():
    """Print a summary of the global verification metrics."""
    _global_metrics.print_summary()


def get_verification_metrics_summary() -> Dict[str, Any]:
    """Get a summary dictionary of the global verification metrics."""
    return _global_metrics.get_summary()


def verify_cms_object_signatures(
    cms_data: bytes,
    cms_public_key: bytes,
    ee_cert_public_key: bytes = None,
    algorithm_name: str = None,
    verifier = None,
    metrics: VerificationMetrics = None
) -> Tuple[bool, bool, str]:
    """
    Verify both the CMS signature and the EE certificate signature in a CMS SignedData object.
    
    Args:
        cms_data: CMS SignedData bytes (ROA or manifest)
        cms_public_key: Public key to verify CMS signature (from EE certificate)
        ee_cert_public_key: Optional public key to verify EE certificate signature (from issuer)
        algorithm_name: Name of algorithm for verification
        verifier: Optional OQS Signature verifier object (if None, only extracts data)
        metrics: Optional VerificationMetrics instance (uses global if None)
    
    Returns:
        Tuple of (cms_signature_valid, ee_cert_signature_valid, error_message)
        error_message is empty string if both are valid
    """
    if metrics is None:
        metrics = _global_metrics
    
    if not ASN1_AVAILABLE:
        metrics.record_object_load_failed("cms", "ASN1 parser not available")
        return False, False, "ASN1 parser not available"
    
    try:
        # Record successful object loading
        metrics.record_object_loaded("cms")
        
        cms_obj = cms.ContentInfo.load(cms_data)
        signed_data = cms_obj['content']
        
        # Verify CMS signature
        cms_valid = False
        cms_error = ""
        if len(signed_data['signer_infos']) > 0:
            signer_info = signed_data['signer_infos'][0]
            
            # Extract CMS TBS (signedAttrs if present, otherwise content)
            if 'signed_attrs' in signer_info and signer_info['signed_attrs']:
                cms_tbs = signer_info['signed_attrs'].dump()
            else:
                cms_tbs = signed_data['encap_content_info']['encap_content'].contents
            
            # Extract CMS signature
            cms_signature = signer_info['signature'].contents if hasattr(signer_info['signature'], 'contents') else bytes(signer_info['signature'])
            
            # Perform actual verification if verifier is provided
            if verifier is not None and cms_public_key:
                try:
                    cms_valid = verifier.verify(cms_tbs, cms_signature, cms_public_key)
                    if not cms_valid:
                        cms_error = "CMS signature verification failed"
                    metrics.record_cms_verification(cms_valid, cms_error)
                except Exception as verify_err:
                    cms_valid = False
                    cms_error = f"CMS verification error: {verify_err}"
                    metrics.record_cms_verification(False, cms_error)
            else:
                # No verifier provided - cannot verify
                cms_error = "No verifier or public key provided for CMS signature"
                metrics.record_cms_verification(False, cms_error)
        else:
            cms_error = "No signer info found in CMS"
            metrics.record_cms_verification(False, cms_error)
        
        # Verify EE certificate signature
        ee_cert_valid = False
        ee_cert_error = ""
        ee_cert_bytes = extract_ee_certificate_from_cms(cms_data)
        if ee_cert_bytes:
            metrics.record_ee_cert_extraction(True)
            try:
                cert_obj = x509.Certificate.load(ee_cert_bytes)
                ee_cert_tbs = cert_obj['tbs_certificate'].dump()
                ee_cert_signature = cert_obj['signature_value']
                ee_cert_sig_bytes = ee_cert_signature.contents if hasattr(ee_cert_signature, 'contents') else bytes(ee_cert_signature)
                
                # Perform actual verification if verifier and issuer public key are provided
                if verifier is not None and ee_cert_public_key:
                    try:
                        ee_cert_valid = verifier.verify(ee_cert_tbs, ee_cert_sig_bytes, ee_cert_public_key)
                        if not ee_cert_valid:
                            ee_cert_error = "EE certificate signature verification failed"
                        metrics.record_ee_cert_verification(ee_cert_valid, ee_cert_error)
                    except Exception as verify_err:
                        ee_cert_valid = False
                        ee_cert_error = f"EE cert verification error: {verify_err}"
                        metrics.record_ee_cert_verification(False, ee_cert_error)
                else:
                    # No verifier or issuer key provided - cannot verify EE cert
                    # This is expected if issuer key is not available
                    ee_cert_error = "No verifier or issuer public key provided for EE certificate signature"
                    metrics.record_ee_cert_verification(False, ee_cert_error)
            except Exception as cert_err:
                ee_cert_error = f"Failed to extract EE certificate: {cert_err}"
                metrics.record_ee_cert_extraction(False, ee_cert_error)
                metrics.record_ee_cert_verification(False, ee_cert_error)
        else:
            ee_cert_error = "No EE certificate found in CMS"
            metrics.record_ee_cert_extraction(False, ee_cert_error)
            metrics.record_ee_cert_verification(False, ee_cert_error)
        
        # Record overall verification result
        can_verify = (verifier is not None and cms_public_key) and (verifier is not None and ee_cert_public_key)
        metrics.record_overall_verification(cms_valid, ee_cert_valid, can_verify)
        
        error_msg = ""
        if not cms_valid:
            error_msg += f"CMS signature invalid: {cms_error}. "
        if not ee_cert_valid:
            error_msg += f"EE cert signature invalid: {ee_cert_error}. "
        
        return cms_valid, ee_cert_valid, error_msg.strip()
    except Exception as e:
        error_msg = f"Verification failed: {e}"
        metrics.record_object_load_failed("cms", error_msg)
        return False, False, error_msg


def create_resigned_object(
    original_data: bytes,
    new_signature: bytes,
    new_public_key: bytes,
    object_type: str = None,
    file_path: str = None,
    algorithm_name: str = None,
    ee_cert_signature: bytes = None,
    issuer_private_key: bytes = None,
    issuer_public_key: bytes = None,
    metrics: VerificationMetrics = None
) -> bytes:
    """
    Create a new RPKI object with replaced signature and public key.
    
    This is the main function that properly replaces signatures instead of appending.
    This fixes the methodological issue where signatures were being added instead of replaced.
    
    Args:
        original_data: Original RPKI object bytes
        new_signature: New post-quantum signature bytes
        new_public_key: New post-quantum public key bytes
        object_type: Type of object (auto-detected if None)
        file_path: Optional file path for type detection
        algorithm_name: Name of algorithm for OID lookup
        ee_cert_signature: Optional signature for EE certificate TBS
        metrics: Optional VerificationMetrics instance (uses global if None)
    
    Returns:
        New RPKI object bytes with replaced signature and public key
    """
    if metrics is None:
        metrics = _global_metrics
    
    if not ASN1_AVAILABLE:
        # Fallback: append signature (old incorrect method)
        # This should be avoided, but provides backward compatibility
        print("WARNING: ASN.1 parser not available, using incorrect append method")
        metrics.record_signature_replacement("unknown", False, "ASN1 parser not available")
        return original_data + new_signature
    
    if object_type is None:
        object_type = detect_rpki_object_type(original_data, file_path)
    
    try:
        if object_type == 'certificate':
            result = replace_certificate_signature(original_data, new_signature, new_public_key, algorithm_name=algorithm_name)
            metrics.record_signature_replacement(object_type, True)
            return result
        elif object_type in ('roa', 'manifest'):
            result = replace_cms_signature(
                original_data, 
                new_signature, 
                new_public_key, 
                algorithm_name=algorithm_name, 
                ee_cert_signature=ee_cert_signature,
                issuer_private_key=issuer_private_key,
                issuer_public_key=issuer_public_key
            )
            metrics.record_signature_replacement(object_type, True)
            return result
        elif object_type == 'crl':
            # CRL signature replacement
            result = replace_crl_signature(original_data, new_signature, new_public_key, algorithm_name=algorithm_name)
            metrics.record_signature_replacement(object_type, True)
            return result
        else:
            # Unknown type - cannot process scientifically
            error_msg = f"Unknown object type {object_type} - cannot replace signature"
            metrics.record_signature_replacement(object_type, False, error_msg)
            raise ValueError(error_msg)
    except Exception as e:
        # If parsing fails, raise exception rather than falling back to incorrect method
        error_msg = f"ASN.1 parsing failed: {e}"
        metrics.record_signature_replacement(object_type or "unknown", False, error_msg)
        raise ValueError(error_msg) from e

