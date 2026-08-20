from pathlib import Path
import sys

# Add the vendored copy of secp256k1lab to path.
sys.path.append(str(Path(__file__).parent / "../secp256k1lab/src"))

from .trusted_dealer_ref import (
    # Functions
    trusted_dealer_keygen,
    trusted_dealer_keygen_internal,
    derive_pubshare_from_commitment,
    thresh_pubkey_from_commitment,
    verify_secshare,
    parse_vss_commitment,
    polynomial_evaluate,
    polynomial_evaluate_point,
    random_scalar,
    random_nonzero_scalar,
    # Types
    DealerOutput,
    PlainPk,
)

__all__ = [
    "trusted_dealer_keygen",
    "trusted_dealer_keygen_internal",
    "derive_pubshare_from_commitment",
    "thresh_pubkey_from_commitment",
    "verify_secshare",
    "parse_vss_commitment",
    "polynomial_evaluate",
    "polynomial_evaluate_point",
    "random_scalar",
    "random_nonzero_scalar",
    "DealerOutput",
    "PlainPk",
]
