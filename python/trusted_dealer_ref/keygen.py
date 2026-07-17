# BIP FROST Trusted Dealer Key Generation - reference implementation
#
# WARNING: This implementation is for demonstration purposes only and _not_ to
# be used in production environments.

import secrets
from typing import List, NamedTuple, NewType, Optional

from secp256k1lab.secp256k1 import G, GE, Scalar


# A 33-byte compressed point ("plain" public key).
PlainPk = NewType("PlainPk", bytes)


def random_scalar() -> Scalar:
    while True:
        try:
            return Scalar.from_bytes_checked(secrets.token_bytes(32))
        except ValueError:
            continue


def random_nonzero_scalar() -> Scalar:
    while True:
        s = random_scalar()
        if s != 0:
            return s


def polynomial_evaluate(coeffs: List[Scalar], x: Scalar) -> Scalar:
    """Evaluate f(x) using Horner's method."""
    value = Scalar(0)
    for coeff in reversed(coeffs):
        value = value * x + coeff
    return value


def polynomial_evaluate_point(commitments: List[GE], x: Scalar) -> GE:
    result = GE()  # point at infinity (additive identity)
    for A_k in reversed(commitments):
        result = x * result + A_k
    return result


def parse_vss_commitment(vss_commitment: List[bytes]) -> List[GE]:
    if len(vss_commitment) == 0:
        raise ValueError("The vss_commitment must contain at least one element.")
    points = []
    for k, enc in enumerate(vss_commitment):
        if len(enc) != 33:
            raise ValueError(f"Invalid vss_commitment element at index {k}.")
        try:
            A_k = GE.from_bytes_compressed_with_infinity(enc)
        except ValueError:
            raise ValueError(f"Invalid vss_commitment element at index {k}.")
        points.append(A_k)
    if points[0].infinity:
        raise ValueError("The constant-term commitment A_0 must not be infinity.")
    return points


#
# Key generation (dealer side)
#
class DealerOutput(NamedTuple):
    # Published to all participants over a consistent broadcast channel:
    vss_commitment: List[bytes]  # t elements, 33 bytes each (cbytes_ext)
    thresh_pk: PlainPk  # 33 bytes, cbytes(A_0); derivable from the above
    pubshares: List[PlainPk]  # n elements, 33 bytes each; derivable from the above
    # Delivered privately, secshares[id] to the participant with identifier id:
    secshares: List[bytes]  # n elements, 32 bytes each


def trusted_dealer_keygen(
    t: int, n: int, seckey: Optional[bytes] = None
) -> DealerOutput:
    if not 2 <= n < 2**32:
        raise ValueError("The number of participants must be 2 <= n < 2**32.")
    if not 1 <= t <= n:
        raise ValueError("The threshold must be 1 <= t <= n.")

    if seckey is not None:
        if len(seckey) != 32:
            raise ValueError("The seckey argument must have length 32.")
        try:
            a_0 = Scalar.from_bytes_nonzero_checked(seckey)
        except ValueError:
            raise ValueError("The seckey argument must decode to a nonzero scalar.")
    else:
        a_0 = random_nonzero_scalar()
    coeffs = [a_0] + [random_scalar() for _ in range(t - 1)]

    return trusted_dealer_keygen_internal(coeffs, n)


def trusted_dealer_keygen_internal(coeffs: List[Scalar], n: int) -> DealerOutput:
    t = len(coeffs)
    if not (1 <= t <= n and 2 <= n < 2**32):
        raise ValueError("Invalid (t, n) parameters.")
    if coeffs[0] == 0:
        raise ValueError("The constant term a_0 must be nonzero.")

    # Feldman VSS commitments to the polynomial: A_k = a_k * G.
    commitment_points = [a_k * G for a_k in coeffs]
    vss_commitment = [
        A_k.to_bytes_compressed_with_infinity() for A_k in commitment_points
    ]
    assert not commitment_points[0].infinity
    thresh_pk = PlainPk(commitment_points[0].to_bytes_compressed())

    secshares: List[bytes] = []
    pubshares: List[PlainPk] = []
    for my_id in range(n):
        # The participant identifiers are 0-based
        x = Scalar(my_id + 1)
        d = polynomial_evaluate(coeffs, x)
        if d == 0:
            # Occurs only with negligible probability for honestly sampled
            # coefficients. A zero share is not a valid secshare, so
            # the dealer aborts and re-runs key generation.
            raise ValueError(
                f"Secret share for participant {my_id} is zero; re-run key generation."
            )
        P = d * G
        pubshare = PlainPk(P.to_bytes_compressed())
        # Mandatory dealer self-check: the pubshare recomputed from the
        # public commitment must match the one derived from the secret share.
        if pubshare != derive_pubshare_from_commitment(my_id, n, vss_commitment):
            raise RuntimeError("Dealer self-check failed; aborting.")
        secshares.append(d.to_bytes())
        pubshares.append(pubshare)

    return DealerOutput(vss_commitment, thresh_pk, pubshares, secshares)


#
# Participant-side derivation and verification
#
def derive_pubshare_from_commitment(my_id: int, n: int, vss_commitment: List[bytes]) -> PlainPk:
    if not 0 <= my_id < n:
        raise ValueError("The participant identifier is out of range.")
    points = parse_vss_commitment(vss_commitment)
    E = polynomial_evaluate_point(points, Scalar(my_id + 1))
    if E.infinity:
        raise ValueError("A zero share is invalid.")
    return PlainPk(E.to_bytes_compressed())


def thresh_pubkey_from_commitment(vss_commitment: List[bytes]) -> PlainPk:
    """Every participant MUST derive thresh_pk from its own view of
    vss_commitment rather than accepting it from the dealer."""
    points = parse_vss_commitment(vss_commitment)
    return PlainPk(points[0].to_bytes_compressed())


def verify_secshare(my_id: int, n: int, secshare: bytes, vss_commitment: List[bytes]) -> bool:
    """Verify a received secret share against the VSS commitment

    A participant MUST run this check on its received share and abort the
    protocol if it fails."""
    if len(secshare) != 32:
        return False
    try:
        d = Scalar.from_bytes_nonzero_checked(secshare)
    except ValueError:
        return False  # zero, or >= group order (no modular reduction on parse)
    expected = derive_pubshare_from_commitment(my_id, n, vss_commitment)
    return (d * G).to_bytes_compressed() == expected
