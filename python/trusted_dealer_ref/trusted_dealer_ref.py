# BIP FROST Trusted Dealer Key Generation - reference implementation
#
# WARNING: This implementation is for demonstration and interoperability
# testing only. It is slow, not constant-time, and does not provide reliable
# secret-memory erasure. It MUST NOT be used in production environments.

from __future__ import annotations

import secrets
from typing import List, NamedTuple, NewType, Optional

from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.util import tagged_hash


# 33-byte ordinary compressed secp256k1 public key.
PlainPk = NewType("PlainPk", bytes)

# Serialized VSS commitment:
#
#     cbytes_ext(B_0) || ... || cbytes_ext(B_{t-1})
#
# exactly 33*t bytes.
VSSCommitment = NewType("VSSCommitment", bytes)


#
# Internal failure classes
#


class ZeroFinalShareError(ValueError):
    """A final post-Taproot-safety participant share is zero."""


class TaprootSafetyError(ValueError):
    """The mandatory Taproot-safety transformation failed."""


#
# Output types
#


class DealerOutput(NamedTuple):
    # Public key-generation output.
    vss_commitment: VSSCommitment
    thresh_pk: PlainPk
    pubshares: List[PlainPk]

    # Private outputs. secshares[id] belongs only to participant id.
    secshares: List[bytes]


class TaprootSafetyResult(NamedTuple):
    final_coeffs: List[Scalar]
    final_commitments: List[GE]
    tweak: Scalar


class ParticipantAcceptedKeyMaterial(NamedTuple):
    participant_id: int
    secshare: bytes
    thresh_pk: PlainPk
    pubshare: PlainPk
    vss_commitment: VSSCommitment


#
# Parameters and randomness
#


def validate_params(t: int, n: int) -> None:
    if not (1 <= t <= n <= 128):
        raise ValueError(
            "Parameters must satisfy 1 <= t <= n <= 128."
        )


def random_scalar() -> Scalar:
    """Sample uniformly from {0, ..., q - 1} using rejection sampling."""
    while True:
        try:
            return Scalar.from_bytes_checked(secrets.token_bytes(32))
        except ValueError:
            # Candidate was >= the secp256k1 group order.
            continue


def random_nonzero_scalar() -> Scalar:
    """Sample uniformly from {1, ..., q - 1}."""
    while True:
        s = random_scalar()
        if s != Scalar(0):
            return s


#
# Polynomial operations
#


def polynomial_evaluate(
    coeffs: List[Scalar],
    x: Scalar,
) -> Scalar:
    """Evaluate a scalar polynomial using Horner's method."""
    if len(coeffs) == 0:
        raise ValueError(
            "Polynomial must contain at least one coefficient."
        )

    value = Scalar(0)

    for coeff in reversed(coeffs):
        value = value * x + coeff

    return value


def polynomial_evaluate_point(
    commitments: List[GE],
    x: Scalar,
) -> GE:
    """Evaluate a committed polynomial in the group using Horner's method."""
    if len(commitments) == 0:
        raise ValueError(
            "Commitment must contain at least one element."
        )

    result = GE()  # infinity / additive identity

    for commitment in reversed(commitments):
        result = x * result + commitment

    return result


#
# Participant identifiers
#


def participant_evaluation_point(
    participant_id: int,
    n: int,
) -> Scalar:
    """
    Convert the BIP 445 participant identifier to its Shamir
    evaluation point.

        x_id = participant_id + 1
    """
    if not (1 <= n <= 128):
        raise ValueError(
            "The number of participants must satisfy "
            "1 <= n <= 128."
        )

    if not (0 <= participant_id < n):
        raise ValueError(
            "The participant identifier is out of range."
        )

    return Scalar(participant_id + 1)


#
# VSS commitment serialization
#


def serialize_vss_commitment(
    commitments: List[GE],
) -> VSSCommitment:
    if len(commitments) == 0:
        raise ValueError(
            "The VSS commitment must contain at least one element."
        )

    # The final threshold public key must be an ordinary
    # non-infinity point.
    if commitments[0].infinity:
        raise ValueError(
            "The constant-term commitment must not be infinity."
        )

    return VSSCommitment(
        b"".join(
            P.to_bytes_compressed_with_infinity()
            for P in commitments
        )
    )


def parse_vss_commitment(
    vss_commitment: bytes,
    t: int,
) -> List[GE]:
    """
    Parse exactly t extended compressed points.

    B_0 must be non-infinity.

    B_j for j > 0 may be infinity, representing a zero
    nonconstant polynomial coefficient.
    """
    if t < 1:
        raise ValueError(
            "The threshold must be positive."
        )

    if len(vss_commitment) != 33 * t:
        raise ValueError(
            "The VSS commitment must contain exactly t elements."
        )

    commitments: List[GE] = []

    for j in range(t):
        enc = vss_commitment[
            33 * j : 33 * (j + 1)
        ]

        try:
            P = GE.from_bytes_compressed_with_infinity(enc)
        except ValueError as e:
            raise ValueError(
                f"Invalid VSS commitment element at index {j}."
            ) from e

        if j == 0 and P.infinity:
            raise ValueError(
                "The constant-term commitment must not be infinity."
            )

        commitments.append(P)

    return commitments


#
# Mandatory Taproot-safety transformation
#


def taproot_safety_tweak(
    initial_thresh_point: GE,
) -> Scalar:
    """
    Compute the BIP341-style TapTweak used by the mandatory
    key-generation Taproot-safety transformation.

    This uses the 32-byte x-only serialization of the initial
    threshold point.

        tweak = int(hash_TapTweak(xbytes(P)))

    and fails if the hash represents an integer >= q.

    This is the key-generation transformation used here. It must not
    be confused with BIP 445 ApplyTweak(..., is_xonly_t=True), whose
    signing-time semantics additionally perform even-Y normalization.
    """
    if initial_thresh_point.infinity:
        raise TaprootSafetyError(
            "The initial threshold public point is infinity."
        )

    tweak_bytes = tagged_hash(
        "TapTweak",
        initial_thresh_point.to_bytes_xonly(),
    )

    try:
        # This implements BIP341's t < q check.
        #
        # Zero itself is permitted.
        return Scalar.from_bytes_checked(tweak_bytes)
    except ValueError as e:
        raise TaprootSafetyError(
            "The BIP341 TapTweak is greater than or equal "
            "to the group order."
        ) from e


def apply_taproot_safety(
    coeffs: List[Scalar],
    commitments: List[GE],
) -> TaprootSafetyResult:
    """
    Transform the initial sharing

        f(x) = a_0 + a_1*x + ...

    into the final BIP-445-compatible sharing

        f_final(x) = f(x) + tweak.

    Therefore:

        b_0 = a_0 + tweak
        b_j = a_j                    for j > 0

        B_0 = A_0 + tweak*G
        B_j = A_j                    for j > 0

    and every final participant share is shifted by exactly the same
    tweak.
    """
    if len(coeffs) == 0:
        raise ValueError(
            "Coefficient list must not be empty."
        )

    if len(coeffs) != len(commitments):
        raise ValueError(
            "Coefficient and commitment lists must have equal length."
        )

    if coeffs[0] == Scalar(0):
        raise ValueError(
            "The initial constant coefficient must be nonzero."
        )

    if commitments[0].infinity:
        raise ValueError(
            "The initial constant-term commitment must not be infinity."
        )

    # Internal consistency check.
    for j, (coeff, commitment) in enumerate(
        zip(coeffs, commitments)
    ):
        if commitment != coeff * G:
            raise RuntimeError(
                f"Commitment at index {j} does not match "
                "its coefficient."
            )

    tweak = taproot_safety_tweak(commitments[0])

    final_coeffs = list(coeffs)
    final_coeffs[0] = final_coeffs[0] + tweak

    if final_coeffs[0] == Scalar(0):
        raise TaprootSafetyError(
            "The Taproot-safety transformation produced "
            "a zero threshold secret."
        )

    final_commitments = list(commitments)
    final_commitments[0] = (
        final_commitments[0] + tweak * G
    )

    if final_commitments[0].infinity:
        raise TaprootSafetyError(
            "The Taproot-safety transformation produced infinity."
        )

    if final_commitments[0] != final_coeffs[0] * G:
        raise RuntimeError(
            "Taproot-safety transformation self-check failed."
        )

    return TaprootSafetyResult(
        final_coeffs,
        final_commitments,
        tweak,
    )


#
# Public-key derivation
#


def derive_pubshare_from_commitment(
    participant_id: int,
    n: int,
    t: int,
    vss_commitment: bytes,
) -> PlainPk:
    validate_params(t, n)

    x = participant_evaluation_point(
        participant_id,
        n,
    )

    commitments = parse_vss_commitment(
        vss_commitment,
        t,
    )

    P = polynomial_evaluate_point(
        commitments,
        x,
    )

    if P.infinity:
        raise ValueError(
            "The derived participant public share is infinity."
        )

    return PlainPk(P.to_bytes_compressed())


def thresh_pubkey_from_commitment(
    t: int,
    vss_commitment: bytes,
) -> PlainPk:
    """
    Derive thresh_pk from the authoritative final VSS commitment.
    """
    commitments = parse_vss_commitment(
        vss_commitment,
        t,
    )

    return PlainPk(
        commitments[0].to_bytes_compressed()
    )


#
# Secret-share verification
#


def verify_secshare(
    participant_id: int,
    n: int,
    t: int,
    secshare: bytes,
    vss_commitment: bytes,
) -> bool:
    """
    Verify a final participant secret share against the final VSS
    commitment.

        secshare * G
            ==
        B_0 + x*B_1 + ... + x^(t-1)*B_(t-1)

    where x = participant_id + 1.
    """
    if len(secshare) != 32:
        return False

    try:
        validate_params(t, n)

        x = participant_evaluation_point(
            participant_id,
            n,
        )

        # BIP 445 requires a canonical nonzero final secret share.
        d = Scalar.from_bytes_nonzero_checked(secshare)

        commitments = parse_vss_commitment(
            vss_commitment,
            t,
        )
    except ValueError:
        return False

    expected = polynomial_evaluate_point(
        commitments,
        x,
    )

    actual = d * G

    # Compare points directly.
    #
    # Since d is nonzero, actual cannot be infinity. Therefore an
    # infinity expected point automatically fails this comparison.
    return actual == expected


#
# Randomized dealer key generation
#


def trusted_dealer_keygen(
    t: int,
    n: int,
    seckey: Optional[bytes] = None,
) -> DealerOutput:
    """
    Generate trusted-dealer FROST key material.

    If seckey is supplied, it is interpreted as the INITIAL constant
    coefficient a_0.

    The mandatory Taproot-safety transformation changes the final
    threshold secret to:

        b_0 = a_0 + tweak

    so the final thresh_pk generally differs from seckey*G.

    For an imported secret, this function can validate scalar encoding
    but cannot determine whether the caller supplied a secret with
    sufficient entropy.

    Only a zero final participant share permits retrying with fresh
    nonconstant coefficients and the same initial secret. A Taproot
    safety failure aborts the operation, including for generated secrets.
    """
    validate_params(t, n)

    imported = seckey is not None

    if imported:
        assert seckey is not None

        if len(seckey) != 32:
            raise ValueError(
                "The seckey argument must have length 32."
            )

        try:
            a_0 = Scalar.from_bytes_nonzero_checked(
                seckey
            )
        except ValueError as e:
            raise ValueError(
                "The seckey argument must decode to a "
                "canonical nonzero scalar."
            ) from e
    else:
        a_0 = random_nonzero_scalar()

    while True:
        # RFC9591 permits zero nonconstant coefficients.
        coeffs = [a_0] + [
            random_scalar()
            for _ in range(t - 1)
        ]

        try:
            return trusted_dealer_keygen_internal(
                coeffs,
                n,
            )

        except ZeroFinalShareError:
            # A zero INITIAL share is not itself a problem.
            #
            # Only a zero FINAL share, after the mandatory
            # Taproot-safety transformation, is invalid.
            #
            # Changing the nonconstant coefficients preserves a_0.
            if t == 1:
                # apply_taproot_safety() already guarantees b_0 != 0,
                # so this should be unreachable.
                raise RuntimeError(
                    "Unexpected zero final share in a 1-of-n setup."
                )

            continue


#
# Deterministic key generation
#
# This function is also the basis for deterministic test vectors.
#


def trusted_dealer_keygen_internal(
    coeffs: List[Scalar],
    n: int,
) -> DealerOutput:
    """
    Deterministically construct final key-generation material from
    explicit initial polynomial coefficients.

    This function MUST NOT sample randomness.
    """
    t = len(coeffs)

    validate_params(t, n)

    if coeffs[0] == Scalar(0):
        raise ValueError(
            "The initial constant term a_0 must be nonzero."
        )

    #
    # Initial Feldman commitment
    #
    # A_j = a_j * G
    #
    # Nonconstant A_j values may be infinity when a_j == 0.
    #
    initial_commitments = [
        coeff * G
        for coeff in coeffs
    ]

    if initial_commitments[0].infinity:
        raise RuntimeError(
            "Nonzero a_0 unexpectedly committed to infinity."
        )

    #
    # Mandatory BIP-445 Taproot-safety transformation
    #
    safety = apply_taproot_safety(
        coeffs,
        initial_commitments,
    )

    final_coeffs = safety.final_coeffs
    final_commitments = safety.final_commitments

    #
    # The final VSS commitment is authoritative.
    #
    vss_commitment = serialize_vss_commitment(
        final_commitments
    )

    thresh_pk = PlainPk(
        final_commitments[0].to_bytes_compressed()
    )

    if (
        thresh_pubkey_from_commitment(
            t,
            vss_commitment,
        )
        != thresh_pk
    ):
        raise RuntimeError(
            "Threshold-public-key self-check failed."
        )

    secshares: List[bytes] = []
    pubshares: List[PlainPk] = []

    for participant_id in range(n):
        x = participant_evaluation_point(
            participant_id,
            n,
        )

        #
        # IMPORTANT:
        #
        # Evaluate the FINAL polynomial, not the initial one.
        #
        d = polynomial_evaluate(
            final_coeffs,
            x,
        )

        if d == Scalar(0):
            raise ZeroFinalShareError(
                "Final secret share for participant "
                f"{participant_id} is zero."
            )

        P = d * G

        if P.infinity:
            raise RuntimeError(
                "A nonzero final secret share produced infinity."
            )

        #
        # Mandatory dealer Feldman self-check.
        #
        expected = polynomial_evaluate_point(
            final_commitments,
            x,
        )

        if P != expected:
            raise RuntimeError(
                "Dealer Feldman self-check failed."
            )

        secshare = d.to_bytes()
        pubshare = PlainPk(
            P.to_bytes_compressed()
        )

        #
        # Cross-check using the externally exposed derivation and
        # verification algorithms.
        #
        if (
            derive_pubshare_from_commitment(
                participant_id,
                n,
                t,
                vss_commitment,
            )
            != pubshare
        ):
            raise RuntimeError(
                "Dealer public-share self-check failed."
            )

        if not verify_secshare(
            participant_id,
            n,
            t,
            secshare,
            vss_commitment,
        ):
            raise RuntimeError(
                "Dealer secret-share self-check failed."
            )

        secshares.append(secshare)
        pubshares.append(pubshare)

    return DealerOutput(
        vss_commitment,
        thresh_pk,
        pubshares,
        secshares,
    )


#
# Participant acceptance
#


def participant_key_accept(
    participant_id: int,
    n: int,
    t: int,
    secshare: bytes,
    vss_commitment: bytes,
    thresh_pk: Optional[bytes] = None,
    pubshares: Optional[List[bytes]] = None,
) -> ParticipantAcceptedKeyMaterial:
    """
    Validate participant key material before it is used by BIP 445.

    Transport authentication, confidentiality, ceremony binding, and
    the requirement that all participants have the same view of the
    VSS commitment are application/protocol responsibilities and
    cannot be established by this local function alone.
    """
    validate_params(t, n)

    # This validates:
    #
    # - exact length 33*t
    # - all extended point encodings
    # - B_0 is non-infinity
    #
    parse_vss_commitment(
        vss_commitment,
        t,
    )

    if not verify_secshare(
        participant_id,
        n,
        t,
        secshare,
        vss_commitment,
    ):
        raise ValueError(
            "The participant secret share failed VSS verification."
        )

    derived_thresh_pk = (
        thresh_pubkey_from_commitment(
            t,
            vss_commitment,
        )
    )

    derived_pubshare = (
        derive_pubshare_from_commitment(
            participant_id,
            n,
            t,
            vss_commitment,
        )
    )

    #
    # A separately supplied thresh_pk is redundant.
    # The final VSS commitment remains authoritative.
    #
    if thresh_pk is not None:
        try:
            supplied_thresh_point = (
                GE.from_bytes_compressed(
                    thresh_pk
                )
            )
        except ValueError as e:
            raise ValueError(
                "The supplied threshold public key is invalid."
            ) from e

        if (
            supplied_thresh_point.to_bytes_compressed()
            != derived_thresh_pk
        ):
            raise ValueError(
                "The supplied threshold public key does not "
                "match the VSS commitment."
            )

    #
    # If a complete public-share list is supplied, verify every entry
    # against the final VSS commitment.
    #
    if pubshares is not None:
        if len(pubshares) != n:
            raise ValueError(
                "The supplied public-share list must "
                "contain n elements."
            )

        for j, supplied in enumerate(pubshares):
            try:
                supplied_point = (
                    GE.from_bytes_compressed(
                        supplied
                    )
                )
            except ValueError as e:
                raise ValueError(
                    f"The supplied public share at index {j} "
                    "is invalid."
                ) from e

            derived = (
                derive_pubshare_from_commitment(
                    j,
                    n,
                    t,
                    vss_commitment,
                )
            )

            if (
                supplied_point.to_bytes_compressed()
                != derived
            ):
                raise ValueError(
                    f"The supplied public share at index {j} "
                    "does not match the VSS commitment."
                )

    return ParticipantAcceptedKeyMaterial(
        participant_id=participant_id,
        secshare=secshare,
        thresh_pk=derived_thresh_pk,
        pubshare=derived_pubshare,
        vss_commitment=VSSCommitment(
            vss_commitment
        ),
    )
