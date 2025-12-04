import secrets
from vendor.secp256k1lab.src.secp256k1lab.secp256k1 import G, GE, Scalar
from vendor.secp256k1lab.src.secp256k1lab.util import tagged_hash

def _random_scalar_nonzero() -> Scalar:
    """
    Sample a uniformly random *nonzero* scalar modulo n.

    The value 0 is rejected and re-sampled; the probability of requiring
    more than one iteration is negligible (~2^-256).

    Returns:
        A Scalar in {1, ..., n-1}.
    """
    while True:
        s = Scalar.from_int_wrapping(secrets.randbits(256))
        if s != 0:
            return s

def _random_scalar() -> Scalar:
    """
    Sample a uniformly random scalar modulo n (zero allowed).

    Used for polynomial coefficients that are pure masks / randomness and
    are not directly used as secret keys.

    Returns:
        A Scalar in {0, ..., n-1}.
    """
    return Scalar.from_int_wrapping(secrets.randbits(256))

def eval_point_poly(commitments: list[GE], x: Scalar) -> GE:
    """
    Evaluate an elliptic-curve polynomial at the point x.

    The polynomial is:
        E(X) = sum_j commitments[j] * X^j

    Args:
        commitments: List of curve points [A_0, A_1, ..., A_k], where
                     A_j encodes the coefficient of X^j.
        x:           Point at which to evaluate the polynomial (Scalar).

    Returns:
        The curve point E(x) as a GE.

    In the VSS context, commitments[j] = a_j * G, so E(x) should equal
    f(x) * G for the corresponding scalar polynomial f.
    """
    result = GE()               # Point at infinity (additive identity)
    power = Scalar(1)           # x^0;  Tracks x^j

    for A in commitments:
        result += int(power) * A
        power *= x              # Update x^(j+1) incrementally

    return result

def eval_scalar_poly(coeffs: list[Scalar], x: Scalar) -> Scalar:
    """
    Evaluate a scalar polynomial at the point x.

    The polynomial is:
        f(X) = sum_j coeffs[j] * X^j

    Args:
        coeffs: List of scalar coefficients [a_0, a_1, ..., a_k].
        x:      Point at which to evaluate the polynomial (Scalar).

    Returns:
        f(x) as a Scalar.
    """
    result = Scalar(0)
    power = Scalar(1)           # x^0;  Tracks x^j

    for c in coeffs:
        result += c * power
        power *= x              # Update x^(j+1) incrementally

    return result

def _taproot_tweak_and_sign(P: GE) -> tuple[Scalar, int]:
    """
    Compute the Taproot tweak and sign bit for an x-only internal key.

    This follows BIP341 for an internal key with no script path:

        T = tagged_hash("TapTweak", P_xonly || merkle_root)
        where merkle_root = 0^32 for the "no scripts" case.

    The sign g is defined as:
        g = +1 if P has even Y
        g = -1 otherwise

    Args:
        P: Internal key point A_0 = a_0 * G (not infinity).

    Returns:
        (tweak, g) where:
          * tweak is the Scalar derived from TapTweak.
          * g is +1 or -1 (int) indicating the parity adjustment used
            in BIP340/BIP341 (x-only pubkeys).
    """
    tweak_bytes = tagged_hash("TapTweak", P.to_bytes_xonly() + bytes(32))
    tweak = Scalar.from_bytes_wrapping(tweak_bytes)
    g = 1 if P.has_even_y() else -1

    return tweak, g

def modinv_scalar(x: Scalar) -> Scalar:
    """
    Compute the multiplicative inverse of x modulo n, as a Scalar.

    Args:
        x: Nonzero Scalar.

    Returns:
        Scalar y such that x * y == 1 (mod n).

    Raises:
        ValueError: If x == 0.
    """
    if x == 0:
        raise ValueError("Cannot invert zero scalar")

    return Scalar(pow(int(x), -1, Scalar.SIZE))

def trusted_dealer_key_generation(t: int, n: int):
    """
    Trusted-dealer t-of-n key generation.

    Constructs a random degree-(t-1) polynomial:

        f(X) = a_0 + a_1 X + ... + a_{t-1} X^{t-1}

    over the secp256k1 scalar field, with:

        * a_0 chosen uniformly at random from {1, ..., n-1} (nonzero).
        * a_1, ..., a_{t-1} chosen uniformly from {0, ..., n-1}.

    Feldman VSS commitments are:
        A_j = a_j * G

    For participant i (1 <= i <= n), the untweaked secret share is:
        f(i)

    The Taproot tweak (BIP341, zero Merkle root) is derived from A_0.
    The final tweaked secret share for participant i is:

        d_i = g * f(i) + tweak

    and the corresponding tweaked public share:

        P_i_Q = d_i * G = g * E(i) + tweak * G

    where:
        E(i) = sum_j A_j * i^j.

    Args:
        t: Threshold (1 <= t <= n).
        n: Total number of participants (n >= 1).

    Returns:
        (vss_commitment, secret_shares, public_shares, Q) where:
          * vss_commitment: [A_0, ..., A_{t-1}] Feldman commitments.
          * secret_shares:  List [d_1, ..., d_n] of tweaked secret shares.
          * public_shares:  List [P_1_Q, ..., P_n_Q] of tweaked pub shares.

    Raises:
        ValueError: For invalid parameters or extremely unlikely edge cases
                    (e.g. zero secret share or Q at infinity).

    WARNING:
        This function assumes a *trusted dealer* who learns the entire
        polynomial and hence the final group secret. It MUST NOT be used
        as a replacement for a distributed key generation (DKG) protocol.
    """
    if n < 1:
        raise ValueError("n must be >= 1")
    if not (1 <= t <= n):
        raise ValueError("t must satisfy 1 <= t <= n")
    
    # Sample coefficients for a degree-(t-1) polynomial
    # a_0 is the secret scalar and must be nonzero; the remaining coefficients
    # are random and may be zero.
    coeffs: list[Scalar] = [_random_scalar_nonzero()]
    for _ in range(1, t):
        coeffs.append(_random_scalar())

    # Feldman-style VSS commitments: A_i = a_i * G
    vss_commitment: list[GE] = [a * G for a in coeffs]

    # Commitment to the secret a_0.
    P = vss_commitment[0]           # A_0 = a_0 * G

    # a_0 != 0 should guarantee A_0 != infinity, but we assert to catch
    # bugs or malformed scalar behavior early.
    if P.infinity:
        raise ValueError("Invalid polynomial: A_0 is infinity")
    
    # Taproot tweak and sign g (BIP340/BIP341, zero Merkle root).
    tweak, g = _taproot_tweak_and_sign(P)

    # Tweaked group key:
    #       Q = g * P + tweak * G
    Q = g * P + tweak * G
    if Q.infinity:
        # Extremely unlikely unless tweak == -g * a_0 mod n
        raise ValueError("Tweaked group public key is infinity")
    
    secret_shares: list[Scalar] = []
    public_shares: list[GE] = []

    for i in range(1, n + 1):
        idx = Scalar(i)

        # Public commitments
        #       E(i) = sum_j A_j * i^j
        # If the commitments are consistent, E(idx) = f(idx) * G.
        E = eval_point_poly(vss_commitment, idx)

        # Scalar evaluation of the underlying polynomial share
        #       f(i) = sum_j a_j * i^j
        f_id = eval_scalar_poly(coeffs, idx)

        # Tweaked secret share and corresponding public share
        #       d_i = g * f(idx) + tweak   (mod n)
        d_i = g * f_id + tweak          # secret share
        if d_i == 0:
            # Extremely rare edge case (would imply a zero private key share).
            # safest behavior is to abort and rerun key generation.
            raise ValueError(f"Secret share for id={i} is 0; aborting.")

        # Public tweaked share:
        #       P_i_Q = g * E(idx) + tweak * G
        # which should equal d_i * G if everything is consistent.
        P_i_Q = g * E + tweak * G

        assert P_i_Q == d_i * G

        secret_shares.append(d_i)
        public_shares.append(P_i_Q)

    return vss_commitment, secret_shares, public_shares

def verify_share(participant_id: int, sec_share: Scalar, vss_commitment: list[GE]) -> bool:
    """
    Verify that a tweaked secret share is consistent with the VSS commitments.

    This recomputes the expected tweaked public share from the Feldman
    commitments and the Taproot tweak derived from A_0, and checks:

        sec_share * G == g * E(participant_id) + tweak * G

    where:
        E(x) = sum_j A_j * x^j

    Args:
        participant_id: 1-based identifier of the participant (must be > 0).
        sec_share: Tweaked secret share d_i.
        vss_commitment: Commitments [A_0, ..., A_{t-1}] to the polynomial.

    Returns:
        True if the share is valid; False otherwise.
    """
    if sec_share == 0:
        return False
    if participant_id <= 0:
        return False
    if not vss_commitment:
        return False

    P = vss_commitment[0]
    if P.infinity:
        return False

    tweak, g = _taproot_tweak_and_sign(P)

    idx = Scalar(participant_id)

    # E(idx) = A_0 + idx*A_1 + ... + idx^{t-1} * A_{t-1}
    E = eval_point_poly(vss_commitment, idx)

    # Expected public tweaked share:
    #       expected_pub = g * E(idx) + tweak * G
    expected_pub = g * E + tweak * G

    # Valid if sec_share * G matches the expected tweaked share.
    return expected_pub == sec_share * G

def group_pubkey_from_commitment(vss_commitment: list[GE]) -> GE:
    """
    Derive the tweaked group public key Q directly from VSS commitments.

    Uses only the Feldman commitments and the Taproot tweak derived from
    A_0 (no shares required):

        P = A_0 = a_0 * G
        (tweak, g) = TapTweak(P_xonly || 0^32)

        Q = g * P + tweak * G

    Args:
        vss_commitment: Feldman commitments [A_0, ..., A_{t-1}].

    Returns:
        The tweaked group public key Q as a GE.

    Raises:
        ValueError: If commitments are empty, A_0 is infinity, or Q is
                    infinity (extremely unlikely).
    """
    if not vss_commitment:
        raise ValueError("Empty commitments")

    P = vss_commitment[0]  # A_0 = a_0 * G
    if P.infinity:
        raise ValueError("Invalid commitment: A_0 is infinity")

    tweak, g = _taproot_tweak_and_sign(P)

    Q = g * P + tweak * G
    if Q.infinity:
        # Extremely unlikely unless tweak == -g * a_0 mod n
        raise ValueError("Tweaked group public key is infinity")

    return Q

def lagrange_at_zero(ids: list[int], target_id: int) -> Scalar:
    """
    Compute the Lagrange coefficient λ_target_id(0) for interpolation at X = 0.

    Given distinct participant IDs ids = [i_1, ..., i_u] and a target_id ∈ ids,
    this returns:

        λ_target_id(0) = ∏_{j ∈ ids, j ≠ target_id} j / (j - target_id)  (mod n)

    This is the Lagrange basis coefficient for reconstructing f(0)
    from the values f(i_j):

        f(0) = sum_{j} λ_j(0) * f(i_j)  (mod n)

    Args:
        ids:        List of distinct positive integer participant IDs.
        target_id:  One of the IDs in ids.

    Returns:
        The Lagrange basis coefficient at X = 0 as a Scalar.
    
    Raises:
        ValueError: If target_id is not in ids or ids contains duplicates.
    """
    if target_id not in ids:
        raise ValueError("target_id must be in ids")
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate ids not allowed")

    num = Scalar(1)
    denom = Scalar(1)
    x = Scalar(target_id)

    for j in ids:
        if j == target_id:
            continue
        j_s = Scalar(j)
        num *= j_s
        denom *= (j_s - x)

    denom_inv = modinv_scalar(denom)
    return num * denom_inv

def group_pub_from_tweaked_pubshares(ids: list[int], pubshares: list[GE]) -> GE:
    """
    Reconstruct the tweaked group public key Q from tweaked public shares.

    Each pubshare is:
        P_i = d_i * G
    where:
        d_i = g * f(i) + tweak

    for the same polynomial f and Taproot tweak used in key generation.

    Using Lagrange interpolation at X = 0, we compute:
        Q = sum_i λ_i * P_i
          = (sum_i λ_i * d_i) * G
          = d * G
    where d is the effective tweaked group secret.

    Args:
        ids:       List of distinct participant IDs (e.g. a subset of
                   [1, 2, ..., n]) with size >= 1.
        pubshares: Corresponding tweaked public shares P_i = d_i * G.

    Returns:
        The reconstructed tweaked group public key Q.

    Raises:
        ValueError: If input lengths mismatch, no shares are provided,
                    ids contain duplicates, or interpolation yields
                    the point at infinity (should not happen for valid
                    inputs and thresholds).
    """
    if len(ids) != len(pubshares):
        raise ValueError("ids and pubshares length mismatch")
    if len(ids) == 0:
        raise ValueError("need at least one share")
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate ids not allowed")

    Q = GE()        # Accumulator starting at infinity

    for id_i, P_i in zip(ids, pubshares):
        lam_i = lagrange_at_zero(ids, id_i)
        Q += int(lam_i) * P_i

    if Q.infinity:
        # This indicates an inconsistency in the input shares or a bug
        # in the interpolation routines.
        raise ValueError("Interpolation yielded infinity")

    return Q