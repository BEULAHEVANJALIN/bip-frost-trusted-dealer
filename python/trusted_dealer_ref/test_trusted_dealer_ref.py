# test_trusted_dealer_ref.py

from itertools import combinations
from unittest.mock import Mock

import pytest

from trusted_dealer_ref import trusted_dealer_ref as td
print("IMPORT:", td.__file__)
print("FUNCTIONS:", [
    name for name in dir(td)
    if name in (
        "validate_params",
        "participant_evaluation_point",
        "taproot_safety_tweak",
        "apply_taproot_safety",
        "serialize_vss_commitment",
        "participant_key_accept",
    )
])
from secp256k1lab.secp256k1 import G, GE, Scalar


SECP256K1_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
    "BAAEDCE6AF48A03BBFD25E8CD0364141",
    16,
)


def s(x: int) -> Scalar:
    return Scalar(x)


def parse_pubkey(pubkey: bytes) -> GE:
    return GE.from_bytes_compressed(pubkey)


def parse_share(secshare: bytes) -> Scalar:
    return Scalar.from_bytes_nonzero_checked(secshare)


def reconstruct_threshold_point(
    participant_ids,
    pubshares,
):
    """
    Interpolate public shares at x = 0.

    BIP 445 participant identifier id corresponds to:

        x = id + 1

    The Lagrange coefficient is

               x_j
        λ_i = Π ------
              x_j-x_i
             j != i
    """
    result = GE()

    for participant_id in participant_ids:
        x_i = Scalar(participant_id + 1)
        numerator = Scalar(1)
        denominator = Scalar(1)

        for other_id in participant_ids:
            if other_id == participant_id:
                continue

            x_j = Scalar(other_id + 1)

            numerator = numerator * x_j
            denominator = denominator * (x_j - x_i)

        # secp256k1lab Scalar implements scalar division.
        lambda_i = numerator / denominator

        P_i = parse_pubkey(pubshares[participant_id])

        result = result + lambda_i * P_i

    return result


#
# Parameter validation
#


@pytest.mark.parametrize(
    "t,n",
    [
        (0, 1),
        (2, 1),
        (1, 0),
        (1, 129),
        (129, 129),
        (1, 2**32),
        (2, 2**32),
    ],
)
def test_invalid_parameters(t, n):
    with pytest.raises(ValueError):
        td.validate_params(t, n)


def test_single_participant_is_valid():
    # BIP 445 permits n = 1.
    td.validate_params(1, 1)


def test_maximum_participant_count():
    td.validate_params(128, 128)
    output = td.trusted_dealer_keygen_internal([s(1), s(2)], 128)
    assert len(output.secshares) == len(output.pubshares) == 128
    assert td.participant_evaluation_point(127, 128) == s(128)
    accepted = td.participant_key_accept(
        127, 128, 2, output.secshares[127], output.vss_commitment,
        output.thresh_pk, output.pubshares,
    )
    assert accepted.pubshare == output.pubshares[127]
    with pytest.raises(ValueError):
        td.participant_evaluation_point(128, 128)


@pytest.mark.parametrize("n", [0, 129, 2**32])
def test_participant_limit_at_public_entry_points(n, monkeypatch):
    # Valid cryptographic inputs must not bypass parameter validation.
    output = td.trusted_dealer_keygen_internal([s(1)], 1)
    sampler = Mock(side_effect=AssertionError("Unexpected randomness"))
    monkeypatch.setattr(td, "random_nonzero_scalar", sampler)
    for seckey in (None, s(1).to_bytes()):
        with pytest.raises(ValueError):
            td.trusted_dealer_keygen(1, n, seckey)
    with pytest.raises(ValueError):
        td.trusted_dealer_keygen_internal([s(1)], n)
    with pytest.raises(ValueError):
        td.participant_evaluation_point(0, n)
    with pytest.raises(ValueError):
        td.derive_pubshare_from_commitment(0, n, 1, output.vss_commitment)
    assert not td.verify_secshare(
        0, n, 1, output.secshares[0], output.vss_commitment,
    )
    with pytest.raises(ValueError):
        td.participant_key_accept(
            0, n, 1, output.secshares[0], output.vss_commitment,
        )
    sampler.assert_not_called()


@pytest.mark.parametrize("imported", [False, True])
@pytest.mark.parametrize("failure", ["out_of_range_tweak", "zero_final_secret"])
def test_taproot_safety_failure_aborts(imported, failure, monkeypatch):
    a0 = s(17)
    sampler = Mock(side_effect=[a0])
    monkeypatch.setattr(td, "random_nonzero_scalar", sampler)
    tweak = SECP256K1_ORDER if failure == "out_of_range_tweak" else SECP256K1_ORDER - 17
    hasher = Mock(return_value=tweak.to_bytes(32, "big"))
    monkeypatch.setattr(td, "tagged_hash", hasher)
    with pytest.raises(td.TaprootSafetyError):
        td.trusted_dealer_keygen(1, 1, a0.to_bytes() if imported else None)
    assert sampler.call_count == (0 if imported else 1)
    hasher.assert_called_once()


@pytest.mark.parametrize("imported", [False, True])
def test_zero_final_share_retries_all_nonconstant_coefficients(imported, monkeypatch):
    a0 = s(17)
    final_constant = a0 + td.taproot_safety_tweak(a0 * G)
    # The first polynomial has final f(1) = 0; the second succeeds.
    bad_a2 = s(5)
    bad_a1 = s(0) - final_constant - bad_a2
    expected = td.trusted_dealer_keygen_internal([a0, s(1), s(2)], 3)
    initial_sampler = Mock(side_effect=[a0])
    coefficient_sampler = Mock(side_effect=[bad_a1, bad_a2, s(1), s(2)])
    monkeypatch.setattr(td, "random_nonzero_scalar", initial_sampler)
    monkeypatch.setattr(td, "random_scalar", coefficient_sampler)
    output = td.trusted_dealer_keygen(3, 3, a0.to_bytes() if imported else None)
    assert output == expected
    assert initial_sampler.call_count == (0 if imported else 1)
    assert coefficient_sampler.call_count == 4


#
# Polynomial evaluation
#


def test_polynomial_evaluate():
    # f(x) = 3 + 4x + 5x^2
    coeffs = [
        s(3),
        s(4),
        s(5),
    ]

    # f(2) = 3 + 8 + 20 = 31
    assert td.polynomial_evaluate(
        coeffs,
        s(2),
    ) == s(31)


def test_polynomial_evaluate_point_matches_scalar_evaluation():
    coeffs = [
        s(3),
        s(4),
        s(5),
    ]

    commitments = [
        coeff * G
        for coeff in coeffs
    ]

    x = s(7)

    scalar_result = td.polynomial_evaluate(
        coeffs,
        x,
    )

    point_result = td.polynomial_evaluate_point(
        commitments,
        x,
    )

    assert point_result == scalar_result * G


#
# Participant identifier mapping
#


def test_participant_evaluation_points_are_id_plus_one():
    n = 3

    assert td.participant_evaluation_point(0, n) == s(1)
    assert td.participant_evaluation_point(1, n) == s(2)
    assert td.participant_evaluation_point(2, n) == s(3)


@pytest.mark.parametrize(
    "participant_id",
    [-1, 3, 4],
)
def test_out_of_range_participant_identifier(participant_id):
    with pytest.raises(ValueError):
        td.participant_evaluation_point(
            participant_id,
            3,
        )


#
# 1-of-1
#


def test_one_of_one_keygen():
    output = td.trusted_dealer_keygen_internal(
        [s(1)],
        1,
    )

    assert len(output.vss_commitment) == 33
    assert len(output.secshares) == 1
    assert len(output.pubshares) == 1

    assert len(output.secshares[0]) == 32
    assert len(output.pubshares[0]) == 33
    assert len(output.thresh_pk) == 33

    assert td.verify_secshare(
        0,
        1,
        1,
        output.secshares[0],
        output.vss_commitment,
    )

    # With t = 1, the only public share equals the
    # threshold public key.
    assert output.pubshares[0] == output.thresh_pk


#
# Normal 2-of-3
#


def test_two_of_three_keygen():
    initial_coeffs = [
        s(1),
        s(2),
    ]

    output = td.trusted_dealer_keygen_internal(
        initial_coeffs,
        3,
    )

    assert len(output.vss_commitment) == 66
    assert len(output.secshares) == 3
    assert len(output.pubshares) == 3

    for participant_id in range(3):
        assert td.verify_secshare(
            participant_id,
            3,
            2,
            output.secshares[participant_id],
            output.vss_commitment,
        )

        assert (
            td.derive_pubshare_from_commitment(
                participant_id,
                3,
                2,
                output.vss_commitment,
            )
            == output.pubshares[participant_id]
        )

        assert (
            parse_share(output.secshares[participant_id]) * G
            == parse_pubkey(output.pubshares[participant_id])
        )

    assert (
        td.thresh_pubkey_from_commitment(
            2,
            output.vss_commitment,
        )
        == output.thresh_pk
    )


#
# Taproot-safety transformation
#


def test_taproot_safety_transformation():
    initial_coeffs = [
        s(7),
        s(11),
        s(13),
    ]

    initial_commitments = [
        coeff * G
        for coeff in initial_coeffs
    ]

    tweak = td.taproot_safety_tweak(
        initial_commitments[0]
    )

    transformed = td.apply_taproot_safety(
        initial_coeffs,
        initial_commitments,
    )

    final_coeffs = transformed.final_coeffs
    final_commitments = transformed.final_commitments

    assert transformed.tweak == tweak

    #
    # b_0 = a_0 + tweak
    #
    assert (
        final_coeffs[0]
        == initial_coeffs[0] + tweak
    )

    #
    # b_j = a_j for j > 0
    #
    assert final_coeffs[1:] == initial_coeffs[1:]

    #
    # B_0 = A_0 + tweak*G
    #
    assert (
        final_commitments[0]
        == initial_commitments[0] + tweak * G
    )

    #
    # B_j = A_j for j > 0
    #
    assert (
        final_commitments[1:]
        == initial_commitments[1:]
    )

    #
    # Every coefficient commitment remains consistent.
    #
    for coeff, commitment in zip(
        final_coeffs,
        final_commitments,
    ):
        assert commitment == coeff * G


def test_final_share_is_initial_share_plus_tweak():
    initial_coeffs = [
        s(5),
        s(9),
        s(12),
    ]

    initial_commitments = [
        coeff * G
        for coeff in initial_coeffs
    ]

    transformed = td.apply_taproot_safety(
        initial_coeffs,
        initial_commitments,
    )

    for participant_id in range(5):
        x = s(participant_id + 1)

        initial_share = td.polynomial_evaluate(
            initial_coeffs,
            x,
        )

        final_share = td.polynomial_evaluate(
            transformed.final_coeffs,
            x,
        )

        assert (
            final_share
            == initial_share + transformed.tweak
        )


def test_keygen_outputs_final_tweaked_commitment():
    initial_coeffs = [
        s(19),
        s(23),
    ]

    initial_A0 = initial_coeffs[0] * G

    tweak = td.taproot_safety_tweak(
        initial_A0
    )

    output = td.trusted_dealer_keygen_internal(
        initial_coeffs,
        3,
    )

    final_commitments = td.parse_vss_commitment(
        output.vss_commitment,
        2,
    )

    assert (
        final_commitments[0]
        == initial_A0 + tweak * G
    )

    assert (
        output.thresh_pk
        == final_commitments[0].to_bytes_compressed()
    )


#
# Zero nonconstant coefficient
#


def test_zero_nonconstant_coefficient_is_valid():
    initial_coeffs = [
        s(7),
        s(0),
    ]

    output = td.trusted_dealer_keygen_internal(
        initial_coeffs,
        3,
    )

    commitments = td.parse_vss_commitment(
        output.vss_commitment,
        2,
    )

    #
    # Taproot safety modifies only the constant term.
    # Therefore B_1 remains:
    #
    #     0 * G = infinity
    #
    assert commitments[1].infinity

    # Extended serialization of infinity is 33 zero bytes.
    assert output.vss_commitment[33:66] == bytes(33)

    for participant_id in range(3):
        assert td.verify_secshare(
            participant_id,
            3,
            2,
            output.secshares[participant_id],
            output.vss_commitment,
        )


#
# Zero FINAL share
#


def test_zero_final_share_is_rejected():
    """
    Deliberately choose a_1 so participant 0 obtains:

        f_final(1)
          = a_0 + tweak + a_1
          = 0.

    This tests that rejection happens after the
    Taproot-safety transformation.
    """
    a_0 = s(17)

    A_0 = a_0 * G

    tweak = td.taproot_safety_tweak(
        A_0
    )

    final_constant = a_0 + tweak

    # participant 0 has x = 1
    #
    # Choose:
    #
    #     a_1 = -(a_0 + tweak)
    #
    # so final f(1) = 0.
    a_1 = s(0) - final_constant

    with pytest.raises(td.ZeroFinalShareError):
        td.trusted_dealer_keygen_internal(
            [a_0, a_1],
            2,
        )


def test_zero_initial_share_is_not_automatically_rejected():
    """
    Choose a_1 = -a_0, so the INITIAL share for participant 0 is:

        a_0 + a_1 = 0.

    After Taproot safety:

        final_share = tweak.

    Thus the initial zero share is harmless provided the
    final share is nonzero.
    """
    a_0 = s(29)
    a_1 = s(0) - a_0

    initial_share = td.polynomial_evaluate(
        [a_0, a_1],
        s(1),
    )

    assert initial_share == s(0)

    output = td.trusted_dealer_keygen_internal(
        [a_0, a_1],
        2,
    )

    final_share = parse_share(
        output.secshares[0]
    )

    assert final_share != s(0)

    assert td.verify_secshare(
        0,
        2,
        2,
        output.secshares[0],
        output.vss_commitment,
    )


#
# Imported secret
#


def test_imported_secret_is_initial_constant_coefficient(
    monkeypatch,
):
    imported_secret = s(31).to_bytes()

    #
    # t = 2 needs one random nonconstant coefficient.
    #
    monkeypatch.setattr(
        td,
        "random_scalar",
        lambda: s(37),
    )

    imported_output = td.trusted_dealer_keygen(
        2,
        3,
        imported_secret,
    )

    deterministic_output = (
        td.trusted_dealer_keygen_internal(
            [s(31), s(37)],
            3,
        )
    )

    assert imported_output == deterministic_output


@pytest.mark.parametrize(
    "seckey",
    [
        b"",
        bytes(31),
        bytes(33),
        bytes(32),  # zero
        SECP256K1_ORDER.to_bytes(32, "big"),
        (SECP256K1_ORDER + 1).to_bytes(32, "big"),
    ],
)
def test_invalid_imported_secret(seckey):
    with pytest.raises(ValueError):
        td.trusted_dealer_keygen(
            2,
            3,
            seckey,
        )


#
# VSS parsing
#


@pytest.mark.parametrize(
    "length",
    [
        0,
        1,
        32,
        34,
        65,
        67,
    ],
)
def test_wrong_vss_length_is_rejected(length):
    with pytest.raises(ValueError):
        td.parse_vss_commitment(
            bytes(length),
            2,
        )


def test_malformed_vss_point_is_rejected():
    # 0x04 denotes an uncompressed SEC encoding and is invalid
    # in this 33-byte compressed-point format.
    malformed_point = (
        b"\x04"
        + bytes(32)
    )

    valid_constant = G.to_bytes_compressed()

    malformed_vss = (
        valid_constant
        + malformed_point
    )

    with pytest.raises(ValueError):
        td.parse_vss_commitment(
            malformed_vss,
            2,
        )


def test_infinity_constant_commitment_is_rejected():
    vss = (
        bytes(33)
        + G.to_bytes_compressed()
    )

    with pytest.raises(ValueError):
        td.parse_vss_commitment(
            vss,
            2,
        )


def test_infinity_nonconstant_commitment_is_accepted():
    vss = (
        G.to_bytes_compressed()
        + bytes(33)
    )

    commitments = td.parse_vss_commitment(
        vss,
        2,
    )

    assert not commitments[0].infinity
    assert commitments[1].infinity


#
# Tampered secret share
#


def test_tampered_secret_share_fails_verification():
    output = td.trusted_dealer_keygen_internal(
        [
            s(41),
            s(43),
        ],
        3,
    )

    original = parse_share(
        output.secshares[0]
    )

    tampered = (
        original + s(1)
    ).to_bytes()

    assert not td.verify_secshare(
        0,
        3,
        2,
        tampered,
        output.vss_commitment,
    )


#
# Tampered VSS
#


def test_tampered_vss_fails_share_verification():
    output = td.trusted_dealer_keygen_internal(
        [
            s(47),
            s(53),
        ],
        3,
    )

    commitments = td.parse_vss_commitment(
        output.vss_commitment,
        2,
    )

    #
    # Change B_1 by G while preserving a valid VSS encoding.
    #
    commitments[1] = commitments[1] + G

    tampered_vss = td.serialize_vss_commitment(
        commitments
    )

    assert not td.verify_secshare(
        0,
        3,
        2,
        output.secshares[0],
        tampered_vss,
    )


#
# Public-share consistency
#


def test_every_pubshare_has_three_equivalent_derivations():
    initial_coeffs = [
        s(59),
        s(61),
        s(67),
    ]

    n = 5
    t = 3

    output = td.trusted_dealer_keygen_internal(
        initial_coeffs,
        n,
    )

    commitments = td.parse_vss_commitment(
        output.vss_commitment,
        t,
    )

    for participant_id in range(n):
        x = s(participant_id + 1)

        secshare = parse_share(
            output.secshares[participant_id]
        )

        from_secret = secshare * G

        from_vss = td.polynomial_evaluate_point(
            commitments,
            x,
        )

        from_output = parse_pubkey(
            output.pubshares[participant_id]
        )

        assert from_secret == from_vss
        assert from_vss == from_output


#
# Threshold reconstruction
#


def test_every_two_of_three_subset_reconstructs_threshold_key():
    output = td.trusted_dealer_keygen_internal(
        [
            s(71),
            s(73),
        ],
        3,
    )

    expected = parse_pubkey(
        output.thresh_pk
    )

    for subset in combinations(
        range(3),
        2,
    ):
        reconstructed = reconstruct_threshold_point(
            subset,
            output.pubshares,
        )

        assert reconstructed == expected


def test_three_of_three_reconstructs_threshold_key():
    output = td.trusted_dealer_keygen_internal(
        [
            s(79),
            s(83),
            s(89),
        ],
        3,
    )

    reconstructed = reconstruct_threshold_point(
        [0, 1, 2],
        output.pubshares,
    )

    assert reconstructed == parse_pubkey(
        output.thresh_pk
    )


#
# Participant acceptance
#


def test_participant_accepts_valid_material():
    output = td.trusted_dealer_keygen_internal(
        [
            s(97),
            s(101),
        ],
        3,
    )

    accepted = td.participant_key_accept(
        participant_id=1,
        n=3,
        t=2,
        secshare=output.secshares[1],
        vss_commitment=output.vss_commitment,
        thresh_pk=output.thresh_pk,
        pubshares=output.pubshares,
    )

    assert accepted.participant_id == 1
    assert accepted.secshare == output.secshares[1]
    assert accepted.pubshare == output.pubshares[1]
    assert accepted.thresh_pk == output.thresh_pk


def test_participant_rejects_wrong_threshold_pubkey():
    output1 = td.trusted_dealer_keygen_internal(
        [
            s(103),
            s(107),
        ],
        3,
    )

    output2 = td.trusted_dealer_keygen_internal(
        [
            s(109),
            s(113),
        ],
        3,
    )

    with pytest.raises(ValueError):
        td.participant_key_accept(
            participant_id=0,
            n=3,
            t=2,
            secshare=output1.secshares[0],
            vss_commitment=output1.vss_commitment,
            thresh_pk=output2.thresh_pk,
        )


def test_participant_rejects_wrong_pubshare_list():
    output1 = td.trusted_dealer_keygen_internal(
        [
            s(127),
            s(131),
        ],
        3,
    )

    output2 = td.trusted_dealer_keygen_internal(
        [
            s(137),
            s(139),
        ],
        3,
    )

    bad_pubshares = list(
        output1.pubshares
    )

    bad_pubshares[2] = output2.pubshares[2]

    with pytest.raises(ValueError):
        td.participant_key_accept(
            participant_id=0,
            n=3,
            t=2,
            secshare=output1.secshares[0],
            vss_commitment=output1.vss_commitment,
            pubshares=bad_pubshares,
        )
