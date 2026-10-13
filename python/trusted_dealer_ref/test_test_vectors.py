# python/trusted_dealer_ref/test_test_vectors.py

from __future__ import annotations

import json
import os
import subprocess
import sys
from itertools import combinations
from pathlib import Path

import pytest

from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.util import tagged_hash

from trusted_dealer_ref import trusted_dealer_ref as td


REPO_ROOT = Path(__file__).resolve().parents[2]

TEST_VECTOR_PATH = (
    REPO_ROOT
    / "bip-frost-trusted-dealer-test-vectors.json"
)


def load_vectors() -> dict:
    with TEST_VECTOR_PATH.open(
        "r",
        encoding="utf-8",
    ) as f:
        return json.load(f)


def scalar_from_hex(value: str) -> Scalar:
    """
    Parse a canonical scalar.

    Zero is permitted here because polynomial coefficients other than
    the final participant secret shares may legitimately be zero.
    """
    raw = bytes.fromhex(value)

    assert len(raw) == 32

    return Scalar.from_bytes_checked(raw)


def nonzero_scalar_from_hex(value: str) -> Scalar:
    raw = bytes.fromhex(value)

    assert len(raw) == 32

    return Scalar.from_bytes_nonzero_checked(raw)


def point_from_compressed_hex(value: str) -> GE:
    raw = bytes.fromhex(value)

    assert len(raw) == 33

    return GE.from_bytes_compressed(raw)


def point_from_extended_hex(value: str) -> GE:
    raw = bytes.fromhex(value)

    assert len(raw) == 33

    return GE.from_bytes_compressed_with_infinity(raw)


def lagrange_coefficient_at_zero(
    participant_id: int,
    participant_ids,
) -> Scalar:
    """
    Compute the Lagrange coefficient for participant_id at x = 0.

    BIP 445 identifiers are zero-based, but Shamir evaluation points
    are:

        x_i = participant_id + 1

    Therefore:

                x_j
        λ_i = Π ---------
               x_j - x_i
             j != i
    """
    x_i = Scalar(participant_id + 1)

    numerator = Scalar(1)
    denominator = Scalar(1)

    for other_id in participant_ids:
        if other_id == participant_id:
            continue

        x_j = Scalar(other_id + 1)

        numerator = numerator * x_j
        denominator = denominator * (x_j - x_i)

    return numerator / denominator


def reconstruct_threshold_point(
    participant_ids,
    pubshares,
) -> GE:
    result = GE()

    for participant_id in participant_ids:
        lambda_i = lagrange_coefficient_at_zero(
            participant_id,
            participant_ids,
        )

        P_i = point_from_compressed_hex(
            pubshares[participant_id]
        )

        result = result + lambda_i * P_i

    return result


def reconstruct_threshold_scalar(
    participant_ids,
    secshares,
) -> Scalar:
    result = Scalar(0)

    for participant_id in participant_ids:
        lambda_i = lagrange_coefficient_at_zero(
            participant_id,
            participant_ids,
        )

        d_i = nonzero_scalar_from_hex(
            secshares[participant_id]
        )

        result = result + lambda_i * d_i

    return result


#
# Test-vector file structure
#


def test_vector_file_exists():
    assert TEST_VECTOR_PATH.is_file()


def test_vector_file_has_expected_sections():
    vectors = load_vectors()

    assert isinstance(vectors["description"], str)
    assert isinstance(vectors["valid"], list)
    assert isinstance(vectors["invalid"], list)

    assert vectors["valid"]
    assert vectors["invalid"]


def test_vector_names_are_unique():
    vectors = load_vectors()

    names = [
        vector["name"]
        for vector in (
            vectors["valid"]
            + vectors["invalid"]
        )
    ]

    assert len(names) == len(set(names))


#
# Valid vectors
#


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_valid_vector_parameters(vector):
    n = vector["n"]
    t = vector["t"]

    td.validate_params(t, n)

    assert len(vector["initial_coefficients"]) == t
    assert len(vector["initial_commitments"]) == t
    assert len(vector["final_coefficients"]) == t
    assert len(vector["final_commitments"]) == t
    assert len(vector["participants"]) == n

    assert len(bytes.fromhex(vector["vss_commitment"])) == 33 * t
    assert len(bytes.fromhex(vector["thresh_pk"])) == 33


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_initial_commitments(vector):
    coeffs = [
        scalar_from_hex(value)
        for value in vector["initial_coefficients"]
    ]

    commitments = [
        point_from_extended_hex(value)
        for value in vector["initial_commitments"]
    ]

    assert len(coeffs) == len(commitments)

    for coeff, commitment in zip(
        coeffs,
        commitments,
    ):
        assert commitment == coeff * G

    # Initial a_0 must be nonzero.
    assert coeffs[0] != Scalar(0)

    # Consequently A_0 must not be infinity.
    assert not commitments[0].infinity


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_taproot_safety_tweak(vector):
    """
    Recompute the tweak directly from the tagged hash instead of
    obtaining it through apply_taproot_safety().
    """
    initial_A0 = point_from_extended_hex(
        vector["initial_commitments"][0]
    )

    assert not initial_A0.infinity

    tweak_bytes = tagged_hash(
        "TapTweak",
        initial_A0.to_bytes_xonly(),
    )

    expected_tweak = Scalar.from_bytes_checked(
        tweak_bytes
    )

    vector_tweak = scalar_from_hex(
        vector["taproot_safety_tweak"]
    )

    assert vector_tweak == expected_tweak

    # Cross-check the exposed implementation helper as well.
    assert (
        td.taproot_safety_tweak(initial_A0)
        == expected_tweak
    )


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_final_coefficients(vector):
    initial = [
        scalar_from_hex(value)
        for value in vector["initial_coefficients"]
    ]

    final = [
        scalar_from_hex(value)
        for value in vector["final_coefficients"]
    ]

    tweak = scalar_from_hex(
        vector["taproot_safety_tweak"]
    )

    #
    # Bitcoin-specific Taproot-safety transformation:
    #
    #     b_0 = sign*a_0 + tweak
    #     b_j = a_j     for j > 0
    #
    sign = Scalar(1) if (initial[0] * G).has_even_y() else -Scalar(1)
    assert final[0] == sign * initial[0] + tweak
    assert final[1:] == initial[1:]

    # The final threshold secret must be nonzero.
    assert final[0] != Scalar(0)


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_final_commitments(vector):
    initial = [
        point_from_extended_hex(value)
        for value in vector["initial_commitments"]
    ]

    final = [
        point_from_extended_hex(value)
        for value in vector["final_commitments"]
    ]

    final_coeffs = [
        scalar_from_hex(value)
        for value in vector["final_coefficients"]
    ]

    tweak = scalar_from_hex(
        vector["taproot_safety_tweak"]
    )

    #
    #     B_0 = sign*A_0 + tweak*G
    #
    sign = Scalar(1) if initial[0].has_even_y() else -Scalar(1)
    assert final[0] == sign * initial[0] + tweak * G

    #
    #     B_j = A_j for j > 0
    #
    assert final[1:] == initial[1:]

    #
    # Every final commitment must also satisfy:
    #
    #     B_j = b_j * G
    #
    for coeff, commitment in zip(
        final_coeffs,
        final,
    ):
        assert commitment == coeff * G

    assert not final[0].infinity


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_vss_serialization(vector):
    final_commitments = [
        point_from_extended_hex(value)
        for value in vector["final_commitments"]
    ]

    expected = b"".join(
        P.to_bytes_compressed_with_infinity()
        for P in final_commitments
    )

    actual = bytes.fromhex(
        vector["vss_commitment"]
    )

    assert actual == expected

    # Cross-check the reference serialization algorithm.
    assert (
        td.serialize_vss_commitment(
            final_commitments
        )
        == actual
    )


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_threshold_public_key(vector):
    t = vector["t"]

    final_B0 = point_from_extended_hex(
        vector["final_commitments"][0]
    )

    expected = final_B0.to_bytes_compressed()

    actual = bytes.fromhex(
        vector["thresh_pk"]
    )

    assert actual == expected

    assert (
        td.thresh_pubkey_from_commitment(
            t,
            bytes.fromhex(vector["vss_commitment"]),
        )
        == actual
    )


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_participant_identifiers_and_evaluation_points(vector):
    n = vector["n"]

    participants = vector["participants"]

    assert [
        participant["id"]
        for participant in participants
    ] == list(range(n))

    for participant in participants:
        participant_id = participant["id"]

        assert (
            participant["evaluation_point"]
            == participant_id + 1
        )

        assert (
            td.participant_evaluation_point(
                participant_id,
                n,
            )
            == Scalar(participant_id + 1)
        )


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_secret_shares_are_final_polynomial_evaluations(vector):
    final_coeffs = [
        scalar_from_hex(value)
        for value in vector["final_coefficients"]
    ]

    for participant in vector["participants"]:
        participant_id = participant["id"]

        x = Scalar(participant_id + 1)

        expected = td.polynomial_evaluate(
            final_coeffs,
            x,
        )

        actual = nonzero_scalar_from_hex(
            participant["secshare"]
        )

        assert expected != Scalar(0)
        assert actual == expected


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_public_shares_from_secret_shares(vector):
    for participant in vector["participants"]:
        secshare = nonzero_scalar_from_hex(
            participant["secshare"]
        )

        pubshare = point_from_compressed_hex(
            participant["pubshare"]
        )

        assert pubshare == secshare * G


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_public_shares_from_vss_commitment(vector):
    n = vector["n"]
    t = vector["t"]

    vss = bytes.fromhex(
        vector["vss_commitment"]
    )

    final_commitments = td.parse_vss_commitment(
        vss,
        t,
    )

    for participant in vector["participants"]:
        participant_id = participant["id"]

        x = Scalar(participant_id + 1)

        expected_point = td.polynomial_evaluate_point(
            final_commitments,
            x,
        )

        actual_point = point_from_compressed_hex(
            participant["pubshare"]
        )

        assert expected_point == actual_point

        assert (
            td.derive_pubshare_from_commitment(
                participant_id,
                n,
                t,
                vss,
            )
            == bytes.fromhex(
                participant["pubshare"]
            )
        )


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_every_secret_share_verifies(vector):
    n = vector["n"]
    t = vector["t"]

    vss = bytes.fromhex(
        vector["vss_commitment"]
    )

    for participant in vector["participants"]:
        assert td.verify_secshare(
            participant["id"],
            n,
            t,
            bytes.fromhex(
                participant["secshare"]
            ),
            vss,
        )


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_reference_keygen_reproduces_vector(vector):
    coeffs = [
        scalar_from_hex(value)
        for value in vector["initial_coefficients"]
    ]

    output = td.trusted_dealer_keygen_internal(
        coeffs,
        vector["n"],
    )

    assert (
        output.vss_commitment.hex()
        == vector["vss_commitment"]
    )

    assert (
        output.thresh_pk.hex()
        == vector["thresh_pk"]
    )

    assert [
        share.hex()
        for share in output.secshares
    ] == [
        participant["secshare"]
        for participant in vector["participants"]
    ]

    assert [
        share.hex()
        for share in output.pubshares
    ] == [
        participant["pubshare"]
        for participant in vector["participants"]
    ]


#
# Threshold reconstruction
#


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_every_threshold_subset_reconstructs_public_key(vector):
    n = vector["n"]
    t = vector["t"]

    expected = point_from_compressed_hex(
        vector["thresh_pk"]
    )

    pubshares = [
        participant["pubshare"]
        for participant in vector["participants"]
    ]

    for subset in combinations(
        range(n),
        t,
    ):
        reconstructed = reconstruct_threshold_point(
            subset,
            pubshares,
        )

        assert reconstructed == expected


@pytest.mark.parametrize(
    "vector",
    load_vectors()["valid"],
    ids=lambda vector: vector["name"],
)
def test_every_threshold_subset_reconstructs_final_secret(vector):
    """
    This reconstruction is performed only inside the test suite.

    The protocol itself does not provide or recommend a secret-key
    reconstruction API.
    """
    n = vector["n"]
    t = vector["t"]

    final_secret = scalar_from_hex(
        vector["final_coefficients"][0]
    )

    secshares = [
        participant["secshare"]
        for participant in vector["participants"]
    ]

    for subset in combinations(
        range(n),
        t,
    ):
        reconstructed = reconstruct_threshold_scalar(
            subset,
            secshares,
        )

        assert reconstructed == final_secret


#
# Special valid edge cases
#


def test_zero_nonconstant_coefficient_vector():
    vectors = load_vectors()

    vector = next(
        vector
        for vector in vectors["valid"]
        if vector["name"]
        == "zero_nonconstant_coefficient"
    )

    initial_coeffs = [
        scalar_from_hex(value)
        for value in vector["initial_coefficients"]
    ]

    assert initial_coeffs[1] == Scalar(0)

    initial_commitments = [
        point_from_extended_hex(value)
        for value in vector["initial_commitments"]
    ]

    final_commitments = [
        point_from_extended_hex(value)
        for value in vector["final_commitments"]
    ]

    assert initial_commitments[1].infinity
    assert final_commitments[1].infinity

    # Extended serialization of infinity is 33 zero bytes.
    assert (
        bytes.fromhex(
            vector["final_commitments"][1]
        )
        == bytes(33)
    )


def test_zero_initial_share_vector():
    vectors = load_vectors()

    vector = next(
        vector
        for vector in vectors["valid"]
        if vector["name"] == "zero_initial_share"
    )

    initial_coeffs = [
        scalar_from_hex(value)
        for value in vector["initial_coefficients"]
    ]

    #
    # Participant 0 uses x = 1.
    #
    initial_share = td.polynomial_evaluate(
        initial_coeffs,
        Scalar(1),
    )

    assert initial_share == Scalar(0)

    final_share = nonzero_scalar_from_hex(
        vector["participants"][0]["secshare"]
    )

    assert final_share != Scalar(0)


#
# Invalid vectors
#


@pytest.mark.parametrize(
    "vector",
    load_vectors()["invalid"],
    ids=lambda vector: vector["name"],
)
def test_invalid_vectors(vector):
    expected_failure = vector["expected_failure"]

    if vector["operation"] == "ParticipantKeyAccept":
        inputs = decode_acceptance_inputs(vector["inputs"])
        error = TypeError if expected_failure == "missing_required_public_key" else ValueError
        with pytest.raises(error):
            td.participant_key_accept(**inputs)
        return

    if expected_failure == "invalid_parameters":
        coeffs = [
            scalar_from_hex(value)
            for value in vector["initial_coefficients"]
        ]
        with pytest.raises(ValueError):
            td.trusted_dealer_keygen(vector["t"], vector["n"])
        with pytest.raises(ValueError):
            td.trusted_dealer_keygen_internal(coeffs, vector["n"])
        return

    if expected_failure == "invalid_seckey":
        with pytest.raises(ValueError):
            td.trusted_dealer_keygen(
                vector["t"],
                vector["n"],
                bytes.fromhex(vector["seckey"]),
            )

        return

    if expected_failure == "invalid_vss_commitment":
        with pytest.raises(ValueError):
            td.parse_vss_commitment(
                bytes.fromhex(
                    vector["vss_commitment"]
                ),
                vector["t"],
            )

        return

    if expected_failure == "zero_final_share":
        coeffs = [
            scalar_from_hex(value)
            for value in vector["initial_coefficients"]
        ]

        with pytest.raises(td.ZeroFinalShareError):
            td.trusted_dealer_keygen_internal(
                coeffs,
                vector["n"],
            )

        return

    pytest.fail(
        f"Unknown expected_failure value: "
        f"{expected_failure}"
    )


#
# Explicit zero-final-share relationship
#


def test_zero_final_share_vector_is_constructed_correctly():
    vectors = load_vectors()

    vector = next(
        vector
        for vector in vectors["invalid"]
        if vector["name"] == "zero_final_share"
    )

    coeffs = [
        scalar_from_hex(value)
        for value in vector["initial_coefficients"]
    ]

    a_0 = coeffs[0]
    a_1 = coeffs[1]

    tweak = td.taproot_safety_tweak(
        a_0 * G
    )

    #
    # Participant 0 evaluates at x = 1:
    #
    #   f_final(1)
    #       = sign*a_0 + tweak + a_1
    #       = 0
    #
    sign = Scalar(1) if (a_0 * G).has_even_y() else -Scalar(1)
    assert sign * a_0 + tweak + a_1 == Scalar(0)


@pytest.mark.parametrize("vector", load_vectors()["valid"], ids=lambda v: v["name"])
def test_vector_public_key_delivery_and_acceptance(vector):
    original_pk = bytes.fromhex(vector["original_pk"])
    assert original_pk == bytes.fromhex(vector["initial_commitments"][0])
    coeffs = [scalar_from_hex(value) for value in vector["initial_coefficients"]]
    output = td.trusted_dealer_keygen_internal(coeffs, vector["n"])
    assert output.original_pk == original_pk
    for participant in vector["participants"]:
        accepted = td.participant_key_accept(
            participant["id"], vector["n"], vector["t"],
            bytes.fromhex(participant["secshare"]),
            bytes.fromhex(vector["vss_commitment"]),
            original_pk, bytes.fromhex(vector["thresh_pk"]),
        )
        assert accepted.original_pk == original_pk
        assert accepted.pubshare.hex() == participant["pubshare"]


def decode_acceptance_inputs(inputs):
    result = dict(inputs)
    result["participant_id"] = result.pop("id")
    for key in ("secshare", "vss_commitment", "original_pk", "thresh_pk"):
        if key in result:
            result[key] = bytes.fromhex(result[key])
    if result.get("pubshares") is not None:
        result["pubshares"] = [bytes.fromhex(p) for p in result["pubshares"]]
    return result


def test_acceptance_failures_with_python_optimizations():
    # A subprocess ensures library assertions really are disabled. In
    # particular, a 34-byte, zero-padded public share must not be normalized
    # to a valid point by the low-level parser and silently accepted.
    script = '''
import json
import sys
from trusted_dealer_ref import participant_key_accept

with open(sys.argv[1], encoding="utf-8") as stream:
    vectors = json.load(stream)
for vector in vectors["invalid"]:
    if vector["operation"] != "ParticipantKeyAccept":
        continue
    args = dict(vector["inputs"])
    args["participant_id"] = args.pop("id")
    for key in ("secshare", "vss_commitment", "original_pk", "thresh_pk"):
        if key in args:
            args[key] = bytes.fromhex(args[key])
    if args.get("pubshares") is not None:
        args["pubshares"] = [bytes.fromhex(p) for p in args["pubshares"]]
    error = TypeError if vector["expected_failure"] == "missing_required_public_key" else ValueError
    try:
        participant_key_accept(**args)
    except error:
        continue
    raise RuntimeError("Accepted invalid vector: " + vector["name"])
'''
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT / "python"))
    subprocess.run(
        [sys.executable, "-O", "-c", script, str(TEST_VECTOR_PATH)],
        env=env, check=True, capture_output=True, text=True,
    )


def test_vector_file_matches_generator():
    from trusted_dealer_ref.gen_test_vectors import build_vectors

    assert load_vectors() == build_vectors()
