# python/trusted_dealer_ref/gen_test_vectors.py

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from secp256k1lab.secp256k1 import G, Scalar

from trusted_dealer_ref import trusted_dealer_ref as td



OUTPUT_PATH = Path("bip-frost-trusted-dealer-test-vectors.json")


def scalar_hex(s: Scalar) -> str:
    return s.to_bytes().hex()


def point_ext_hex(P) -> str:
    return P.to_bytes_compressed_with_infinity().hex()


def make_valid_vector(
    name: str,
    comment: str,
    n: int,
    coeff_ints: list[int],
) -> dict[str, Any]:
    coeffs = [Scalar(x) for x in coeff_ints]
    t = len(coeffs)

    initial_commitments = [a * G for a in coeffs]

    safety = td.apply_taproot_safety(
        coeffs,
        initial_commitments,
    )

    output = td.trusted_dealer_keygen_internal(
        coeffs,
        n,
    )

    participants = []

    for participant_id in range(n):
        participants.append(
            {
                "id": participant_id,
                "evaluation_point": participant_id + 1,
                "secshare": output.secshares[participant_id].hex(),
                "pubshare": output.pubshares[participant_id].hex(),
            }
        )

    return {
        "name": name,
        "comment": comment,
        "n": n,
        "t": t,
        "initial_coefficients": [
            scalar_hex(a)
            for a in coeffs
        ],
        "initial_commitments": [
            point_ext_hex(P)
            for P in initial_commitments
        ],
        "taproot_safety_tweak": scalar_hex(
            safety.tweak
        ),
        "final_coefficients": [
            scalar_hex(b)
            for b in safety.final_coeffs
        ],
        "final_commitments": [
            point_ext_hex(P)
            for P in safety.final_commitments
        ],
        "vss_commitment": output.vss_commitment.hex(),
        "thresh_pk": output.thresh_pk.hex(),
        "participants": participants,
    }


def make_zero_final_share_vector() -> dict[str, Any]:
    """
    Construct a deterministic polynomial whose FINAL share for
    participant 0 is zero.

        f_final(1) = a_0 + tweak + a_1 = 0
    """
    a_0 = Scalar(17)

    tweak = td.taproot_safety_tweak(
        a_0 * G
    )

    a_1 = Scalar(0) - (a_0 + tweak)

    return {
        "name": "zero_final_share",
        "comment": (
            "Final secret share for participant 0 is zero "
            "after the Taproot-safety transformation."
        ),
        "n": 2,
        "t": 2,
        "initial_coefficients": [
            scalar_hex(a_0),
            scalar_hex(a_1),
        ],
        "expected_failure": "zero_final_share",
    }


def make_invalid_vectors() -> list[dict[str, Any]]:
    q = int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
        "BAAEDCE6AF48A03BBFD25E8CD0364141",
        16,
    )

    return [
        {
            "name": "participant_count_above_limit",
            "comment": "Participant count exceeds the BIP 445 limit of 128.",
            "n": 129,
            "t": 1,
            "initial_coefficients": [scalar_hex(Scalar(1))],
            "expected_failure": "invalid_parameters",
        },
        {
            "name": "zero_imported_secret",
            "comment": "Imported threshold secret is zero.",
            "n": 3,
            "t": 2,
            "seckey": bytes(32).hex(),
            "expected_failure": "invalid_seckey",
        },
        {
            "name": "seckey_equal_to_group_order",
            "comment": (
                "Imported threshold secret is equal to the "
                "secp256k1 group order."
            ),
            "n": 3,
            "t": 2,
            "seckey": q.to_bytes(32, "big").hex(),
            "expected_failure": "invalid_seckey",
        },
        {
            "name": "malformed_vss_length",
            "comment": (
                "VSS commitment length is not exactly 33*t bytes."
            ),
            "n": 3,
            "t": 2,
            "vss_commitment": bytes(65).hex(),
            "expected_failure": "invalid_vss_commitment",
        },
        {
            "name": "infinity_constant_commitment",
            "comment": (
                "The constant-term VSS commitment is infinity."
            ),
            "n": 3,
            "t": 2,
            "vss_commitment": (
                bytes(33)
                + G.to_bytes_compressed()
            ).hex(),
            "expected_failure": "invalid_vss_commitment",
        },
        make_zero_final_share_vector(),
    ]


def build_vectors() -> dict[str, Any]:
    valid = [
        make_valid_vector(
            name="1_of_1",
            comment="Basic deterministic 1-of-1 vector.",
            n=1,
            coeff_ints=[1],
        ),
        make_valid_vector(
            name="2_of_3",
            comment="Basic deterministic 2-of-3 vector.",
            n=3,
            coeff_ints=[1, 2],
        ),
        make_valid_vector(
            name="3_of_3",
            comment="Basic deterministic 3-of-3 vector.",
            n=3,
            coeff_ints=[3, 5, 7],
        ),
        make_valid_vector(
            name="zero_nonconstant_coefficient",
            comment=(
                "A zero nonconstant coefficient produces an "
                "infinity nonconstant Feldman commitment."
            ),
            n=3,
            coeff_ints=[7, 0],
        ),
        make_valid_vector(
            name="zero_initial_share",
            comment=(
                "Participant 0 has an initial zero share, but "
                "the final share is nonzero after Taproot safety."
            ),
            n=2,
            coeff_ints=[
                29,
                (-29) % int(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
                    "BAAEDCE6AF48A03BBFD25E8CD0364141",
                    16,
                ),
            ],
        ),
    ]

    return {
        "description": (
            "BIP FROST Trusted Dealer Key Generation "
            "deterministic test vectors"
        ),
        "valid": valid,
        "invalid": make_invalid_vectors(),
    }


def main() -> None:
    vectors = build_vectors()

    OUTPUT_PATH.write_text(
        json.dumps(
            vectors,
            indent=2,
            sort_keys=False,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"Wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
