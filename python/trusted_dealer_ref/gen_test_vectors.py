# python/trusted_dealer_ref/gen_test_vectors.py

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from secp256k1lab.secp256k1 import G, GE, Scalar

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
        "original_pk": output.original_pk.hex(),
        "thresh_pk": output.thresh_pk.hex(),
        "participants": participants,
    }


def make_zero_final_share_vector() -> dict[str, Any]:
    """
    Construct a deterministic polynomial whose FINAL share for
    participant 0 is zero.

        f_final(1) = sign*a_0 + tweak + a_1 = 0
    """
    a_0 = Scalar(17)

    tweak = td.taproot_safety_tweak(
        a_0 * G
    )

    sign = Scalar(1) if (a_0 * G).has_even_y() else -Scalar(1)
    a_1 = -sign * a_0 - tweak

    return {
        "name": "zero_final_share",
        "operation": "TrustedDealerKeygenInternal",
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
            "operation": "TrustedDealerKeygenInternal",
            "comment": "Participant count exceeds the BIP 445 limit of 128.",
            "n": 129,
            "t": 1,
            "initial_coefficients": [scalar_hex(Scalar(1))],
            "expected_failure": "invalid_parameters",
        },
        {
            "name": "zero_imported_secret",
            "operation": "TrustedDealerKeygen",
            "comment": "Imported threshold secret is zero.",
            "n": 3,
            "t": 2,
            "seckey": bytes(32).hex(),
            "expected_failure": "invalid_seckey",
        },
        {
            "name": "seckey_equal_to_group_order",
            "operation": "TrustedDealerKeygen",
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
            "operation": "ParseVSSCommitment",
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
            "operation": "ParseVSSCommitment",
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


def make_acceptance_failure_vectors() -> list[dict[str, Any]]:
    """Self-contained inputs for ParticipantKeyAccept; no mocked hashes."""
    output = td.trusted_dealer_keygen_internal([Scalar(6), Scalar(5)], 3)
    inputs = {
        "id": 0,
        "n": 3,
        "t": 2,
        "secshare": output.secshares[0].hex(),
        "vss_commitment": output.vss_commitment.hex(),
        "original_pk": output.original_pk.hex(),
        "thresh_pk": output.thresh_pk.hex(),
        "pubshares": [share.hex() for share in output.pubshares],
    }
    vectors = []

    def add(name, comment, failure, **changes):
        case_inputs = deepcopy(inputs)
        case_inputs.update(changes)
        vectors.append({
            "name": name,
            "operation": "ParticipantKeyAccept",
            "comment": comment,
            "inputs": case_inputs,
            "expected_failure": failure,
        })

    malformed = {
        "empty": b"",
        "short": bytes(32),
        "long": bytes(34),
        "infinity": bytes(33),
        "invalid_prefix": b"\x04" + output.original_pk[1:],
        "x_out_of_range": b"\x02" + bytes([255]) * 32,
    }
    for key in ("original_pk", "thresh_pk"):
        for kind, raw in malformed.items():
            add(f"accept_{key}_{kind}", f"Malformed {key}: {kind}.",
                "invalid_public_key_encoding", **{key: raw.hex()})
        add(f"accept_missing_{key}", f"The required {key} is absent.",
            "missing_required_public_key")
        del vectors[-1]["inputs"][key]

    add("accept_unrelated_original_key", "A0 does not produce the supplied A1.",
        "invalid_taproot_relationship", original_pk=G.to_bytes_compressed().hex())
    add("accept_unrelated_tweaked_key", "A1 is unrelated to the supplied A0.",
        "invalid_taproot_relationship", thresh_pk=G.to_bytes_compressed().hex())
    opposite = -GE.from_bytes_compressed(output.thresh_pk)
    add("accept_opposite_tweaked_key_parity", "A1 has the right X but wrong Y parity.",
        "invalid_taproot_relationship", thresh_pk=opposite.to_bytes_compressed().hex())
    other = td.trusted_dealer_keygen_internal([Scalar(7), Scalar(5)], 3)
    add("accept_keys_from_another_commitment", "Valid A0/A1 pair belongs to another commitment.",
        "threshold_key_mismatch", original_pk=other.original_pk.hex(),
        thresh_pk=other.thresh_pk.hex())

    # This obsolete transformation has a valid Feldman share, so failure
    # specifically tests the even-Y normalization in the BIP 341 relation.
    old_constant = Scalar(6) + td.taproot_safety_tweak(Scalar(6) * G)
    old_key = (old_constant * G).to_bytes_compressed()
    add("accept_unnormalized_odd_y_key", "Odd-Y A0 was tweaked without even-Y normalization.",
        "invalid_taproot_relationship", thresh_pk=old_key.hex(),
        vss_commitment=(old_key + (Scalar(5) * G).to_bytes_compressed()).hex(),
        secshare=(old_constant + Scalar(5)).to_bytes().hex(), pubshares=None)

    valid_share = output.pubshares[1]
    for kind, raw in {
        "short": valid_share[:-1],
        "padded": valid_share[:1] + b"\x00" + valid_share[1:],
        "infinity": bytes(33),
        "invalid_prefix": b"\x04" + valid_share[1:],
        "x_out_of_range": b"\x02" + bytes([255]) * 32,
    }.items():
        pubshares = list(inputs["pubshares"])
        pubshares[1] = raw.hex()
        add(f"accept_pubshare_{kind}", f"Malformed public share at identifier 1: {kind}.",
            "invalid_pubshare_encoding", pubshares=pubshares)
    pubshares = list(inputs["pubshares"])
    pubshares[1] = pubshares[2]
    add("accept_pubshare_wrong_identifier", "Public share for identifier 2 occupies slot 1.",
        "pubshare_mismatch", pubshares=pubshares)
    add("accept_incomplete_pubshare_list", "Supplied list has fewer than n entries.",
        "invalid_pubshare_count", pubshares=inputs["pubshares"][:-1])
    add("accept_invalid_identifier", "Identifier n is outside the participant range.",
        "invalid_identifier", id=3)
    add("accept_tampered_secret_share", "A canonical scalar fails the Feldman equation.",
        "invalid_secret_share", secshare=Scalar(1).to_bytes().hex())
    return vectors


def build_vectors() -> dict[str, Any]:
    valid = [
        make_valid_vector(
            name="odd_y_initial_key",
            comment="Odd-Y initial key requires negating only the constant coefficient before tweaking.",
            n=3,
            coeff_ints=[6, 5, 0],
        ),
        make_valid_vector(
            name="equal_nonconstant_commitments",
            comment="Equal coefficients legitimately occupy distinct commitment slots.",
            n=4,
            coeff_ints=[7, 5, 5],
        ),
        make_valid_vector(
            name="bip341_no_script_path",
            comment="BIP 341 wallet-test-vectors.json, keyPathSpending[0].inputSpending[0].",
            n=1,
            coeff_ints=[int("6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa", 16)],
        ),
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
        "invalid": make_invalid_vectors() + make_acceptance_failure_vectors(),
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
