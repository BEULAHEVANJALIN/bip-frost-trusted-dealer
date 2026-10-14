"""Run the operation-specific JSON vectors and their documented shared cases."""

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
VECTOR_DIR = REPO_ROOT / "test-vectors"


def load_vectors(filename):
    return json.loads((VECTOR_DIR / filename).read_text(encoding="utf-8"))


KEYGEN = load_vectors("keygen.json")
VALIDATION = load_vectors("validation.json")
ACCEPTANCE = load_vectors("acceptance.json")


def scalar_from_hex(value):
    raw = bytes.fromhex(value)
    assert len(raw) == 32
    return Scalar.from_bytes_checked(raw)


def decode_acceptance_inputs(inputs):
    result = dict(inputs)
    result["participant_id"] = result.pop("id")
    for key in ("secshare", "vss_commitment", "original_pk", "thresh_pk"):
        result[key] = bytes.fromhex(result[key])
    if result.get("pubshares") is not None:
        result["pubshares"] = [bytes.fromhex(p) for p in result["pubshares"]]
    return result


def acceptance_failure_cases():
    base = ACCEPTANCE["base"]
    for case in ACCEPTANCE["point_encoding_error_cases"]:
        for field in ("original_pk", "thresh_pk", "pubshares"):
            inputs = dict(base)
            if field == "pubshares":
                inputs[field] = list(base[field])
                inputs[field][1] = case["value"]
            else:
                inputs[field] = case["value"]
            yield f"{case['name']}/{field}", inputs, "invalid_point_encoding"
    for case in ACCEPTANCE["error_test_cases"]:
        yield case["name"], {**base, **case["replace"]}, case["expected_failure"]


def lagrange_coefficient_at_zero(participant_id, subset):
    # Participant identifiers are zero-based; evaluation points are id + 1.
    numerator, denominator = 1, 1
    for other_id in subset:
        if other_id != participant_id:
            numerator = numerator * (other_id + 1) % Scalar.SIZE
            denominator = denominator * (other_id - participant_id) % Scalar.SIZE
    return Scalar(numerator * pow(denominator, -1, Scalar.SIZE) % Scalar.SIZE)


@pytest.mark.parametrize("case", KEYGEN["valid_test_cases"], ids=lambda c: c["name"])
def test_keygen(case):
    n = case["inputs"]["n"]
    coeffs = [scalar_from_hex(c) for c in case["inputs"]["coefficients"]]
    t = len(coeffs)
    expected = case["expected"]
    final_coeffs = [scalar_from_hex(c) for c in expected["coefficients"]]
    original = coeffs[0] * G
    tweak_bytes = tagged_hash("TapTweak", original.to_bytes_xonly())
    assert tweak_bytes.hex() == expected["tweak"]
    tweak = Scalar.from_bytes_checked(tweak_bytes)
    g = Scalar(1) if original.has_even_y() else -Scalar(1)
    assert final_coeffs == [g * coeffs[0] + tweak] + coeffs[1:]

    final_commitments = [c * G for c in final_coeffs]
    vss = bytes.fromhex(expected["vss_commitment"])
    assert vss == b"".join(p.to_bytes_compressed_with_infinity() for p in final_commitments)
    assert td.parse_vss_commitment(vss, t) == final_commitments
    assert td.serialize_vss_commitment(final_commitments) == vss
    assert td.thresh_pubkey_from_commitment(t, vss).hex() == expected["thresh_pk"]
    safety = td.apply_taproot_safety(coeffs, [c * G for c in coeffs])
    assert safety == (final_coeffs, final_commitments, tweak)

    output = td.trusted_dealer_keygen_internal(coeffs, n)
    assert output.original_pk == original.to_bytes_compressed()
    for field in ("original_pk", "thresh_pk", "vss_commitment"):
        assert getattr(output, field).hex() == expected[field]
    assert len(output.secshares) == len(output.pubshares) == n
    # For t=1 the imported-secret wrapper is deterministic as well.
    if t == 1:
        assert td.trusted_dealer_keygen(t, n, coeffs[0].to_bytes()) == output

    for share in expected["shares"]:
        assert output.secshares[share["id"]].hex() == share["secshare"]
        assert output.pubshares[share["id"]].hex() == share["pubshare"]

    # Check every share, including those omitted from the boundary vector.
    # Use a power sum independent of the implementation's Horner evaluation.
    for participant_id in range(n):
        x = participant_id + 1
        value = sum(int(c, 16) * pow(x, j, Scalar.SIZE)
                    for j, c in enumerate(expected["coefficients"])) % Scalar.SIZE
        assert value != 0
        assert output.secshares[participant_id] == value.to_bytes(32, "big")
        assert output.pubshares[participant_id] == (Scalar(value) * G).to_bytes_compressed()
        assert td.participant_evaluation_point(participant_id, n) == Scalar(x)
        assert td.derive_pubshare_from_commitment(participant_id, n, t, vss) == output.pubshares[participant_id]
        assert td.verify_secshare(participant_id, n, t, output.secshares[participant_id], vss)
        # One participant checks the complete list; others derive their own share.
        pubshares = output.pubshares if participant_id == n - 1 else None
        accepted = td.participant_key_accept(
            participant_id, n, t, output.secshares[participant_id], vss,
            output.original_pk, output.thresh_pk, pubshares,
        )
        assert accepted == td.ParticipantAcceptedKeyMaterial(
            output.original_pk, participant_id, output.secshares[participant_id],
            output.thresh_pk, output.pubshares[participant_id], vss,
        )

    subsets = case.get("reconstruction_subsets", combinations(range(n), t))
    for subset in subsets:
        secret, point = Scalar(0), GE()
        for participant_id in subset:
            weight = lagrange_coefficient_at_zero(participant_id, subset)
            secret += weight * Scalar.from_bytes_nonzero_checked(output.secshares[participant_id])
            point += weight * GE.from_bytes_compressed(output.pubshares[participant_id])
        assert secret == final_coeffs[0]
        assert point == final_commitments[0]


@pytest.mark.parametrize("case", KEYGEN["error_test_cases"], ids=lambda c: c["name"])
def test_keygen_failure(case):
    assert case["expected_failure"] == "zero_final_share"
    coeffs = [scalar_from_hex(c) for c in case["inputs"]["coefficients"]]
    with pytest.raises(td.ZeroFinalShareError):
        td.trusted_dealer_keygen_internal(coeffs, case["inputs"]["n"])


@pytest.mark.parametrize("case", VALIDATION["parameter_error_cases"], ids=lambda c: c["name"])
def test_invalid_parameters(case):
    t, n = case["t"], case["n"]
    args = decode_acceptance_inputs(ACCEPTANCE["base"])
    if t <= 1:
        # Use a matching one-coefficient commitment so parsing does not hide
        # missing parameter validation at public entry points.
        expected = KEYGEN["valid_test_cases"][0]["expected"]
        for field in ("original_pk", "thresh_pk", "vss_commitment"):
            args[field] = bytes.fromhex(expected[field])
        args["secshare"] = bytes.fromhex(expected["shares"][0]["secshare"])
    args.update(t=t, n=n, pubshares=None)
    with pytest.raises(ValueError):
        td.validate_params(t, n)
    for seckey in (None, Scalar(1).to_bytes()):
        with pytest.raises(ValueError):
            td.trusted_dealer_keygen(t, n, seckey)
    with pytest.raises(ValueError):
        td.trusted_dealer_keygen_internal([Scalar(1)] * t, n)
    if not 1 <= n <= 128:
        with pytest.raises(ValueError):
            td.participant_evaluation_point(0, n)
    with pytest.raises(ValueError):
        td.derive_pubshare_from_commitment(0, n, t, args["vss_commitment"])
    assert not td.verify_secshare(0, n, t, args["secshare"], args["vss_commitment"])
    with pytest.raises(ValueError):
        td.participant_key_accept(**args)


@pytest.mark.parametrize("case", VALIDATION["scalar_error_cases"], ids=lambda c: c["name"])
def test_invalid_scalar(case):
    raw = bytes.fromhex(case["value"])
    with pytest.raises(ValueError):
        td.trusted_dealer_keygen(1, 1, raw)
    args = decode_acceptance_inputs({**ACCEPTANCE["base"], "secshare": case["value"]})
    assert not td.verify_secshare(0, args["n"], args["t"], raw, args["vss_commitment"])
    with pytest.raises(ValueError):
        td.participant_key_accept(**args)
    if case["name"] == "zero":
        with pytest.raises(ValueError):
            td.trusted_dealer_keygen_internal([Scalar(0)], 1)


@pytest.mark.parametrize("case", VALIDATION["commitment_error_cases"], ids=lambda c: c["name"])
def test_invalid_commitment(case):
    args = decode_acceptance_inputs({**ACCEPTANCE["base"], "t": case["t"], "vss_commitment": case["value"]})
    with pytest.raises(ValueError):
        td.parse_vss_commitment(args["vss_commitment"], args["t"])
    with pytest.raises(ValueError):
        td.derive_pubshare_from_commitment(0, args["n"], args["t"], args["vss_commitment"])
    assert not td.verify_secshare(0, args["n"], args["t"], args["secshare"], args["vss_commitment"])
    with pytest.raises(ValueError):
        td.participant_key_accept(**args)


@pytest.mark.parametrize("supply_pubshares", [False, True])
def test_acceptance_base(supply_pubshares):
    args = decode_acceptance_inputs(ACCEPTANCE["base"])
    expected_pubshare = args["pubshares"][args["participant_id"]]
    if not supply_pubshares:
        args["pubshares"] = None
    accepted = td.participant_key_accept(**args)
    assert accepted.pubshare == expected_pubshare
    for field in ("original_pk", "participant_id", "secshare", "thresh_pk", "vss_commitment"):
        assert getattr(accepted, field) == args[field]


ACCEPTANCE_FAILURES = list(acceptance_failure_cases())


@pytest.mark.parametrize("name,inputs,failure", ACCEPTANCE_FAILURES, ids=[c[0] for c in ACCEPTANCE_FAILURES])
def test_acceptance_failure(name, inputs, failure):
    args = decode_acceptance_inputs(inputs)
    messages = {
        "taproot_relationship": "do not satisfy the BIP 341 tweak",
        "threshold_key_mismatch": "does not match the VSS commitment",
        "pubshare_mismatch": "does not match the VSS commitment",
        "pubshare_count": "contain n elements",
        "invalid_identifier": "failed VSS verification",
        "invalid_secret_share": "failed VSS verification",
    }
    if name == "missing_even_y_normalization":
        # A Feldman-consistent share alone must not establish Taproot safety.
        assert td.verify_secshare(inputs["id"], inputs["n"], inputs["t"], args["secshare"], args["vss_commitment"])
    with pytest.raises(ValueError, match=messages.get(failure)):
        td.participant_key_accept(**args)
    if failure in ("invalid_identifier", "invalid_secret_share"):
        assert not td.verify_secshare(inputs["id"], inputs["n"], inputs["t"], args["secshare"], args["vss_commitment"])
    if failure == "invalid_identifier":
        with pytest.raises(ValueError):
            td.participant_evaluation_point(inputs["id"], inputs["n"])
        with pytest.raises(ValueError):
            td.derive_pubshare_from_commitment(inputs["id"], inputs["n"], inputs["t"], args["vss_commitment"])


def test_acceptance_failures_with_python_optimizations():
    # Run the same vectors with library assertions disabled. The padded valid
    # public share must be rejected even if a low-level parser normalizes it.
    script = '''
import json
import sys
from trusted_dealer_ref import participant_key_accept

base, failures = json.load(sys.stdin)
def accept(inputs):
    args = dict(inputs)
    args["participant_id"] = args.pop("id")
    for key in ("secshare", "vss_commitment", "original_pk", "thresh_pk"):
        args[key] = bytes.fromhex(args[key])
    if args.get("pubshares") is not None:
        args["pubshares"] = [bytes.fromhex(p) for p in args["pubshares"]]
    return participant_key_accept(**args)

accept(base)
for name, inputs, failure in failures:
    try:
        accept(inputs)
    except ValueError:
        continue
    raise RuntimeError("Accepted invalid vector: " + name)
'''
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([
        str(REPO_ROOT / "python"), str(REPO_ROOT / "python/secp256k1lab/src"),
    ]))
    subprocess.run(
        [sys.executable, "-O", "-c", script],
        input=json.dumps([ACCEPTANCE["base"], ACCEPTANCE_FAILURES]),
        env=env, check=True, capture_output=True, text=True,
    )


def test_vector_files_match_generator():
    from trusted_dealer_ref.gen_test_vectors import build_vectors

    generated = build_vectors()
    assert {p.name for p in VECTOR_DIR.glob("*.json")} == set(generated)
    for filename, data in generated.items():
        assert (VECTOR_DIR / filename).read_text(encoding="utf-8") == json.dumps(data, indent=2) + "\n"
