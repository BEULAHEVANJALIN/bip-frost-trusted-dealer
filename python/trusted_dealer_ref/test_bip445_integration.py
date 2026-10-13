"""End-to-end tests against an external BIP 445 reference checkout.

Set BIP445_REFERENCE_DIR to the checkout root to enable these tests.
Nothing is downloaded or installed by the tests. See the repository README.
"""

import importlib.util
import json
import os
from itertools import combinations
from pathlib import Path

import pytest

from secp256k1lab.bip340 import schnorr_verify
from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.util import tagged_hash
from trusted_dealer_ref import trusted_dealer_ref as td


VECTOR_PATH = Path(__file__).resolve().parents[2] / "bip-frost-trusted-dealer-test-vectors.json"
VECTORS = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))["valid"]


@pytest.fixture(scope="module")
def frost():
    checkout = os.environ.get("BIP445_REFERENCE_DIR")
    if not checkout:
        pytest.skip("Set BIP445_REFERENCE_DIR to run BIP 445 interoperability tests")
    source = Path(checkout) / "python" / "frost_ref" / "signing.py"
    if not source.is_file():
        pytest.fail(f"BIP 445 reference implementation not found: {source}")
    spec = importlib.util.spec_from_file_location("bip445_signing", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("vector", VECTORS, ids=lambda v: v["name"])
@pytest.mark.parametrize("supply_pubshares", [False, True], ids=["derived", "supplied"])
@pytest.mark.parametrize("output_use", ["direct", "new_internal_no_script", "new_internal_script"])
def test_dealer_to_bip445_to_bip340(frost, vector, supply_pubshares, output_use):
    n, t = vector["n"], vector["t"]
    coeffs = [Scalar.from_bytes_checked(bytes.fromhex(c)) for c in vector["initial_coefficients"]]
    dealer = td.trusted_dealer_keygen_internal(coeffs, n)
    accepted = [
        td.participant_key_accept(
            participant_id, n, t, dealer.secshares[participant_id],
            dealer.vss_commitment, dealer.original_pk, dealer.thresh_pk,
            dealer.pubshares if supply_pubshares else None,
        )
        for participant_id in range(n)
    ]

    # Application-level authenticated distribution and common-view agreement
    # are assumed by this local test; each signer uses its own accepted data.
    infos = []
    for record in accepted:
        pubshares = list(dealer.pubshares) if supply_pubshares else [
            td.derive_pubshare_from_commitment(i, n, t, record.vss_commitment)
            for i in range(n)
        ]
        info = frost.ThresholdInfo(t, record.thresh_pk, pubshares)
        frost.validate_threshold_info(info)
        infos.append(info)
    assert all(info == infos[0] for info in infos)

    # Direct use already includes key generation's TapTweak. Other modes
    # deliberately use A1 as a NEW internal key, with a newly derived tweak.
    tweaks, is_xonly = [], []
    expected_point = GE.from_bytes_compressed(dealer.thresh_pk)
    if output_use != "direct":
        # BIP 341 leaf: version 0xc0, CompactSize length 1, script OP_TRUE.
        root = tagged_hash("TapLeaf", b"\xc0\x01\x51") if output_use == "new_internal_script" else b""
        tweak = tagged_hash("TapTweak", expected_point.to_bytes_xonly() + root)
        scalar = Scalar.from_bytes_checked(tweak)
        normalized = expected_point if expected_point.has_even_y() else -expected_point
        expected_point = normalized + scalar * G
        assert not expected_point.infinity
        assert expected_point.to_bytes_xonly() != dealer.thresh_pk[1:]
        tweaks, is_xonly = [tweak], [True]
    tweak_ctx = frost.thresh_pubkey_and_tweak(dealer.thresh_pk, tweaks, is_xonly)
    assert frost.get_plain_pk(tweak_ctx) == expected_point.to_bytes_compressed()
    signing_key = expected_point.to_bytes_xonly()

    # All subsets of at least t signers, including non-contiguous identifiers.
    for count in range(t, n + 1):
        for subset in combinations(range(n), count):
            ids = list(subset)
            message = tagged_hash("TrustedDealer/test", vector["name"].encode() + bytes(ids))
            nonces = [
                frost.nonce_gen(
                    accepted[i].secshare, i, accepted[i].pubshare,
                    signing_key, message, None,
                )
                for i in ids
            ]
            pubnonces = [pubnonce for _, pubnonce in nonces]
            aggnonce = frost.nonce_agg(pubnonces)
            partials = []
            for position, participant_id in enumerate(ids):
                info = infos[participant_id]
                selected_pubshares = [info.pubshares[i] for i in ids]
                ctx = frost.SessionContext(
                    n, info.t, ids, selected_pubshares, info.thresh_pk,
                    aggnonce, tweaks, is_xonly, message,
                )
                partial = frost.sign(
                    nonces[position][0], accepted[participant_id].secshare,
                    participant_id, ctx,
                )
                assert frost.partial_sig_verify(
                    partial, pubnonces, n, t, ids, selected_pubshares,
                    info.thresh_pk, tweaks, is_xonly, message, position,
                )
                partials.append(partial)
            signature = frost.partial_sig_agg(partials, ctx)
            assert schnorr_verify(message, signing_key, signature)
            assert not schnorr_verify(message + b"\x00", signing_key, signature)
            if output_use != "direct":
                assert not schnorr_verify(message, dealer.thresh_pk[1:], signature)


def test_bip445_rejects_inconsistent_threshold_info(frost):
    dealer = td.trusted_dealer_keygen_internal([Scalar(6), Scalar(5)], 3)
    bad_shares = list(dealer.pubshares)
    bad_shares[2] = G.to_bytes_compressed()
    with pytest.raises(ValueError):
        frost.validate_threshold_info(frost.ThresholdInfo(2, dealer.thresh_pk, bad_shares))
    with pytest.raises(ValueError):
        frost.validate_threshold_info(frost.ThresholdInfo(2, dealer.original_pk, dealer.pubshares))


def test_bip445_participant_limit(frost):
    dealer = td.trusted_dealer_keygen_internal([Scalar(6), Scalar(5)], 128)
    frost.validate_threshold_info(frost.ThresholdInfo(2, dealer.thresh_pk, dealer.pubshares))
    with pytest.raises(ValueError):
        frost.validate_threshold_info(
            frost.ThresholdInfo(2, dealer.thresh_pk, dealer.pubshares + [None])
        )
