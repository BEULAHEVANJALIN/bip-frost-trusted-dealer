"""BIP 341 compatibility and mandatory public-key verification."""

import pytest

from secp256k1lab.secp256k1 import G, GE, Scalar
from trusted_dealer_ref import trusted_dealer_ref as td


@pytest.mark.parametrize("negate", [False, True])
def test_bip341_published_no_script_path_vector(negate):
    # bitcoin/bips/bip-0341/wallet-test-vectors.json:
    # scriptPubKey[0] and keyPathSpending[0].inputSpending[0].
    # https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json
    secret = Scalar.from_bytes_nonzero_checked(bytes.fromhex(
        "6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa"
    ))
    if negate:
        secret = -secret
    initial = secret * G
    assert initial.to_bytes_xonly().hex() == (
        "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d"
    )
    assert td.taproot_safety_tweak(initial).to_bytes().hex() == (
        "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70"
    )
    output = td.trusted_dealer_keygen_internal([secret], 1)
    assert output.original_pk == initial.to_bytes_compressed()
    assert output.secshares[0].hex() == (
        "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9"
    )
    assert output.thresh_pk[1:].hex() == (
        "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
    )
    accepted = td.participant_key_accept(
        0, 1, 1, output.secshares[0], output.vss_commitment,
        output.original_pk, output.thresh_pk,
    )
    assert accepted.original_pk == output.original_pk
    assert accepted.thresh_pk == output.thresh_pk


@pytest.fixture
def output():
    assert not (Scalar(6) * G).has_even_y()
    return td.trusted_dealer_keygen_internal([Scalar(6), Scalar(5)], 3)


@pytest.mark.parametrize("key", ["original_pk", "thresh_pk"])
@pytest.mark.parametrize("bad", [
    b"", bytes(32), bytes(33), bytes(34),
    b"\x04" + bytes(32), b"\x02" + bytes([255]) * 32,
])
def test_rejects_malformed_public_keys(output, key, bad):
    keys = {"original_pk": output.original_pk, "thresh_pk": output.thresh_pk}
    keys[key] = bad
    with pytest.raises(ValueError):
        td.participant_key_accept(
            0, 3, 2, output.secshares[0], output.vss_commitment, **keys,
        )


@pytest.mark.parametrize("key", ["original_pk", "thresh_pk"])
def test_both_keys_are_required(output, key):
    keys = {"original_pk": output.original_pk, "thresh_pk": output.thresh_pk}
    del keys[key]
    with pytest.raises(TypeError):
        td.participant_key_accept(
            0, 3, 2, output.secshares[0], output.vss_commitment, **keys,
        )


def test_rejects_unrelated_original_key(output):
    with pytest.raises(ValueError, match="BIP 341 tweak"):
        td.participant_key_accept(
            0, 3, 2, output.secshares[0], output.vss_commitment,
            G.to_bytes_compressed(), output.thresh_pk,
        )


def test_rejects_valid_key_pair_from_different_commitment(output):
    other = td.trusted_dealer_keygen_internal([Scalar(7), Scalar(5)], 3)
    with pytest.raises(ValueError, match="VSS commitment"):
        td.participant_key_accept(
            0, 3, 2, output.secshares[0], output.vss_commitment,
            other.original_pk, other.thresh_pk,
        )


def test_rejects_old_odd_y_transformation_even_when_share_verifies():
    a0, a1 = Scalar(6), Scalar(5)
    initial = a0 * G
    assert not initial.has_even_y()
    old_constant = a0 + td.taproot_safety_tweak(initial)
    old_key = (old_constant * G).to_bytes_compressed()
    old_vss = old_key + (a1 * G).to_bytes_compressed()
    old_share = (old_constant + a1).to_bytes()
    assert td.verify_secshare(0, 3, 2, old_share, old_vss)
    with pytest.raises(ValueError, match="BIP 341 tweak"):
        td.participant_key_accept(
            0, 3, 2, old_share, old_vss, initial.to_bytes_compressed(), old_key,
        )


def test_rejects_opposite_parity_of_tweaked_key(output):
    opposite = -GE.from_bytes_compressed(output.thresh_pk)
    with pytest.raises(ValueError, match="BIP 341 tweak"):
        td.participant_key_accept(
            0, 3, 2, output.secshares[0], output.vss_commitment,
            output.original_pk, opposite.to_bytes_compressed(),
        )


@pytest.mark.parametrize("failure", ["out_of_range", "infinity"])
def test_participant_rejects_invalid_tweak(output, monkeypatch, failure):
    initial = GE.from_bytes_compressed(output.original_pk)
    normalized_secret = -Scalar(6)  # The fixture's original key has odd Y.
    value = Scalar.SIZE if failure == "out_of_range" else int.from_bytes(
        (-normalized_secret).to_bytes(), "big"
    )
    monkeypatch.setattr(td, "tagged_hash", lambda tag, data: value.to_bytes(32, "big"))
    with pytest.raises(td.TaprootSafetyError):
        td.participant_key_accept(
            0, 3, 2, output.secshares[0], output.vss_commitment,
            initial.to_bytes_compressed(), output.thresh_pk,
        )


@pytest.mark.parametrize("a0", [6, 7])
def test_zero_tweak_is_valid_and_keeps_even_y_normalization(a0, monkeypatch):
    monkeypatch.setattr(td, "tagged_hash", lambda tag, data: bytes(32))
    output = td.trusted_dealer_keygen_internal([Scalar(a0), Scalar(2)], 3)
    assert GE.from_bytes_compressed(output.thresh_pk).has_even_y()
    assert output.thresh_pk[1:] == output.original_pk[1:]
    td.participant_key_accept(
        0, 3, 2, output.secshares[0], output.vss_commitment,
        output.original_pk, output.thresh_pk,
    )
