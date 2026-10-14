"""Exceptional TapTweak outputs requiring a mocked hash.

Ordinary BIP 341 compatibility and acceptance failures are JSON vectors.
"""

import pytest

from secp256k1lab.secp256k1 import G, GE, Scalar
from trusted_dealer_ref import trusted_dealer_ref as td


@pytest.fixture
def output():
    assert not (Scalar(6) * G).has_even_y()
    return td.trusted_dealer_keygen_internal([Scalar(6), Scalar(5)], 3)


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
    # Keep all final shares nonzero after normalizing only the constant.
    output = td.trusted_dealer_keygen_internal([Scalar(a0), Scalar(5)], 3)
    assert GE.from_bytes_compressed(output.thresh_pk).has_even_y()
    assert output.thresh_pk[1:] == output.original_pk[1:]
    td.participant_key_accept(
        0, 3, 2, output.secshares[0], output.vss_commitment,
        output.original_pk, output.thresh_pk,
    )
