"""Mocked abort/retry behavior that fixed cryptographic vectors cannot exercise."""

from unittest.mock import Mock

import pytest

from secp256k1lab.secp256k1 import G, Scalar
from trusted_dealer_ref import trusted_dealer_ref as td

SECP256K1_ORDER = Scalar.SIZE


def s(x: int) -> Scalar:
    return Scalar(x)


@pytest.mark.parametrize("imported", [False, True])
@pytest.mark.parametrize("failure", ["out_of_range_tweak", "zero_final_secret"])
def test_taproot_safety_failure_aborts(imported, failure, monkeypatch):
    a0 = s(17)
    sampler = Mock(side_effect=[a0])
    monkeypatch.setattr(td, "random_nonzero_scalar", sampler)
    normalized_secret = a0 if (a0 * G).has_even_y() else -a0
    tweak = SECP256K1_ORDER if failure == "out_of_range_tweak" else int.from_bytes((-normalized_secret).to_bytes(), "big")
    hasher = Mock(return_value=tweak.to_bytes(32, "big"))
    monkeypatch.setattr(td, "tagged_hash", hasher)
    with pytest.raises(td.TaprootSafetyError):
        td.trusted_dealer_keygen(1, 1, a0.to_bytes() if imported else None)
    assert sampler.call_count == (0 if imported else 1)
    hasher.assert_called_once()


@pytest.mark.parametrize("imported", [False, True])
def test_zero_final_share_retries_all_nonconstant_coefficients(imported, monkeypatch):
    a0 = s(17)
    sign = s(1) if (a0 * G).has_even_y() else -s(1)
    final_constant = sign * a0 + td.taproot_safety_tweak(a0 * G)
    # The first polynomial has final f(1) = 0; the second succeeds.
    bad_a2 = s(5)
    bad_a1 = -final_constant - bad_a2
    expected = td.trusted_dealer_keygen_internal([a0, s(1), s(2)], 3)
    initial_sampler = Mock(side_effect=[a0])
    coefficient_sampler = Mock(side_effect=[bad_a1, bad_a2, s(1), s(2)])
    monkeypatch.setattr(td, "random_nonzero_scalar", initial_sampler)
    monkeypatch.setattr(td, "random_scalar", coefficient_sampler)
    output = td.trusted_dealer_keygen(3, 3, a0.to_bytes() if imported else None)
    assert output == expected
    assert initial_sampler.call_count == (0 if imported else 1)
    assert coefficient_sampler.call_count == 4
