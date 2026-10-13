# FROST Trusted Dealer Key Generation

The [BIP draft](bip-frost-trusted-dealer.mediawiki) specifies trusted-dealer
generation and verification of threshold keys for
[BIP 445 signing](https://github.com/siv2r/bip-frost-signing).
The normative specification is the MediaWiki document.

The [Python reference](python/trusted_dealer_ref/trusted_dealer_ref.py) and
[JSON vectors](bip-frost-trusted-dealer-test-vectors.json) support review and
interoperability testing. The reference is not constant-time and does not
provide secure secret-memory erasure; it is unsuitable for production.

## Setup and tests

Use Python 3.11 or later. Run these commands from the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install pytest
export PYTHONPATH="$PWD/python:$PWD/python/secp256k1lab/src"
python -m pytest python/trusted_dealer_ref -q
```

Curve arithmetic comes from the vendored `python/secp256k1lab` library.
The suite checks key generation, participant acceptance, Taproot parity,
Feldman verification, threshold reconstruction, and malformed inputs. A
subprocess also runs the acceptance failure vectors under `python -O` so
input validation cannot depend on assertions.

The BIP 445 integration tests are skipped unless `BIP445_REFERENCE_DIR` is
set to an external checkout. To enable them:

```sh
git clone https://github.com/siv2r/bip-frost-signing.git /tmp/bip-frost-signing
export BIP445_REFERENCE_DIR=/tmp/bip-frost-signing
python -m pytest python/trusted_dealer_ref -q
```

These tests use that checkout's signing implementation to validate Threshold
Info, generate and verify partial signatures, aggregate them, and verify the
result as a BIP 340 signature. They exercise all signer subsets of at least
the threshold size for each successful vector, public shares supplied or
derived, direct use of the final key, and further Taproot tweaks with and
without a script tree. Tests never download code automatically; an invalid
configured checkout path fails the integration tests.

## Reference API

The package exports the current implementation, including
`participant_key_accept` and `ParticipantAcceptedKeyMaterial`. The Python
generation entry point takes `(t, n, seckey=None)`; the document presents
these parameters as `(n, t, seckey)`.

```python
from trusted_dealer_ref import trusted_dealer_keygen, participant_key_accept

t, n = 2, 3
dealer = trusted_dealer_keygen(t, n)
participant_id = 1
accepted = participant_key_accept(
    participant_id, n, t,
    dealer.secshares[participant_id],
    dealer.vss_commitment,
    dealer.original_pk,
    dealer.thresh_pk,
    dealer.pubshares,
)
```

This demonstrates local computations. Applications must provide authenticated,
confidential share delivery, ceremony binding, and agreement on the parameters,
participant identity mapping, original key, final key, and commitments. The
dealer retains shares only for delivery and must delete them after completion
or abort; participants must discard shares from failed attempts.

Before signing, construct BIP 445 `ThresholdInfo(t, accepted.thresh_pk,
pubshares)` using the accepted public shares in identifier order and run
`validate_threshold_info`. If public shares were omitted during acceptance,
derive each with `derive_pubshare_from_commitment(id, n, t,
accepted.vss_commitment)`. See the
[integration test](python/trusted_dealer_ref/test_bip445_integration.py) for
the complete handoff to signing.

The mandatory key-generation TapTweak is already incorporated in the shares
and `thresh_pk`. Direct use of its X coordinate as the Taproot output key
needs no further tweak. Using that key as a new Taproot internal key requires
a newly derived tweak and produces a different output key.

## Test vectors

Regenerate the checked-in JSON from the repository root:

```sh
python -m trusted_dealer_ref.gen_test_vectors
```

The suite checks that regeneration reproduces the file exactly.

- `valid` contains deterministic construction inputs and expected intermediate
  and final outputs. Coefficients are test data, not production randomness.
- `invalid` identifies the algorithm in `operation` and the failure class in
  `expected_failure`; exact exception text is not normative. Generation and
  commitment-parsing cases have their inputs at the top level.
- `ParticipantKeyAccept` failure cases contain a complete `inputs` object using
  the document's names (`id` maps to Python's `participant_id`). Hex strings
  encode byte arrays, `pubshares` is a list of hex strings or `null`, and an
  intentionally absent required key tests rejection of missing inputs.

Rare out-of-range or infinity-producing tweak hashes are exercised with mocks
in Python tests; the JSON cases use actual hash outputs.
