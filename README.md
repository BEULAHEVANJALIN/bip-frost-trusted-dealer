# FROST Trusted Dealer Key Generation

Trusted-dealer key generation for [BIP 445](https://github.com/siv2r/bip-frost-signing).
See the [BIP draft](bip-frost-trusted-dealer.mediawiki) for the specification and
[Python reference](python/trusted_dealer_ref/trusted_dealer_ref.py) for the implementation.

The reference is not constant-time and cannot securely erase secrets. Do not
use it in production.

## Tests

Requires Python 3.11+ and pytest. From the repository root:

```sh
python -m pytest -q
```

`pytest.ini` sets the import paths for the reference and vendored `secp256k1lab`.
For use outside pytest, set `PYTHONPATH=python:python/secp256k1lab/src`.

## Test vectors

- [Key generation](test-vectors/keygen.json)
- [Input validation](test-vectors/validation.json)
- [Participant acceptance](test-vectors/acceptance.json)

See the [vector format and coverage](test-vectors/README.md).
