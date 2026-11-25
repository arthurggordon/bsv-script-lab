# GB/T 35275-2026 Python signer

This test-only CLI uses OpenSSL 3 with SM2 and SM3 support for signing
and `asn1crypto` for DER encoding. It produces attached or detached
direct-signature `SignedData` with outer version 1, inner version 2,
and SM2 user ID `1234567812345678`. Its CLI, four JSON fields and DER
signer identifier match the [Rust signer](../rust-signer/README.md).

Run from this directory with a dedicated test key:

```sh
python3 -m pip install asn1crypto==1.5.1
python3 sm2_signed_data_signer.py \
  -message 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -key 0000000000000000000000000000000000000000000000000000000000000001
```

Add `-detached` to omit the content from the envelope. The key is passed
on the command line and written to a private temporary directory for
OpenSSL, which Python removes on exit from the signing operation.

From the repository root, install the [reference dependencies](../../requirements.txt)
and run the focused tests:

```sh
PYTHONPATH=.:projects/p2pkh-sm2/reference \
  python -m unittest -v test_signed_data.PythonSignedDataSignerTests
```

Run `bash projects/p2pkh-sm2/reference/verify.sh` to replay transactions
signed by both the Python and Rust CLIs through BSV Node and chain-gang.
