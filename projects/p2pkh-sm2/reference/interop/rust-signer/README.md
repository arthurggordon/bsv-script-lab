# Independent GB/T 35275-2026 Rust signer

This test-only process uses RustCrypto `sm2` for SM2/SM3 signing and `der`
for ASN.1 encoding. It produces a direct-signature `SignedData` envelope
with outer version 1, inner `SignerInfo.version = 2`, and the template's
fixed SM2 user ID `1234567812345678`.

The command takes `-message HEX -key TEST_KEY_HEX [-detached]` and prints
`envelope_hex`, `public_key_hex`, `signer_identifier_hex` and `signer_version`
as JSON. The issuer retains the original fixture's common name
`Independent Go Signer` and serial 1 so the pinned DER identifier stays
the same. Use a dedicated test key. The key is passed on the command line.

From the repository root, build the signer and run its focused tests:

```sh
signer_dir="$PWD/projects/p2pkh-sm2/reference/interop/rust-signer"
cargo build --locked --release --manifest-path "$signer_dir/Cargo.toml" --target-dir "$signer_dir/target"
SM2_SIGNED_DATA_SIGNER="$signer_dir/target/release/sm2-signed-data-signer" \
  PYTHONPATH=.:projects/p2pkh-sm2/reference python -m unittest -v test_signed_data.IndependentSignedDataTests
```

The focused tests require the [pinned reference dependencies](../../requirements.txt)
and OpenSSL with SM2/SM3 support. Run `bash projects/p2pkh-sm2/reference/verify.sh`
to build the signer automatically and replay payments from both this signer
and the [Python signer](../python-signer/README.md) on BSV Node 1.2.3.
