# Independent GB/T 35275-2026 signer

This test-only process uses `github.com/emmansun/gmsm` for SM2/SM3 and Go's
independent ASN.1 encoder for the complete direct-signature `SignedData`
response. By default it emits `SignedData.version = 1` and
`SignerInfo.version = 2` with an issuer-and-serial identifier, following
GB/T 35275-2026 §8. Use `-signer-version 1` to exercise the legacy direct-signing
adapter path. Supply a dedicated test private key.

```sh
go build -o /tmp/sm2-signed-data-signer .
SM2_SIGNED_DATA_SIGNER=/tmp/sm2-signed-data-signer PYTHONPATH=../../../../..:../.. \
  python -m unittest -v test_signed_data
```

The Python test exercises attached ForkID and detached Chronicle OTDA
payments in both modes. The wallet pins the public key, complete DER signer
identifier and expected inner version before accepting the 64-byte SM2
authorization.
