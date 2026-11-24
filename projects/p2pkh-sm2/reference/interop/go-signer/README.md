# Independent GB/T 35275-2026 signer

This test-only process uses `github.com/emmansun/gmsm` for SM2/SM3 and Go's
independent ASN.1 encoder for the complete direct-signature `SignedData`
response. It emits `SignerInfo.version = 2`, as required by the 2026 national
standard profile. The private key is supplied explicitly and must remain a
non-production test key.

```sh
go build -o /tmp/sm2-signed-data-signer .
SM2_SIGNED_DATA_SIGNER=/tmp/sm2-signed-data-signer PYTHONPATH=../../../../..:../.. \
  python -m unittest -v test_signed_data
```

The Python test exercises both attached ForkID and detached Chronicle OTDA
payments. The wallet pins the returned public key and complete DER signer
identifier before accepting the 64-byte SM2 authorization.
