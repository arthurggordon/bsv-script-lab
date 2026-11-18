# P2PKH-SM2 reference

Run from this directory. Python 3.12+, OpenSSL with SM2/SM3, and `ecdsa==0.19.1` are sufficient for local tests:

```sh
python3 -m pip install ecdsa==0.19.1
python3 -m unittest -v test_sm2
python3 generate_lock.py --owner-hash160 000102030405060708090a0b0c0d0e0f10111213 --format hex
```

`sm2.py` defines curve parameters, ZA, digest verification and an **explicit-nonce test-only** signer. `sm3_script.py` unrolls SM3 into ordinary Script bytecode. `asm/` contains SM2 group verification, scalar multiplication and PUSHTX. `p2pkh_sm2.py` is the wallet API. No new consensus opcode is used.

The local evaluator is a development harness. For independent complete-input validation, use Linux x86-64 with Rust, install the pinned extension, then run the node comparison:

```sh
python3 -m pip install -r requirements.txt
bash verify.sh
```

This checks three consecutive transfers, mixed inputs and multiple outputs, output/input mutations, invalid keys/scalars/identities, forged signing preimages, and extra witness items in both BSV Node 1.2.3 and chain-gang. The node launcher checks the downloaded archive against the release checksum and uses a temporary regtest directory with no peers. It does not broadcast transactions.

`test_sm2.py` also checks SM3 padding boundaries and fixed-prefix midstates against the host SM3 implementation, the published SM2 vector, and a real OpenSSL-generated SM2 key/signature accepted by the generated script. All fixture private scalars and nonces are public test data.

The [standard vector](../template/sm2-standard.json), [payment vector](../template/spend-all.json), and [layout manifest](../template/layout.json) are checked in. Raw lock bytes are generated on demand and checked against the pinned manifest hash.
