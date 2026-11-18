# Reference implementation

The wallet uses the exact script bytes in [the canonical template](../template/template.hex). The assembler rebuilds those bytes independently from the literal blocks in [lock.asm](./asm/lock.asm). Conformance compares three owner vectors, validates three consecutive ordinary payments, and exercises the twelve paired sighash modes and four unpaired SINGLE modes. Both BSV Node and chain-gang must accept each valid complete input, including the two OTDA companion cases. This is input-level regtest validation with supplied UTXOs and explicit script flags.

Use Python 3.12 on Linux x86-64. Install the dependencies from requirements.txt and an approved Chronicle-capable chain-gang build before running the node comparison. The stable engine revision is awaiting maintainer designation. The ordinary TypeScript, Rust and Go SDKs are independent of this dependency.

```sh
cd reference
python -m pip install -r requirements.txt
python generate_lock.py --owner-hash160 4ceab2c8be16c1d4c6b4147d39aa449c2d63f184
# After installing the designated tx-engine build
bash verify.sh
```

The regtest script downloads BSV Node 1.2.3 and checks the archive against the release checksum. It runs a local node with no peers and submits only verification RPCs. The software signer in the test uses publicly known test scalars. Integrations should supply a device callback to [wallet.py](./wallet.py). The current release draft awaits physical-device verification, independent review and relay/fee measurements.
