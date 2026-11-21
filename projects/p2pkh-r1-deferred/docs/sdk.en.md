# P2PKH-R1-Deferred SDK integration

[简体中文](sdk.zh-CN.md)

All three source SDKs use the [deferred template](../template/template.hex) and the [canonical R1 template](../../p2pkh-r1/template/template.hex). Strip whitespace from the `.hex` files and decode the raw bytes starting at the first opcode. Amounts are integer satoshis. TypeScript uses `bigint`, Rust uses `u64`, and Go uses `int64`.

| Operation | TypeScript | Rust | Go |
|---|---|---|---|
| Construct the short lock | `lockForKey` | `lock_for_key` | `LockForKey` |
| Recognize the complete script | `recognize` | `recognize` | `Recognize` |
| Encode the activation unlocking script | `activationWitness` | `activation_witness` | `ActivationWitness` |

Construction takes both templates, the recipient key, and amount. Recognition takes the R1 template, actual short lock, and actual amount. It reconstructs the full script before returning the validated public key, target script SHA-256, and target output HASH256. The receiving wallet checks the expected key and amount against its invoice.

Finalize the paired inputs and outputs, fee inputs, and change. The transaction builder constructs the `0x43` preimage from the actual transaction and authenticated previous output. The SDK witness helper checks the supplied scriptCode, amount, output commitment, and sighash before encoding one push. See the [Python reference](../reference/README.md) for complete transaction construction. Use the [ordinary R1 SDK](../../p2pkh-r1/docs/sdk.en.md) and its external signer callback for the activated output.

Run `npm test`, `cargo test`, or `go test ./...` in the corresponding SDK directory. Each suite replays the [generation and recognition vectors](../template/layout.json) and [activation vector](../template/activation-single.json).
