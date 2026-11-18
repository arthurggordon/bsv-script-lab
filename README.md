# BSV Script Lab

BSV Script Lab is a public repository for exploring Bitcoin Script on BSV. We publish script designs alongside reference code and reproducible test vectors so developers can inspect the script bytes, replay spends and review the results.

BSV Script Lab 是我们公开研究 BSV 上 Bitcoin Script 的仓库。这里收录脚本设计、参考代码和可复现的测试向量，方便开发者核对脚本字节、重放交易并评审设计。

## Projects · 公开项目

### [Native P2PK and P2PKH baseline](projects/p2pk-p2pkh-baseline/README.md)

Conventional secp256k1 P2PK and P2PKH fixtures for comparison with the research
templates. Includes reproducible locking bytes and five offline validation cases.

原生 secp256k1 P2PK／P2PKH 对照样例，提供可复现的锁定脚本和五个离线验签用例。

### [P2PKH-R1](projects/p2pkh-r1/README.md)

Our first public script project is a payment template for P-256 (secp256r1) keys. A payer can create an output from the recipient’s public-key hash, and the recipient authorizes an ordinary spend with one device signature.

P2PKH-R1 是本仓库首个公开的脚本项目。收款方提供 P-256 公钥哈希即可收款，普通花费只需设备签名一次。目前处于开发者 RFC 阶段，提供 TypeScript、Rust 和 Go SDK。

[Project overview / 项目介绍](projects/p2pkh-r1/README.md) · [中文规范](docs/spec.zh-CN.md) · [English specification](docs/spec.en.md)

### [03 · Lamport OTS (SHA-256)](projects/03-lamport-ots/README.md)

A third experimental project: 256-bit Lamport one-time signatures, unrolled BSV
Script, BIP143 and Chronicle OTDA transaction binding, public vectors,
and measured sizes/performance. Read the explicit one-time and transaction-binding
security boundaries before using it. The second SM2 experiment and its directory
migration are maintained separately and are not bundled into this change.

第三个项目提供 Lamport SHA-256 密钥生成、签名验签、BSV Script 与交易绑定，
并区分仅验证摘要的实验脚本和交易支付脚本。属于实验实现，尚非已审计抗量子钱包。
