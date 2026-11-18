# BSV Script Lab

BSV Script Lab is a public repository for exploring Bitcoin Script on BSV. We publish script designs alongside reference code and reproducible test vectors so developers can inspect the script bytes, replay spends and review the results.

BSV Script Lab 是我们公开研究 BSV 上 Bitcoin Script 的仓库。这里收录脚本设计、参考代码和可复现的测试向量，方便开发者核对脚本字节、重放交易并评审设计。

## Projects · 公开项目

### [P2PKH-R1](projects/p2pkh-r1/README.md)

Our first public script project is a payment template for P-256 (secp256r1) keys. A payer can create an output from the recipient’s public-key hash, and the recipient authorizes an ordinary spend with one device signature.

P2PKH-R1 是本仓库首个公开的脚本项目。收款方提供 P-256 公钥哈希即可收款，普通花费只需设备签名一次。目前处于开发者 RFC 阶段，提供 TypeScript、Rust 和 Go SDK。

[Project overview / 项目介绍](projects/p2pkh-r1/README.md) · [中文规范](docs/spec.zh-CN.md) · [English specification](docs/spec.en.md)
