# BSV Script Lab

Public Bitcoin Script experiments on BSV, with inspectable programs, reference implementations and reproducible test vectors.

BSV 上 Bitcoin Script 的公开实验仓库。每个项目独立维护协议规范、参考实现、SDK 与测试向量；共享工具不定义项目的授权规则。

## Projects · 项目

| Project | Authorization | Resources | Status |
|---|---|---|---|
| [P2PKH-R1](projects/p2pkh-r1/README.md) | secp256r1 / P-256 ECDSA | TypeScript, Rust, Go SDKs; Python reference; ForkID and OTDA | Developer RFC |
| [P2PKH-SM2](projects/p2pkh-sm2/README.md) | curveSM2 + SM3 + ZA | Python payment API; generated Bitcoin Script; standard and payment vectors | Experimental v1; ForkID ALL |

P2PKH-SM2 是第二个项目：付款方只需收款方公钥哈希即可创建输出；收款方使用 SM2 签名授权当前花费。链上脚本执行 SM3、ZA 和 SM2 验签，通过原生 secp256k1 `OP_CHECKSIG` 的公开 PUSHTX 构造绑定当前交易。

## Repository layout · 目录约定

| Path | Responsibility |
|---|---|
| `projects/<name>/README.md` | 项目入口、状态、使用说明 |
| `projects/<name>/docs/` | 协议与集成规范 |
| `projects/<name>/reference/` | 脚本、参考钱包、生成器、测试 |
| `projects/<name>/template/` | 布局指纹和可复现向量；大脚本可由生成器导出 |
| `projects/<name>/sdk/` | 已实现的语言 SDK；R1 提供 TypeScript / Rust / Go |
| [shared/](shared/README.md) | 通用编码、开发测试工具和节点验证启动器 |
| `.github/workflows/<name>.yml` | 按项目触发的验证流水线 |

The former top-level `docs/`, `reference/`, `sdk/` and `template/` directories belong to R1 and now live under `projects/p2pkh-r1/`. R1 script bytes and payment vectors are unchanged. Go imports now use `github.com/linzhm/bsv-script-lab/projects/p2pkh-r1/sdk/go`.

原根目录下的 R1 文件已整体迁入项目目录。R1 协议、脚本字节和支付向量保持不变；文件路径与 Go 模块导入路径随目录更新。

## Local checks · 本地验证

```sh
python3 -m pip install ecdsa==0.19.1
python3 -m unittest shared.test_layout -v
python3 -m unittest discover -s projects/p2pkh-sm2/reference -p test_sm2.py -v
```

OpenSSL with SM2/SM3 support is required for the interoperability test. Follow each project's reference guide for complete-input BSV Node and chain-gang verification.
