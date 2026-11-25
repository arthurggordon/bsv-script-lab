# /handoff · BSV Script Lab 签名实现

接手 Pure ML‑DSA‑44 开发线。统一实现及 BSV Node 1.2.3 独立交易验收已经完成。SM2 `SignedData` 互操作已拆分到 `feat/p2pkh-sm2-signeddata`。

## 接续工作区

在 `linzhm/bsv-script-lab` 检出 `feat/ml-dsa-44`，进入仓库根目录后先读 `AGENTS.md`。本分支以 `feat/wots-plus` 的提交 `d600ee81245c113311b3c80468aedf0264ade9ea` 为基线，包含完整的 ML‑DSA‑44 子项目和复现所需的共享代码。

## Pure ML‑DSA‑44

- `projects/ml-dsa/reference/script.py` 提供 `verify_message_script(public_key, message_bytes, context=...)`。公钥、消息字节长度和上下文在生成脚本时固定，消息和签名在执行时入栈。脚本使用 FIPS 204 的原始编码，公钥 1,312 字节，签名 2,420 字节。
- `locking_script(public_key)` 复用同一验签核心，以当前输入的 32 字节交易摘要和空上下文验签。`payment.py` 先核对资金输出和规范锁定脚本，再请求外部签名器。ForkID 与 Chronicle OTDA 共用一种锁定脚本，覆盖 12 种 sighash 模式。缺少同索引输出的 OTDA `SINGLE` 继续使用伴随 ForkID 绑定。
- Python 与 Script 的 `SampleInBall` 共用 FIPS 204 附录 C 的 221 字节预算。旧锁定模板、136 字节采样和双版本分派已从代码与文档移除。保留这一实现决策。交易自身的 `nVersion` 仍由验收矩阵分别覆盖。
- 标准测量向量的锁定脚本为 926,403 字节，普通单输入 ForkID `ALL` 的解锁脚本为 2,588 字节。该锁定脚本的 SHA‑256 为 `3905094cfb41cad09a939cfe8c8264400faf264a6db0cb30851c7dbdefd93295`。
- 已通过 NIST ACVP external Pure ML‑DSA‑44 15/15（Python 和 Script）、Wycheproof 80/80（Python），以及 `chain-gang` 和 `bsv-script-lean` 各 192 项完整交易检查。新增完整输入测试确认空消息、255 字节上下文及错误上下文的拒绝行为。
- 记录见 `projects/ml-dsa/README.md` 和 `shared/chronicle-regression.md`。Lean 使用 `Calhooon/bsv-script-lean@1c051eaef1077cc95e5d1618686d5efacc4aa097` 与 Lean 4.34.0。`shared/requirements-chronicle.txt` 给出可移植的 `chain-gang` 依赖。保留完整 Chronicle 上下文和 unpaired OTDA `SINGLE` 修复，避免退回仅有上下文 API 的构建。

## 复现与剩余门禁

在仓库根目录准备 Python 3.12、带 ML‑DSA 的 OpenSSL 3.5.9 或已验证的同等版本、更新过的 `chain-gang` 和已构建的 `bsvs`。将 ML‑DSA 版 OpenSSL 所在目录放到 `PATH` 中。所有签名用公开测试种子或隔离测试签名器。

```sh
python -m pip install -r shared/requirements-chronicle.txt
PYTHONPATH=.:projects/ml-dsa/reference python -m unittest -v \
  shared.test_layout test_mldsa test_challenge_script test_signature_script \
  test_shake_script check_chain_gang test_payment
ML_DSA_BSVS=/absolute/path/to/bsvs PYTHONPATH=.:projects/ml-dsa/reference \
  python -m unittest -v test_payment
```

ACVP 与 Wycheproof 的向量来源、固定版本和复现命令在 ML‑DSA README 中。临时下载及本地编译目录只供此前会话使用，接手后从链接重新获取。

`test_payment` 在提供 `REGTEST_COOKIE` 和 `REGTEST_URL` 时，会对同一 192 项矩阵调用 `verifyscript`，逐项比对结果及 flags。云端 Linux 已核实 `/Bitcoin SV:1.2.3/` 版本 `101020300`，192/192 项通过，正式共享启动脚本耗时 36.890 秒。锁定脚本为 926,403 字节，启动器必须保留 `-maxscriptsizepolicy=100000000`。

```sh
PYTHONPATH=.:projects/ml-dsa/reference \
  bash shared/verify_node_apple.sh ml-dsa-acceptance 18467 test_payment
```

节点、chain-gang 和 Lean 三条完整交易验收线均已完成。后续改动应继续保持统一 Pure ML‑DSA‑44 核心以及 221 字节采样预算。
