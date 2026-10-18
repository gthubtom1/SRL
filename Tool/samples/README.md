# 实战样本库（Self-contained Practice Samples）

> 用途：给 `seep_pe_resources` / `seep_packer_detect` / `seep_decompile_auto` / `seep_mem_strings`
> 等扩展工具提供**可复现、自包含、无版权风险**的测试与练习样本。
> 这些样本全部**从源码现场编译**，不引入任何第三方二进制，仓库干净、可审计、可重建。

## 一、为什么这样做（而不是直接下载别人的 exe）

1. **版权/合规**：直接打包别人的 exe（crackme 站点、恶意样本库）有版权与恶意软件传播风险；
   本仓库是 GPL-3.0 开源项目，不能夹带来源不明的二进制。
2. **可复现**：从源码编译 → 任何人 `make` 一下就能得到同样样本，结果可核对。
3. **可控**：我们可以自己写"故意带反调试/高熵资源"的样本，精准测到扩展工具的每条路径。

> **另见 `real/` 目录**：收录了 MIT 许可的真实第三方样本（crackerjack 4 个 crackme + MaxXor KeygenMe V7），
> 随仓库分发，保证换机/仓库重建后仍有真实样本可用。详见 [`real/README.md`](real/README.md)。

## 二、样本清单（源码在 `src/`）

| 样本 | 源码 | 测什么 |
|---|---|---|
| `crackme_basic.exe` | `src/crackme_basic.c` | 基础 PE 反编译、字符串、判壳（无壳） |
| `antidebug_demo.exe` | `src/antidebug_demo.c` | `seep_packer_detect` 识别反调试导入（IsDebuggerPresent 等） |
| `resource_blob.exe` | `src/resource_blob.c` + 资源 | `seep_pe_resources` 枚举高熵资源 |

## 三、如何重建（Windows + MinGW/gcc）

```powershell
cd Tool/samples
powershell -File build.ps1      # 或手动：gcc -O2 -o crackme_basic.exe src/crackme_basic.c
```

> 无 gcc 时，这些样本可跳过（扩展工具本身不依赖它们，测试里用仓库内置的
> `Tool/mcp/Tool/safe/radare2/bin/r2agent.exe` 作为 PE 回退）。

## 四、来源与许可

- 全部为本仓库原创源码（GPL-3.0），无第三方二进制。
- 设计思路参考公开逆向教学（crackme 概念、反调试 API 用途），但不复制任何他人代码/二进制。

## 五、扩展：想用真实第三方样本时

如果确实需要更多真实样本（如带壳/混淆的商业程序），**不要**把它们提交进本仓库，而是：
1. 在本地 `work/` 目录（已 gitignore）下载/放置；
2. 通过环境变量 `SEEP_TEST_PE=/path/to/sample.exe` 喂给 `test_ext_assets.py`；
3. 参考 [`Tool/docs/MERGE-PLAYBOOK.md`](../docs/MERGE-PLAYBOOK.md) 的"外部样本不进仓库"原则。
