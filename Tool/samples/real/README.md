# 真实第三方样本（Third-party Real Samples）

> 本目录收录**来源明确、许可证宽松（MIT）**的公开逆向练习样本，随仓库一起分发，
> 保证你换电脑/仓库重建后仍有一套真实样本可用（不只是自造样本）。
> **每一个子目录都带原始 LICENSE，来源与许可见下表。绝不收录无许可证或恶意样本。**

## 收录清单

| 子目录 | 来源仓库 | 许可证 | 内容 | 用来测什么 |
|---|---|---|---|---|
| `crackerjack/` | [jmcph4/crackerjack](https://github.com/jmcph4/crackerjack) | **MIT** | 4 个 crackme（a~d，难度递增），含源码 `.c` + 编译好的 `.exe` | 基础 PE 反编译、字符串、判壳、`seep_decompile_auto` |
| `maxxor-keygenme-v7/` | [MaxXor/keygenme-v7](https://github.com/MaxXor/keygenme-v7) | **MIT** | 真实 KeygenMe（自修改代码 + 方法 Hook + 注入类 API），含 `.exe` + 完整 C++ 源码 | `seep_packer_detect` 识别注入/自修改特征；`seep_mem_strings` 内存取证 |

## 为什么只收 MIT

本仓库是 **GPL-3.0**。收录第三方样本必须**许可证兼容**：
- MIT 允许再分发与修改（保留版权声明即可）→ 可收。
- 大量 crackme 站点（crackmes/crackmes、NoraCodes/crackmes 等）**无许可证（NO-LICENSE）** → 默认版权保留，**不能**随 GPL 仓库再分发。
- 恶意样本库（jstrosch/malware-samples 等）→ 法律+安全风险，**绝不入库**。

所以本目录只收 **MIT 许可**的样本；无许可的真实样本请放本地 `work/`，用 `SEEP_TEST_PE` 环境变量喂给测试（见 `../README.md` §五）。

## 复现与验证

```powershell
# 这些 .exe 已随仓库提供，可直接用扩展工具分析：
cd ../../mcp
python -c "import seep_mcp_server as s; print(s.seep_packer_detect(r'../samples/real/maxxor-keygenme-v7/KeygenMe V7.exe'))"
```

## 许可声明

- `crackerjack/` 与 `maxxor-keygenme-v7/` 的原始代码/二进制版权归其作者所有，遵循各自目录下的 `LICENSE`（均为 MIT）。
- 本仓库仅为**教学/测试用途**收录，未修改原始二进制；如作者有异议可移除。
