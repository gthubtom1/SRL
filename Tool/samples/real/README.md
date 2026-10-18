# 真实第三方样本（Third-party Real Samples）

> 本目录收录**来源明确、许可证宽松（MIT）**的公开逆向练习样本，随仓库一起分发，
> 保证你换电脑/仓库重建后仍有一套真实样本可用（不只是自造样本）。
> 本仓库为**个人自用**（公开仅为规避私有库流量限制），样本策略：**真实 crackme/教学样本应收尽收**（含无许可证的，因为自用不分发）；**恶意样本（真病毒/木马）绝不收录**（安全风险，非许可证问题）。

## 收录清单

| 子目录 | 来源仓库 | 许可证 | 内容 | 用来测什么 |
|---|---|---|---|---|
| `crackerjack/` | [jmcph4/crackerjack](https://github.com/jmcph4/crackerjack) | **MIT** | 4 个 crackme（a~d，难度递增），含源码 `.c` + 编译好的 `.exe` | 基础 PE 反编译、字符串、判壳、`seep_decompile_auto` |
| `maxxor-keygenme-v7/` | [MaxXor/keygenme-v7](https://github.com/MaxXor/keygenme-v7) | **MIT** | 真实 KeygenMe（自修改代码 + 方法 Hook + 注入类 API），含 `.exe` + 完整 C++ 源码 | `seep_packer_detect` 识别注入/自修改特征；`seep_mem_strings` 内存取证 |
| `noracodes-crackmes/` | [NoraCodes/crackmes](https://github.com/NoraCodes/crackmes) | 教学用途（作者公开供学习） | 17 个 crackme（crackme01~09 及 e 变体），含源码 `.c` + 编译 `.exe` | 基础 PE 反编译、字符串、判壳、`seep_decompile_auto`、逐级难度练习 |
| `monologix-crackmes/` | [Monologix/Monologix-Crackmes](https://github.com/Monologix/Monologix-Crackmes) | 教学用途 | 4 个 Windows PE crackme + 3 个 Linux ELF crackme（32/64 位混合） | PE/ELF 双格式、32位/64位、判壳、反编译 |
| `dotnet-crackmes/` | [mrhery/CrackMe](https://github.com/mrhery/CrackMe) | **GPL-3.0** | 5 个 .NET (CLR) 授权练习（本地文件/枚举/远程/注册码/试用） | .NET 识别、dnSpy/ILSpy 靶子、dotnet 降级链 |
| `android-apks/` | [ev-flow/apk-samples](https://github.com/ev-flow/apk-samples) | 教学靶场 | 6 个经典 Android 漏洞靶场 APK（DIVA/InsecureBankv2/AndroGoat/allsafe/OVAA/Vuldroid） | `seep_apk_info/decompile/unpack/smali_search` 真实 APK 验证 |
| `js-obfuscated/` | [kuizuo/js-deobfuscator](https://github.com/kuizuo/js-deobfuscator) | **MIT** | 9 组真实 Web/JS 混淆样本（obfuscator.io + 猫眼/网易/拼多多等真实站点，含 input/output） | JS 逆向、AST 去混淆、js-reverse-mcp 运行时采样 |
| `protocol-pcaps/` | [wireshark/wireshark](https://github.com/wireshark/wireshark) | **GPL-2.0** | HTTP/HTTP2/WebSocket/DNS/TCP 真实 pcap | `seep_pcap_extract` 三模式验证、`seep_http_replay` 金样重放 |

## 样本策略（个人自用）

本仓库是**个人自用**（公开仅为绕过私有库流量限制），所以：
- ✅ **真实 crackme / 教学样本应收尽收**（含无许可证的，因为不分发给第三方，仅自己用）；
- ❌ **恶意样本（真病毒/木马/勒索软件）绝不收录**——不是许可证问题，是**安全风险**（怕哪天被自动执行）。

> 如果你要练恶意样本分析，把样本放本地 `work/`（gitignore），用 `SEEP_TEST_PE` 喂给测试即可。

## 复现与验证

```powershell
# 这些 .exe 已随仓库提供，可直接用扩展工具分析：
cd ../../mcp
python -c "import seep_mcp_server as s; print(s.seep_packer_detect(r'../samples/real/maxxor-keygenme-v7/KeygenMe V7.exe'))"
```

## 许可声明

- `crackerjack/` 与 `maxxor-keygenme-v7/` 的原始代码/二进制版权归其作者所有，遵循各自目录下的 `LICENSE`（均为 MIT）。
- 本仓库仅为**教学/测试用途**收录，未修改原始二进制；如作者有异议可移除。
