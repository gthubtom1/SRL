# pwn-crypto 任务卡（24 张）

> 源技能名取自 `Tool/config/taskcard-sources.json` 的 `pwn-crypto` 键（24 条，逐条对应）。
> 每张卡固定六段：触发词 / 前置 / 步骤 / 判据 / 失败判据 / reference。
> 只用于授权实验室资产；涉及生产系统的条目只做检测/原理验证，不做破坏性操作。
> 统一入口：`Tool/skill/pwn-crypto/SKILL.md`；机检：`python Tool/scripts/domain-gate.py --domain pwn-crypto`。

### 01 栈溢出偏移与 saved RIP 控制（源：performing-binary-exploitation-analysis）
- 触发词：栈溢出、gets、strcpy、返回地址、cyclic、offset
- 前置：本地 PE/ELF + 编译选项已知；`pwn-check.py` 已给出 NX/PIE/Canary。
- 步骤：1) `python Tool/scripts/pwn-check.py --file ./chall --json > pwn_check.json`（期望 rc=0，`protections` 四项齐）；2) `objdump -d -M intel ./chall > d.txt`（rc=0）并取 `lea -0x..(%rbp)`；3) `python Tool/skill/pwn-crypto/scripts/pwn-repro.py --objdump d.txt --func vuln --probe-log probe.txt --json > repro.json`（期望 rc=0 且 `consistent=true`）；4) `python exploit.py`（期望 rc=0，stdout 含目标 marker）。
- 判据：三条命令 rc=0；`repro.json` 的 `consistent=true` 且两源 `offset` 相同；marker 出现且 rc=0（只有崩溃不算）。
- 失败判据：`pwn-repro` rc=1/`offset-mismatch`，或 exploit rc≠0 且无 marker → 先统一 `-O0 -fno-stack-protector -no-pie` 重测，见 `02-failure-criteria.md` #1/#2。
- reference：Tool/skill/pwn-crypto/references/04-walkthrough-local-pe.md

### 02 堆喷射与 tcache 布局测量（源：analyzing-heap-spray-exploitation）
- 触发词：堆喷射、heap spray、tcache、chunk 布局、malloc/free
- 前置：确认 glibc 版本与分配器；有菜单式 alloc/free/show。
- 步骤：1) `python Tool/scripts/pwn-check.py --file ./chall --json`（rc=0）；2) `strings -a libc.so.6 | grep -m1 'GNU C Library'`（rc=0，记版本/build id）；3) `gdb -q -batch -ex 'b malloc' -ex run -ex 'vis_heap_chunks' ./chall`（rc=0）；4) `for i in $(seq 10); do ./exploit.py >/tmp/r.$i 2>&1; echo $?; done`（期望 ≥9 次 rc=0 且 `malloc` 返回 target）。
- 判据：`vis_heap_chunks` 见重复/重叠 chunk；10 次中 ≥9 次 `malloc` 返回受控 target；全程无 `abort`。
- 失败判据：`free(): invalid pointer`/abort、count 已满、target 未 0x10 对齐 → 见 `02-failure-criteria.md` #7；2.34+ 放弃 hook，转 `heap-and-sandbox.md` §6。
- reference：Tool/skill/pwn-crypto/references/heap-and-sandbox.md

### 03 利用模块选择与本地复现（源：exploiting-vulnerabilities-with-metasploit-framework）
- 触发词：metasploit、exploit 模块、payload、本地复现
- 前置：授权隔离靶机；模块与目标版本匹配；有回滚/快照。
- 步骤：1) 先手工确认漏洞点与保护位；2) 选模块后核对 target/offset；3) 本地快照上跑一次；4) 记录 rc、会话与失败原因。
- 判据：本地隔离环境可重复命中；模块参数与手工分析一致。
- 失败判据：只靠模块默认参数、无手工判据 → 视为“疑似”，退回手工验证。
- reference：Tool/skill/pwn-crypto/references/binary-exploitation.md

### 04 反序列化原语到代码执行的判据（源：exploiting-insecure-deserialization）
- 触发词：反序列化、deserialization、gadget chain、对象注入
- 前置：确认序列化格式（Java/PHP/Python/.NET）与可控字段；有本地解析器。
- 步骤：1) 定位反序列化入口；2) 构造最小对象验证类型/字段可控；3) 找一条 gadget 链到可观测副作用；4) 记录依赖版本。
- 判据：最小对象能改变程序行为（文件/命令/回显）；链在目标版本成立。
- 失败判据：只在本地版本成立、目标依赖不同 → 换链或降级为“类型可控”结论。
- reference：Tool/skill/pwn-crypto/references/01-criteria.md

### 05 类型混淆/整数比较绕过的二进制验证（源：exploiting-type-juggling-vulnerabilities）
- 触发词：type juggling、类型混淆、宽松比较、整数截断
- 前置：能拿到比较点反汇编或源码；知道输入类型。
- 步骤：1) 找 `==`/`strcmp`/长度比较；2) 用 z3 或边界值验证绕过；3) 观察分支是否真的走通；4) 记录 payload 与 rc。
- 判据：输入使校验分支走通且后续行为改变；不是仅“理论可绕”。
- 失败判据：只证明比较表达式有歧义、无运行时分支变化 → 降级为“疑似”。
- reference：Tool/skill/pwn-crypto/references/01-criteria.md

### 06 模板注入到命令执行的验证（源：exploiting-template-injection-vulnerabilities）
- 触发词：SSTI、模板注入、表达式求值、命令执行
- 前置：确认模板引擎与可控参数；有本地同版本服务。
- 步骤：1) 用算术表达式确认求值；2) 逐级升级到对象/函数访问；3) 用无害命令（`id`/`echo`）验证；4) 记录引擎版本。
- 判据：模板输出出现求值结果；无害命令回显可复现。
- 失败判据：只看到模板报错、无求值证据 → 转 Web 域或继续找入口。
- reference：Tool/skill/pwn-crypto/references/01-criteria.md

### 07 竞态窗口测量与可复现性（源：exploiting-race-condition-vulnerabilities）
- 触发词：竞态、race condition、TOCTOU、窗口
- 前置：本地可并发运行；有可观测的成功/失败标志。
- 步骤：1) 先串行确认逻辑；2) 加并发并统计成功次数；3) 测窗口大小；4) 至少 100 次统计成功率。
- 判据：成功率可量化，且失败原因可解释（窗口/调度）。
- 失败判据：偶发一次成功就写“可复现” → 不成立，重跑统计。
- reference：Tool/skill/pwn-crypto/references/02-failure-criteria.md

### 08 原型污染到运行时对象篡改（源：exploiting-prototype-pollution-in-javascript）
- 触发词：原型污染、prototype pollution、__proto__、客户端
- 前置：确认 JS 运行时与可控 merge/parse 入口；有本地页面或 node 脚本。
- 步骤：1) 注入 `__proto__` 观察对象属性；2) 找被污染的属性影响的分支；3) 在本地运行时复现；4) 判断是否越界到 pwn 域。
- 判据：运行时对象属性被改且影响可观测行为。
- 失败判据：只是 payload 被接受、无行为变化 → 转 Web/JS 域，不冒充 pwn。
- reference：Tool/skill/pwn-crypto/references/03-model-pitfalls.md

### 09 口令哈希识别与真实回代（源：performing-hash-cracking-with-hashcat）
- 触发词：hashcat、口令哈希、NTLM、bcrypt、字典
- 前置：有授权哈希样本；知道算法/盐/迭代；不碰真实生产凭据。
- 步骤：1) `hashid -m '<hash>'`（rc=0，得 hashcat 模式号）；2) `hashcat -m <mode> -a 0 hash.txt wordlist.txt --potfile-disable -o cracked.txt`（rc=0=已破解，rc=1=字典耗尽，rc=255=参数/设备错）；3) 回代 `python -c "import hashlib;assert hashlib.<alg>(b'<plain>').hexdigest().lower()=='<hash>'"`（rc=0）；4) 记耗时/成功率。
- 判据：hashcat rc=0 且 `cracked.txt` 有明文；回代 `assert` rc=0；不是“看起来像密码”。
- 失败判据：hashcat rc=1 只能写“字典未命中”，不得写“强口令”；回代失败即该明文作废 → 换规则/掩码，仍失败如实写“未解出”。
- reference：Tool/skill/pwn-crypto/references/crypto-attacks.md

### 10 密码学实现审计（模式/IV/填充）（源：performing-cryptographic-audit-of-application）
- 触发词：密码学审计、ECB、CBC、IV、padding、密钥管理
- 前置：能拿到实现或密文样本；知道威胁模型。
- 步骤：1) 列算法/模式/IV 来源；2) 做相同明文块对照；3) 检查 IV 重用与填充错误粒度；4) 用 `crypto-verify.py` 回代。
- 判据：块关系/位翻转/回代等式成立；结论能落到具体字节。
- 失败判据：只凭“用了 AES”就判安全/不安全 → 判据不足。
- reference：Tool/skill/pwn-crypto/references/crypto-attacks.md

### 11 RSA 密钥生成与参数校验（源：implementing-rsa-key-pair-management）
- 触发词：RSA、密钥生成、e=65537、p/q、模数
- 前置：本地 Python/pycryptodome；仅生成测试密钥。
- 步骤：1) 生成素数并验证 `p*q==n`；2) 检查 `gcd(e,φ(n))==1`；3) 用 `pow(m,e,n)` 回代；4) 记录 key size 与来源。
- 判据：`p*q==n`、私钥回代成立、e 与 φ 互质。
- 失败判据：共享素数/小私钥未检查 → 用 gcd/Wiener 复核后再用。
- reference：Tool/skill/pwn-crypto/references/crypto-attacks.md

### 12 AES 模式选择与 IV/认证（源：implementing-aes-encryption-for-data-at-rest）
- 触发词：AES、GCM、CBC、IV、认证加密、at rest
- 前置：本地 pycryptodome；有明文/密钥测试向量。
- 步骤：1) `python Tool/skill/pwn-crypto/scripts/crypto-verify.py --ecb inputs/ecb.json`（期望 rc=0，`duplicate_blocks>=1`）；2) `... --cbc inputs/cbc.json`（期望 rc=0，`verified=true`）；3) 篡改 GCM tag 后解密（期望抛 `InvalidTag`，即 rc≠0 才是对的行为）。
- 判据：1)/2) rc=0 且 `verified=true`；ECB 重复块与 CBC `before^after==xor` 均落到具体字节；tag 篡改必须失败。
- 失败判据：ECB `duplicate_blocks=0`（随机碰撞）→ 用 `'A'*32` 对照重测；CBC 差值与 xor 不符 → 查改的是 C[i-1]/IV；tag 篡改仍解密成功 → 记设计缺陷，不算“利用成功”。
- reference：Tool/skill/pwn-crypto/references/crypto-attacks.md

### 13 PQC 迁移风险清单（源：performing-post-quantum-cryptography-migration）
- 触发词：PQC、后量子、迁移、混合密钥、签名
- 前置：有算法清单与数据生命周期；不接触生产密钥。
- 步骤：1) 盘点 RSA/ECC 使用点；2) 标注 harvest-now-decrypt-later 风险；3) 设计混合方案；4) 用测试向量验证互操作。
- 判据：迁移清单覆盖密钥交换/签名/证书；测试向量通过。
- 失败判据：只换算法不改证书链/协议 → 迁移未完成。
- reference：Tool/skill/pwn-crypto/references/crypto-attacks.md

### 14 混合密钥交换/签名验证（源：migrating-to-post-quantum-cryptography）
- 触发词：混合密钥、KEM、签名迁移、互操作
- 前置：本地测试环境；有双方实现版本。
- 步骤：1) 固定测试向量；2) 跑经典+PQ 双栈；3) 验证降级/失败路径；4) 记录版本矩阵。
- 判据：双方互操作成功；降级路径可检测。
- 失败判据：只测一端、或降级被静默接受 → 安全结论不成立。
- reference：Tool/skill/pwn-crypto/references/01-criteria.md

### 15 JWT alg 混淆（RSA→HMAC）（源：exploiting-jwt-algorithm-confusion-attack）
- 触发词：JWT、alg confusion、RS256、HS256、公钥
- 前置：授权测试环境；有公钥与签名校验代码。
- 步骤：1) 解析 header/alg；2) 用公钥做 HMAC 密钥伪造 token；3) 观察服务端是否接受；4) 记录库版本。
- 判据：服务端接受伪造 token 且能访问受保护资源。
- 失败判据：只改 alg 未重签、或服务端校验失败 → 不算成立。
- reference：Tool/skill/pwn-crypto/references/01-criteria.md

### 16 JWT none/签名剥离（源：performing-jwt-none-algorithm-attack）
- 触发词：JWT none、签名剥离、alg=none
- 前置：授权测试环境；抓到一枚有效 token。
- 步骤：1) `python -c "import base64,json;h=open('hdr.b64').read();print(json.loads(base64.urlsafe_b64decode(h+'==')))"`（rc=0，得 alg/kid）；2) 造 `alg=none` 空签名 token（rc=0）；3) `curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOK" http://127.0.0.1:8000/admin`（期望 200）；4) 对照：不带头请求同一 URL（期望 401）。
- 判据：伪造 token 得 200 且响应体含受保护资源；无 token 得 401（证明鉴权分支确实在跑）；两请求 curl rc=0。
- 失败判据：返回 401/403 → 结论“已修复”，写清服务端是否解析 `alg`；只在前端解码成功、服务端拒收不算成立。
- reference：Tool/skill/pwn-crypto/references/01-criteria.md

### 17 JWT 测试矩阵（弱密钥/过期/声明）（源：testing-jwt-token-security）
- 触发词：JWT 测试、弱密钥、过期、aud/iss、kid
- 前置：授权环境；有签发与校验两端。
- 步骤：1) 测弱 HMAC 密钥；2) 测过期/未生效；3) 测 aud/iss/kid 注入；4) 记录每项结果。
- 判据：每项都有请求/响应证据；弱密钥能回代签名。
- 失败判据：只跑工具不核对响应语义 → 误报。
- reference：Tool/skill/pwn-crypto/references/01-criteria.md

### 18 永恒之蓝漏洞验证（授权隔离）（源：exploiting-ms17-010-eternalblue-vulnerability）
- 触发词：MS17-010、永恒之蓝、SMB、隔离靶机
- 前置：仅隔离实验网；有快照；禁止生产/公网。
- 步骤：1) 确认 SMB 版本与补丁级别；2) 用检测脚本/模块验证可达性；3) 记录流量与结果；4) 立即回滚。
- 判据：隔离环境可重复验证；检测证据完整。
- 失败判据：无隔离、无授权、或造成破坏 → 立即停止，不做“再试一次”。
- reference：Tool/skill/pwn-crypto/references/02-failure-criteria.md

### 19 Zerologon 原理与检测（源：exploiting-zerologon-vulnerability-cve-2020-1472）
- 触发词：Zerologon、CVE-2020-1472、Netlogon、检测
- 前置：仅授权 AD 实验域；有域控快照；只做检测/原理验证。
- 步骤：1) 确认补丁级别；2) 用检测脚本验证脆弱性；3) 记录事件日志；4) 给出修复建议。
- 判据：检测结果与补丁/日志一致；不执行破坏性重置。
- 失败判据：对生产域控操作、或无法回滚 → 停止，交 AD 域处理。
- reference：Tool/skill/pwn-crypto/references/01-criteria.md

### 20 NoPac 原理与检测（源：exploiting-nopac-cve-2021-42278-42287）
- 触发词：NoPac、CVE-2021-42278、CVE-2021-42287、AD 检测
- 前置：授权 AD 实验域；有快照；只做检测。
- 步骤：1) 核对补丁；2) 复现原理（机器账户名/票据）；3) 记录日志；4) 输出修复项。
- 判据：检测证据可复现；未越权到生产。
- 失败判据：无隔离/无授权 → 停止，交 ad-cloud 域。
- reference：Tool/skill/pwn-crypto/references/02-failure-criteria.md

### 21 移动端不安全存储（边界）（源：exploiting-insecure-data-storage-in-mobile）
- 触发词：移动端存储、SharedPreferences、Keychain、明文
- 前置：授权测试设备/APK；只读分析。
- 步骤：1) 定位存储文件；2) 检查明文/弱加密；3) 用 `hashlib` 回代若涉及哈希；4) 判断归属域。
- 判据：敏感数据可读且有来源路径；哈希可回代。
- 失败判据：需要脱壳/动态注入 → 交 `apkseep`/`forensics-mobile`，不在本域硬做。
- reference：Tool/skill/pwn-crypto/references/03-model-pitfalls.md

### 22 智能合约整数/重入（EVM 视角）（源：analyzing-ethereum-smart-contract-vulnerabilities）
- 触发词：智能合约、Solidity、重入、整数溢出、EVM
- 前置：本地链/测试网；有合约源码与测试账户。
- 步骤：1) 找外部调用与状态更新顺序；2) 构造重入/溢出用例；3) 在本地链跑交易；4) 记录 gas 与状态变化。
- 判据：交易成功且状态被非预期改变；有交易哈希。
- 失败判据：只在理论层面、无本地链证据 → 降级为“疑似”。
- reference：Tool/skill/pwn-crypto/references/01-criteria.md

### 23 Foundry 测试与断言（源：auditing-foundry-smart-contract-security）
- 触发词：Foundry、forge test、断言、模糊测试
- 前置：本地 Foundry 工程；合约可编译。
- 步骤：1) 写失败即回滚的断言；2) `forge test -vvv` 跑；3) 加 fuzz/invariant；4) 记录输出。
- 判据：测试输出可复现；断言覆盖目标不变量。
- 失败判据：测试只验证“能编译”、无断言 → 不算审计证据。
- reference：Tool/skill/pwn-crypto/references/01-criteria.md

### 24 SSRF 到内网访问的验证（边界）（源：performing-ssrf-vulnerability-exploitation）
- 触发词：SSRF、内网、回环、元数据、URL 白名单
- 前置：授权测试环境；有可控 URL 参数；禁止访问真实云元数据。
- 步骤：1) 用回环/自建服务验证请求；2) 测协议/重定向绕过；3) 记录请求日志；4) 判断归属域。
- 判据：服务端确实发起请求（日志/回显）；不触碰真实内网资产。
- 失败判据：只看到错误页、无请求证据 → 不成立；真实生产目标立即停止，交 Web 域。
- reference：Tool/skill/pwn-crypto/references/02-failure-criteria.md
