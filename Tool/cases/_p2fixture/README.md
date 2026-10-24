# `_p2fixture` —— 阶段机 / WAIT_USER 回放夹具

**这是什么**：一个**完全离线**的「需要凭据的假目标」。它只有一个脚本
`Tool/cases/_p2fixture/target/fake_auth.py`，读一个环境变量、比对常量、打印一行结论、给退出码。
它存在的理由只有一个：给**阶段机与 WAIT_USER 回放**提供可复现样本 ——
没有样本，阶段机没法验自己会不会在「等用户输入凭据」这一步停住、能不能接回合法/非法两条路。

**它不是什么**：它不是真实产品的授权模块，输入值是虚构常量，与任何真实凭据无关；
脚本无网络调用、无文件写入、无子进程、无注册表操作。

## 三种用法（三条路都要能跑）

在仓库根目录执行（下面命令都是从仓库根写起的相对路径，换机器照抄即可）：

1. 合法卡 —— 应打印 `OK:authorized`，退出码 0

   ```bash
   CARD_CODE=TEST-CARD-0001 python Tool/cases/_p2fixture/target/fake_auth.py
   ```

2. 非法卡 —— 应打印 `DENY:invalid card`，退出码 1

   ```bash
   CARD_CODE=WRONG python Tool/cases/_p2fixture/target/fake_auth.py
   ```

3. 缺卡（不设环境变量）—— 应打印 `DENY:invalid card`，退出码 1

   ```bash
   python Tool/cases/_p2fixture/target/fake_auth.py
   ```

环境变量名按 `card_code` 读；Windows 环境变量大小写不敏感，`CARD_CODE` 同效（脚本两种拼写都查）。
需要看退出码时用 `; echo rc=$?`（bash）或 `; echo rc=$LASTEXITCODE`（PowerShell）。

## 回放时要验的三件事

- **停得住**：走到「需要凭据」这一步时，阶段机应停在 WAIT_USER，而不是自己编一个卡密
- **接得回**：用户给出合法卡后，流程从停点继续，且结论为 `OK:authorized`（rc=0）
- **拒得对**：非法卡与缺卡都必须走拒绝分支，结论 `DENY:invalid card`（rc=1），不得被当成成功

## 目录结构

```
Tool/cases/_p2fixture/
├── case.json                 案例元数据（evidence_kind = fixture）
├── README.md                 本文件
└── target/
    └── fake_auth.py          假目标：读卡片环境变量，打印 OK/DENY
```

目录名以 `_` 开头，案例索引生成器会跳过它（不进 `Tool/cases/index.json`），
所以它只是回放样本，不会被算成一个「真实案例」。

## 配套模板

回放产出的记录按这四份骨架写：

- `Tool/prompts/templates/triage.md` —— 六字段画像卡
- `Tool/prompts/templates/static.md` —— 静态记录 + 证据表
- `Tool/prompts/templates/dynamic.md` —— 动态记录 + 三列地址台账
- `Tool/prompts/templates/final.md` —— 交付与验收清单
