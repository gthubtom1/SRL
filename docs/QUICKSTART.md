# 5 分钟快速路径（新 agent / 换会话先看这个）

> 目标：**5 分钟内跑出第一条有效结论**，不被 110 条门禁和 30 个技能吓住。
> 详细契约见 `docs/DOMAIN-SPEC-v2.md`；接力棒见 `ROADMAP.md`；差分见 `docs/UPSTREAM.md`。

## 0. 一条命令确认环境（10 秒）

```bash
cd <repo>
python Tool/scripts/env-check.py --text     # 缺什么会直接说，并给安装命令
```

## 1. 一条命令开一个案子（30 秒）

```bash
python Tool/scripts/seep-start.py --domain <域> --case <案子名> [--target <样本/网址>]
```

- `<域>` ∈ `web-pentest` `pwn-crypto` `firmware-iot` `ad-cloud` `protocol-plugin`
  `plugin-targets` `forensics-mobile` `malware-analysis` `supply-chain-security` `reverse` `site-clone`
- 它会：建 `Tool/cases/<案子名>/`、建 `evidence/<案子名>/`、打印该域**下一步 3 条命令**。

## 2. 读一张卡就动手（不读整本技能）

```bash
ls Tool/prompts/domains/<域>.md          # 24 张卡，每张=触发词/前置/步骤/判据/失败判据/reference
```

挑一张与目标最像的卡，照「步骤」里的命令跑；判据不成立就看该卡指向的 `references/02-failure-criteria.md` 换路。

## 3. 三条最常用的入口

| 场景 | 命令 |
| :-- | :-- |
| 不知道目标是什么 | `python Tool/skill/softseep/scripts/preflight-classify.py <样本>`（逆向域） |
| 网站/接口基线 | `python Tool/skill/web-pentest/scripts/web-check.py --url <URL>` |
| 网站 1:1 复刻 | `python Tool/skill/site-clone/scripts/site-crawl.py --url <URL> --out <目录>` |

## 4. 交付前只跑这两条

```bash
python Tool/scripts/domain-gate.py --domain <域>     # 本域 7 条
python Tool/scripts/preflight.py --fast              # 全局（悬空引用/篇幅/路由/清理）
```

## 5. 常见卡点（先看这里，别硬猜）

| 现象 | 处理 |
| :-- | :-- |
| 工具找不到 | `python Tool/scripts/mcp-doctor.py --fix` 或 `tool-run.ps1 -Tool <id>` |
| 门禁说「案例 sha256 不符」 | 先 `git status` 看是否换行符漂移；案例证据按字节保存（`-text`），不要手改产物 |
| 路由把任务分错域 | 看 `Tool/scripts/routing.json` 的 priority；改路由只走主分支 |
| 不知道用哪篇 reference | 该域 `references/01-criteria.md` 顶部的「场景 → 判据」表 |
