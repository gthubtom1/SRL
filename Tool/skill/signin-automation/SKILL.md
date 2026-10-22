---
name: signin-automation
description: "账号任务自动化的六个原语：会话池、定时通知、验证码分支、滑块缺口、旋转角度、TLS 指纹。供 playbook（qinglong-signin / multi-account-runner）组合调用。"
---

# signin-automation（原语层）

> 本目录只提供脚本原语；任务编排见 `Tool/playbooks/qinglong-signin.md` 与 `multi-account-runner.md`。
> 执行范围由用户提供的 `scope` 决定：目标、账号、速率、通知渠道均为输入。

## 原语

| 脚本 | 作用 | self-test |
| :-- | :-- | :-- |
| `scripts/session-pool.py` | 多账号凭据池（cookie/token/device_id），状态 ok/expired/blocked，失效标记 | rc=0 |
| `scripts/schedule-notify.py` | cron 校验、幂等键（日期+账号+任务）、重试上限、三种通知载荷 | rc=0 |
| `scripts/captcha-branch.py` | 三条处置：ocr / interactive / manual，输出 `next_action` | rc=0 |
| `Tool/scripts/captcha-gap.py` | 滑块缺口定位：Sobel+NCC，输出 `x` 与 `confidence` | rc=0（<0.35 时 rc=3） |
| `Tool/scripts/captcha-angle.py` | 旋转角度求解：粗搜+细搜，输出 `angle`/`angle_mod90` | rc=0（<0.35 时 rc=3） |
| `scripts/tls-fingerprint.py` | JA3/JA4 → curl_cffi impersonate、header 顺序、H2 开关的请求计划 | rc=0 |

## 判据

- 会话池：每个账号有独立凭据与状态；过期账号必须被标记并停止重试。
- 定时：同一幂等键重复执行只产生一次副作用。
- 验证码：三条处置任一必须给出可执行的下一步，且记录所选项。
- 指纹：请求计划里的 impersonate/头序/H2 与目标观测一致。
- 滑块：`gap.json` 的 `confidence >= 0.55` 才直接提交；0.35–0.55 用 ±2px 试探；<0.35 换图或人工。
- 旋转：`angle.json` 的 `confidence >= 0.6` 直接提交；对称图只看 `angle_mod90`，需要唯一角必须有方向线索。

## 失败判据

- 账号全部 blocked → 换登录方式或交人工，不空转重试。
- cron 表达式非法 → 回退到 `--dry-run` 打印计划。
- 验证码分支无法判定 → 记录响应特征，交 manual。
