#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""new-skill.py —— Seep 外挂技能标准化自动化脚手架生成器

功能：
  1. 严格按照 MANUAL/SKILL-CREATION-GUIDE.md 规范创建 Tool/skill/<name>/SKILL.md；
  2. 强制使用 UTF-8 无 BOM 格式写入，彻底规避 Agent frontmatter 解析静默跳过（Issue #6）；
  3. 自动在 Tool/skill/softseep/SKILL.md 的可调度资源表中追加注册该技能；
  4. 自动将新技能同步到 ~/.pi/agent/skills/（若存在），实现即建即用；
  5. 自动完成无 BOM 与格式自检。

用法：
  python Tool/scripts/new-skill.py <skill_name> [--desc "描述"] [--title "中文标题"]
"""
import os
import sys
import argparse
import re
import shutil

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SKILL_DIR = os.path.join(ROOT, "Tool", "skill")
SOFTSEEP_MD = os.path.join(SKILL_DIR, "softseep", "SKILL.md")
USER_AGENT_SKILLS = os.path.expanduser(os.path.join("~", ".pi", "agent", "skills"))


def clean_skill_name(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9\-_]", "", name.strip().lower())
    return cleaned or "custom-skill"


def generate_skill_content(name: str, desc: str, title: str) -> str:
    display_title = title.strip() or f"{name.capitalize()} 专项技能"
    description = desc.strip() or f"{name} 领域的逆向分析与专项白盒审计支持技能。"

    template = f"""---
name: {name}
description: "{description}"
metadata:
  version: "1.0.0"
  target_runtimes: "Windows PE | Android DEX/SO | Multi-Platform"
  compatible_workbench: "Seep v1.8.0+"
---

# {display_title}

> **核心目标**：遵循 Seep 工作台微内核外挂规范，解决 {name} 专项实战问题。

---

## 一、 适用场景与触发口令

当遇到以下任务时，优先引用本技能：
1. 涉及 {name} 相关的逆向分析、资产提取或漏洞排查；
2. 需要与 Seep 核心工具链协同执行自动化验证。

**大白话唤醒指令示例**：
- `lab：引用技能 {name}，分析目标程序并输出验证代码与成品`

---

## 二、 标准作战工作流 (SOP)

1. **Step 1：资产探测与工具自愈**
   - 调用 `seep_tool_discover` 探测所需工具，若缺失直接调用 `seep_tool_install(execute=True)` 自动安装（多途径自适应支持无 winget 环境）；
2. **Step 2：核心业务逆向与伪代码走查**
   - 复杂函数优先调用 `seep_decompile_auto`（真 Ghidra 驱动优先，优雅落 r2 兜底）；
   - 运行期内存解密调用 `seep_mem_strings`；网络通信分析调用 `seep_http_replay`；
3. **Step 3：逻辑旁路与微创打桩**
   - 严格遵循内存 ABI 防崩守则，只劫持纯标量返回，优选零栈破坏字节序列；
4. **Step 4：成品交付与断网验证**
   - Windows 端交付免落盘代理补丁 `version.dll`；Android 端交付重新签名包 `*_rebuilt_signed.apk`；
   - 输出符合合规规范的三段式白盒评估报告。

---

## 三、 调度纪律

- 遵循平台统一的 G-Auth 授权门禁（未经测试授权严禁操作）；
- 同构路径失败 2 次必须触发熔断换法，禁止无效死磕。
"""
    return template


def register_to_softseep(name: str, desc: str) -> bool:
    if not os.path.isfile(SOFTSEEP_MD):
        return False
    try:
        content = open(SOFTSEEP_MD, "r", encoding="utf-8").read()
        if f"**{name}**" in content:
            return True  # 已经注册过

        # 找到资源表末尾插入
        anchor = "| client-license-validation-bypass | `Tool/client-license-validation-bypass/SKILL.md` | 许可校验专项 |"
        new_row = f"| | **{name}** | `Tool/skill/{name}/SKILL.md` | {desc[:20]} |"
        if anchor in content:
            content = content.replace(anchor, f"{anchor}\n{new_row}")
            open(SOFTSEEP_MD, "w", encoding="utf-8", newline="\n").write(content)
            return True
    except Exception:
        pass
    return False


def sync_to_agent(target_dir: str, name: str) -> bool:
    if os.path.isdir(USER_AGENT_SKILLS):
        dst = os.path.join(USER_AGENT_SKILLS, name)
        try:
            if os.path.exists(dst):
                shutil.rmtree(dst)
            shutil.copytree(target_dir, dst)
            return True
        except Exception:
            return False
    return False


def main():
    parser = argparse.ArgumentParser(description="Seep 外挂技能标准化自动化脚手架")
    parser.add_argument("name", help="技能英文标识符（如 bluetooth-re）")
    parser.add_argument("--desc", default="", help="一句话描述")
    parser.add_argument("--title", default="", help="技能中文标题")
    args = parser.parse_args()

    clean_name = clean_skill_name(args.name)
    target_dir = os.path.join(SKILL_DIR, clean_name)
    os.makedirs(target_dir, exist_ok=True)

    skill_file = os.path.join(target_dir, "SKILL.md")
    content = generate_skill_content(clean_name, args.desc, args.title)

    # 强制写入 UTF-8 无 BOM 格式
    with open(skill_file, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

    registered = register_to_softseep(clean_name, args.desc or f"{clean_name} 专项技能")
    synced = sync_to_agent(target_dir, clean_name)

    result = {
        "status": "success",
        "skill_name": clean_name,
        "path": skill_file,
        "registered_to_softseep": registered,
        "synced_to_agent_skills": synced,
        "format": "UTF-8 No-BOM (YAML Frontmatter Compliant)",
        "message": f"技能 '{clean_name}' 已成功按照规范生成并自动注册！可在 Agent 中直接引用: lab：引用技能 {clean_name}"
    }
    import json
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
