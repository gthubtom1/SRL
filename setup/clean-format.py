import os
import sys

root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
print(f"[*] Starting Seep Formatting & Encoding Sanitizer on: {root}")

sh_fixed = 0
ps_bom_fixed = 0
md_bom_fixed = 0
py_checked = 0

for dirpath, dirnames, filenames in os.walk(root):
    # 跳过 .git、外部大包缓存，以及第三方上游镜像
    # （upstream/ 保持字节级保真，不重新格式化 vendored 代码）
    # 注意：第三方 vendored 目录（Tool/upstream 与 Tool/mcp/Tool 运行时）必须字节级保真，
    # 绝不重排 BOM/换行，否则与上游 diff 爆炸、并破坏第三方文件完整性。
    if (".git" in dirpath or "node_modules" in dirpath or ".venv" in dirpath
            or "tmp_" in dirpath
            or os.path.join(root, "Tool", "upstream") in dirpath
            or os.path.join(root, "Tool", "mcp", "Tool") in dirpath
            or os.path.join(root, "work") in dirpath):
        continue

    for f in filenames:
        ext = os.path.splitext(f)[1].lower()
        filepath = os.path.join(dirpath, f)

        # 0. 通用 BOM 剥离：除 PowerShell / 批处理（PS 5.1 解析 UTF-8 CJK 需要 BOM）外，
        #    所有文本文件一律不允许 BOM —— .py 带 BOM 会直接 SyntaxError，
        #    .md 带 BOM 会让 SKILL.md 的 frontmatter 被 Agent 静默跳过。
        if ext not in (".ps1", ".psm1", ".bat", ".cmd"):
            try:
                with open(filepath, "rb") as fp:
                    _raw = fp.read()
                if _raw.startswith(b"\xef\xbb\xbf"):
                    with open(filepath, "wb") as fp:
                        fp.write(_raw[3:])
                    md_bom_fixed += 1
                    print(f"  [BOM Strip] {os.path.relpath(filepath, root)}")
            except Exception as e:
                print(f"  [!] Error checking BOM {filepath}: {e}")

        # 1. 规范化 Bash 脚本 (*.sh)：坚决杜绝 \r
        if ext in [".sh", ".bash"]:
            try:
                with open(filepath, "rb") as fp:
                    data = fp.read()
                if b"\r\n" in data:
                    clean_data = data.replace(b"\r\n", b"\n")
                    with open(filepath, "wb") as fp:
                        fp.write(clean_data)
                    sh_fixed += 1
                    print(f"  [LF Fix] {os.path.relpath(filepath, root)}")
            except Exception as e:
                print(f"  [!] Error fixing {filepath}: {e}")

        # 2. 规范化 PowerShell 脚本 (*.ps1)：在 Windows 下确保带 UTF-8 BOM，防止 PS5.1 乱码
        elif ext == ".ps1":
            try:
                with open(filepath, "rb") as fp:
                    data = fp.read()
                # 检查是否有 UTF-8 BOM: EF BB BF
                if not data.startswith(b"\xef\xbb\xbf"):
                    # 补齐 BOM 并保证换行符
                    bom_data = b"\xef\xbb\xbf" + data
                    with open(filepath, "wb") as fp:
                        fp.write(bom_data)
                    ps_bom_fixed += 1
                    print(f"  [BOM Fix] {os.path.relpath(filepath, root)}")
            except Exception as e:
                print(f"  [!] Error checking BOM {filepath}: {e}")

        # 3. 规范化 Markdown / JSON：必须无 BOM
        #    SKILL.md 带 BOM 时，YAML frontmatter 解析器（DSH / Claude Code 等）
        #    无法识别首行 `---`，整条技能会被静默跳过；JSON 带 BOM 也会令部分解析器报错。
        elif ext in [".md", ".markdown", ".json", ".jsonc"]:
            try:
                with open(filepath, "rb") as fp:
                    data = fp.read()
                if data.startswith(b"\xef\xbb\xbf"):
                    with open(filepath, "wb") as fp:
                        fp.write(data[3:])
                    md_bom_fixed += 1
                    print(f"  [BOM Strip] {os.path.relpath(filepath, root)}")
            except Exception as e:
                print(f"  [!] Error stripping BOM {filepath}: {e}")

        # 4. 语法解析检查 (*.py)
        elif ext == ".py":
            py_checked += 1
            try:
                import ast
                with open(filepath, "r", encoding="utf-8", errors="ignore") as fp:
                    code = fp.read()
                ast.parse(code)
            except Exception as e:
                print(f"  [SYNTAX ERROR in Python] {os.path.relpath(filepath, root)}: {e}")

print(f"\n[√] 格式化治理完成:")
print(f"  - 修正 LF 换行 Bash 脚本: {sh_fixed}")
print(f"  - 补齐 UTF-8 BOM 的 PowerShell 脚本: {ps_bom_fixed}")
print(f"  - 剥离 UTF-8 BOM 的 Markdown/JSON: {md_bom_fixed}")
print(f"  - 校验通过的 Python 脚本: {py_checked}")
