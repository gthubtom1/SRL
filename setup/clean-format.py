"""Normalize maintained text sources; leave dependencies and runtime data alone."""
from __future__ import annotations

import argparse
import ast
import os
import stat
from pathlib import Path

TEXT_EXTENSIONS = {".sh", ".bash", ".ps1", ".psm1", ".py", ".md", ".markdown",
                   ".json", ".jsonc", ".yaml", ".yml", ".ts", ".js", ".txt", ".toml"}
SOURCE_DIRS = {"setup", "MANUAL", "docs", ".github", "Tool"}
EXCLUDED_NAMES = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache",
                  "tmp", "work", "proj", ".pi", "_archived"}
EXCLUDED_PATHS = {"Tool/upstream", "Tool/mcp/Tool", "Tool/cases", "Tool/samples",
                  "Tool/bin", "Tool/runtime", "Tool/bundles"}


def is_link(path: Path) -> bool:
    info = path.lstat()
    return path.is_symlink() or bool(getattr(info, "st_file_attributes", 0)
                                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def source_files(root: Path):
    for current, dirs, files in os.walk(root, followlinks=False):
        directory = Path(current)
        dirs[:] = [name for name in dirs
                   if name not in EXCLUDED_NAMES
                   and (directory != root or name in SOURCE_DIRS)
                   and (directory / name).relative_to(root).as_posix() not in EXCLUDED_PATHS
                   and not is_link(directory / name)]
        for name in sorted(files):
            path = directory / name
            if path.suffix.lower() in TEXT_EXTENSIONS and not is_link(path):
                yield path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="只检查，不写入")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    changed = passed = failed = 0
    for path in source_files(root):
        try:
            data = path.read_bytes()
            text = data.decode("utf-8-sig")
            if path.suffix.lower() == ".py":
                ast.parse(text, filename=str(path))
                passed += 1
            output = data
            if path.suffix.lower() in {".ps1", ".psm1"}:
                if not data.startswith(b"\xef\xbb\xbf"):
                    output = b"\xef\xbb\xbf" + data
            else:
                output = data.removeprefix(b"\xef\xbb\xbf")
                if path.suffix.lower() in {".sh", ".bash"}:
                    output = output.replace(b"\r\n", b"\n")
            if output != data:
                changed += 1
                if not args.check:
                    path.write_bytes(output)
                print(f"[{'NEEDS FORMAT' if args.check else 'FIXED'}] {path.relative_to(root)}")
        except (OSError, UnicodeError, SyntaxError) as exc:
            failed += 1
            print(f"[FAIL] {path.relative_to(root)}: {exc}")
    print(f"Python 语法通过: {passed}; 格式{'待修正' if args.check else '修正'}: {changed}; 失败: {failed}")
    return 1 if failed or (args.check and changed) else 0


if __name__ == "__main__":
    raise SystemExit(main())
