#!/usr/bin/env bash
# ==============================================================================
# Seep 逆向工程工作台 —— 上游定点隔离同步与防外溢驱动 (Linux / macOS)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PY_ENGINE="${SCRIPT_DIR}/sync-upstream.py"

TARGET="all"
DRY_RUN=""
CHECK_ONLY=""
PROXY=""
SKIP_VERIFY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -Target|--target)
      if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then echo "$1 需要目标参数" >&2; exit 2; fi
      TARGET="$2"; shift 2 ;;
    -DryRun|--dry-run)
      DRY_RUN="--dry-run"; shift ;;
    -CheckOnly|--check-only)
      CHECK_ONLY="--check-only"; shift ;;
    -Proxy|--proxy)
      if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then echo "$1 需要代理地址" >&2; exit 2; fi
      PROXY="$2"; shift 2 ;;
    -SkipVerify|--skip-verify)
      SKIP_VERIFY=1; shift ;;
    *)
      echo "未知参数: $1" >&2; exit 1 ;;
  esac
done

export PYTHONIOENCODING=utf-8
PYTHON_CMD=""
for candidate in python3 python; do
  if command -v "$candidate" &>/dev/null && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 11))' &>/dev/null; then
    PYTHON_CMD="$candidate"
    break
  fi
done
if [[ -z "$PYTHON_CMD" ]]; then
  echo " [FAIL] 未检测到可用的 Python 3.11+" >&2
  exit 1
fi

ARGS=("$PY_ENGINE" "--target" "$TARGET")
[[ -n "$DRY_RUN" ]] && ARGS+=("$DRY_RUN")
[[ -n "$CHECK_ONLY" ]] && ARGS+=("$CHECK_ONLY")
[[ -n "$PROXY" ]] && ARGS+=("--proxy" "$PROXY")

EXIT_CODE=0
"$PYTHON_CMD" "${ARGS[@]}" || EXIT_CODE=$?

if [[ $EXIT_CODE -eq 2 && -z "$CHECK_ONLY" ]]; then
  echo " [FATAL] 防外溢安全检查未通过！已紧急拦截并阻断。" >&2
  exit 2
fi

if [[ $EXIT_CODE -ne 0 && -z "$CHECK_ONLY" ]]; then
  exit $EXIT_CODE
fi

if [[ -z "$DRY_RUN" && -z "$CHECK_ONLY" && $SKIP_VERIFY -eq 0 ]]; then
  echo -e "\n>>> 正在运行工作台环境自检..."
  "$PYTHON_CMD" "${ROOT_DIR}/Tool/scripts/check.py" --env
fi

exit $EXIT_CODE
