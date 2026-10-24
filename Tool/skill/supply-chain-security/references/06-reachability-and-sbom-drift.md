# 06 · SBOM 漂移与可达性对账

> 范围：已有 SBOM（CycloneDX/SPDX）或锁文件/freeze，需要回答“组件是否进了源码、SBOM 是否漏项、可达是否成立”。
> 前置：组件清单 + 源码；二进制内嵌依赖用 `strings`/符号表另做。
> 工具：`scripts/sbom-reach.py`（本域）、`sc-check.py`（清单盘点）、外部 `syft`/`osv-scanner`（可选）。

## 1. 三个集合，先画清边界

```text
声明集合 = manifest 直接依赖
锁定集合 = 锁文件/freeze 解析结果（传递依赖）
清单集合 = SBOM 组件
可达集合 = 源码里出现 import/require 的组件
```

四个集合不相等是常态，关键是**差异可解释**：

| 差异 | 含义 | 处理 |
| :-- | :-- | :-- |
| 锁定 ⊄ 清单 | SBOM 漏项/过期 | 重新生成 SBOM，或把锁文件解析结果当清单 |
| 清单 ⊄ 锁定 | SBOM 含未安装/OS 包/工具链 | 标注来源，不强行对齐 |
| 可达 ⊄ 锁定 | 动态导入、插件、运行时注入 | 人工补调用链，不写“不可达” |
| 锁定 ⊄ 可达 | 未使用/仅测试/仅工具 | 写“未观察到调用”，不写“无风险” |

`sbom-reach.py` 的 `missing_from_sbom[]` 就是“锁定 − 清单”，`unreachable[]` 是“锁定 − 可达”。

## 2. 最小可复现命令

```bash
# 1) 组件清单：优先 SBOM，没有就锁文件/freeze
python Tool/skill/supply-chain-security/scripts/sbom-reach.py \
  --sbom bom.cdx.json \
  --lock package-lock.json \
  --freeze freeze.txt \
  --source . \
  --out reach.json

# 2) 只看锁文件（无 SBOM 时的降级）
python Tool/skill/supply-chain-security/scripts/sbom-reach.py \
  --lock package-lock.json --source src --entry 'main.py' --out reach.json

# 3) 清单盘点与风险线索
python Tool/skill/supply-chain-security/scripts/sc-check.py --path . --out sc.json
```

输出关键字段：

```json
{
  "components_total": 42,
  "by_ecosystem": {"npm": 30, "pypi": 12},
  "reachable": [{"name": "left-pad", "version": "1.3.0", "entry_hit": true,
                 "hits": [{"file": "src/index.js", "line": 1,
                           "snippet": "const pad = require('left-pad');"}]}],
  "unreachable": [{"name": "@corp/auth", "version": "2.0.0", "hits": []}],
  "missing_from_sbom": [],
  "entries": ["src/app.py", "src/index.js"]
}
```

判据：`reachable[].hits[].file/line/snippet` 必须能人工打开核对；`entry_hit=true` 表示命中文件本身就是入口，优先级更高。

## 3. Python 发行名 → import 名（最容易假阴性的地方）

| 发行名 | import 名 |
| :-- | :-- |
| `PyYAML` | `yaml` |
| `beautifulsoup4` | `bs4` |
| `Pillow` | `PIL` |
| `python-dateutil` | `dateutil` |
| `scikit-learn` | `sklearn` |
| `opencv-python` | `cv2` |
| `pycryptodome` | `Crypto` |
| `psycopg2-binary` | `psycopg2` |
| `protobuf` | `google`（protobuf 运行时） |

脚本内置上表与归一化（小写、`-`/`_`/`.` 统一），未命中的发行名按原名替换 `-`→`_` 再搜。
仍搜不到时，按下面顺序排查，而不是直接写“不可达”：

1. 动态导入：`importlib.import_module(name)`、`__import__(...)`、字符串拼接。
2. 插件/entry points：`pkg_resources.iter_entry_points`、`importlib.metadata`。
3. 框架约定：Django app、pytest 插件、Celery worker 自动发现。
4. 子进程/外部命令：包提供 CLI，代码只 `subprocess.run(["tool", ...])`。

## 4. SBOM 漂移的三种来源

| 来源 | 现象 | 复算 |
| :-- | :-- | :-- |
| 时间漂移 | SBOM 生成于旧 commit，锁文件已更新 | 对比 `metadata.component.version`/subject 与 `git rev-parse HEAD` |
| 环境漂移 | 生成 SBOM 的机器没装 optional/peer 依赖 | 组件数与锁文件条目数差 >20% 即告警 |
| 工具漂移 | syft/cdxgen 版本不同，许可证/命名不同 | 记录工具+版本；按 purl 而非 name 对齐 |

判据：SBOM 必须能追到 commit 或 image digest；否则只作“参考清单”，不作结论依据。

## 5. 从可达走到“可利用”还差什么

可达只是第一层。要写 `confirmed` 还需要：

1. **入口可控**：攻击者能控制进入该 import 的参数/数据。
2. **危险 sink**：组件内真正执行危险操作的函数被调用（反序列化、模板、命令、路径）。
3. **版本受影响**：版本在 advisory 范围内，且没有 backport 修复。
4. **运行时存在**：打包产物/镜像里确实包含该组件（不是 devDependency 被裁掉）。
5. **对照**：修复版本或禁用开关后行为变化。

缺 1–5 任一项，按 `02-failure-criteria.md` 降级，不要用“依赖里有 CVE”替代利用链。

## 6. 失败判据

| 现象 | 判定 | 改走哪条 | 代价 |
| :-- | :-- | :-- | :-- |
| `missing_from_sbom` 很大且无解释 | 清单与锁定不同源 | 重新生成 SBOM / 用锁文件当清单 | 低：一次重生成 |
| `reachable` 很少但项目明显在用某框架 | import 名/动态导入漏检 | 补别名、查 entry points、查 CLI 调用 | 低：补规则 |
| 所有组件都 `unreachable` | 入口 glob 没覆盖或源码根错 | 检查 `--source`/`--entry`，列出 `entries[]` 是否为空 | 低：改参数重跑 |
| 可达组件版本不在 advisory 范围 | 不是该 CVE 的受影响版本 | 查 advisory 的 affected ranges 与 backport | 低：换 CVE 或关掉 |
| 可达但参数不可控 | 是调用不是利用 | 写“可达、未见可控入口”，转人工审计 | 中：需要读业务代码 |
| SBOM 无 subject/commit | 对象不可钉住 | 重新生成并绑定 commit/digest | 中：需要构建记录 |

## 7. 边界

- 静态 import 扫描不执行代码，不处理混淆/压缩后的 bundle；前端产物需先还原。
- 不把“未观察到调用”写成“不可达”；不把“可达”写成“可利用”。
- 组件清单不覆盖 OS 包、内核模块、固件内嵌库；那些走 `firmware-iot`/`forensics-mobile`。
- CVE 数据需 OSV/GHSA 等外部源；离线时只做版本与调用面，不编造漏洞编号。
