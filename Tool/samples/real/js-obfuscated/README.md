# Web/JS 混淆样本（真实混淆脚本）

> 来源：[kuizuo/js-deobfuscator](https://github.com/kuizuo/js-deobfuscator)（**MIT**）的 `example/`。
> 9 组真实 Web/JS 混淆样本，每组含 `input.js`（混淆后）+ `output.js`（去混淆参考），
> 覆盖 obfuscator.io、某点评/电商/视频站点的真实前端混淆，供 JS 逆向/去混淆练手。

| 目录 | 混淆来源 | 用途 |
|---|---|---|
| `obfuscator/` | obfuscator.io 标准混淆 | 控制流平坦化、字符串数组、十六进制标识符 |
| `maoyan/` | 猫眼（真实站点） | 大体积 bundle 去混淆 |
| `wangyi/` | 网易（真实站点） | 前端签名/加密链 |
| `pdd/` | 拼多多（真实站点） | 反爬参数还原 |
| `gk/` | 某站点 | 混淆还原 |
| `jsonv6/` | JSON v6 | 结构混淆 |
| `lamz/` | 某站点 | setupCode + 混淆 |
| `cx/` | 某站点 | 混淆还原 |
| `cycgo/` | 某站点 | 混淆还原 |

用途：`mcp-js-reverse-playbook` 技能、js-reverse-mcp（浏览器运行时采样）、AST 去混淆的真实靶子。
**不是可执行恶意脚本**——都是前端混淆代码，供静态/动态分析练习。

## 说明

- 每组 `input.js` = 混淆后（真实目标），`output.js` = 作者去混淆后的参考结果（可对照验证）。
- 来源仓库为 MIT，个人自用收录。
