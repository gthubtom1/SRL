---
name: game-rendering
description: 核对游戏 World-to-Screen 矩阵、坐标与画面的关系，规划 Overlay 窗口和图形资源的启停恢复；用于投影错位、分辨率变化和渲染生命周期排查。
---

# 游戏渲染核对

`Tool/...` 路径以宿主登记的工作台源码根为基准；KB 和配方不复制进技能部署目录。技能内相对路径仍以本技能目录为基准。

归属 softseep。当前可执行交付是离线几何验证器；未实现图形 Hook、Overlay 绘制或完整 ESP，未实测真实引擎。`visible` 只指齐次裁剪范围内，不能证明无遮挡、实体语义正确或画面已绘制。

## 输入与现有材料

需要目标构建身份、平台/图形 API、同帧世界坐标和完整 world→clip 矩阵、明确的存储/向量/clip-z 约定、viewport 及其物理像素尺寸。实机画面对照另需同帧截图、实体标识与窗口客户区/DPR。没有目标或设备时只交付离线结果，不能宣布实机验收。

方法来源复用 ESP/W2S/Overlay KB（`Tool/mcp/Tool/reverselab/kb/general/techniques/cheating/03-esp-wallhack-rendering.md`），按 W2S、D3D11、External Overlay 相关段落读取，不复制全文。可用当前 `seep_kb_search` / `seep_kb_read` 检索；先发现宿主实际工具及参数，KB 中旧工具名/示例不代表已接线。无 MCP 时读取仓库正文。脚本补足 KB 示例缺少的布局、深度裁剪和坏输入核对。

## 操作

1. 钉住构建与采样帧，向数据提供者索取矩阵来源/组合顺序。列向量使用 `clip=M*[x,y,z,1]`，行向量使用 `clip=[x,y,z,1]*M`。`row-major`/`column-major` 只解释16个数的存储，独立于向量约定；不通过“换个转置看起来对”推断真实约定。引擎左右手、世界单位、相机方向需来源佐证；脚本不猜测、不改轴、不自动组合 view/projection。
2. 使用下列 canonical 命令（仓库根目录），先生成输入，再填入已知同帧数据。JSON 字段见 `--example`；`project/version/run` 沿用当前项目的真实身份，不另建账本。

   ```powershell
   python Tool/skill/softseep/subskills/game-rendering/scripts/w2s_check.py --help
   python Tool/skill/softseep/subskills/game-rendering/scripts/w2s_check.py --example
   python Tool/skill/softseep/subskills/game-rendering/scripts/w2s_check.py --input tmp/capability-logs/game-rendering/input.json
   python Tool/skill/softseep/subskills/game-rendering/scripts/w2s_check.py --self-test
   ```

   输入最多1 MiB/4096点，矩阵16个数、每点xyz；数值必须有限且绝对值≤1e12，viewport宽高在(0,1e6]。`clip_z` 显式选 `zero-to-one` 或 `minus-one-to-one`；反向Z仍选实际裁剪区间，理由仅表示超出上下限，不擅称近/远平面。`viewport.origin` 为 top-left/bottom-left；x/y及输出使用同一物理像素坐标系。屏幕映射为viewport连续坐标，边界可等于width/height，不代表可索引像素。DPR和客户区到桌面偏移由采集者换算，不能把逻辑像素混入物理像素。
3. 检查输出的 clip、ndc、screen、visible、behind、reasons。正w允许输出裁剪外屏幕点；负w不投影；|w|≤1e-9记不可投影，不能拿[0,0]代替失败。矩阵有限只能证明数值合法；错误但有限的矩阵可能仍生成“可见”点。
4. 有实机条件后，固定至少三个非共线已知锚点，记录同帧世界点、相机、截图位置与投影残差(px)，在执行前设定可接受误差。比较中心/边缘/相机后方和裁剪外点；改变相机朝向再复查，避免单位矩阵或静态截图碰巧通过。若仅有合成输入，报告限于几何核对。
5. 实机生命周期按下述清单执行；本脚本不执行这些动作，也不启动目标。

## 窗口、资源与停用恢复

首个实机任务限定一种已确认 API（例如 D3D11）及一个构建。先记录未启用时窗口句柄/客户区、DPR、显示模式、输入焦点、帧时间基线与图形资源拥有者。

- 初始化：确认 device/context/swapchain 与窗口对应关系；记录每项创建的RTV、字体、纹理、回调和输入处理的拥有者与释放方法。采用外部Overlay时同步客户区到桌面位置，明确输入穿透/菜单焦点规则；不能凭窗口标题绑定目标。
- resize/DPR/全屏/最小化：暂停新增绘制；零尺寸或缺帧直接跳过；释放旧backbuffer关联资源，待有效尺寸后重建并更新viewport，重新投影同一组锚点。800×600变1600×1200时相对位置应一致；禁止继续用旧尺寸。设备移除/窗口销毁时停止使用旧句柄和资源，回到未初始化状态；只在新对象身份确认后重建。
- 停用：先关闭新绘制和输入捕获，等待在途回调结束；恢复任务实际改过的渲染状态/回调/窗口属性，释放自有资源，移除自有Overlay。不得释放宿主资源。对照停用前基线检查焦点、正常画面、帧时间及遗留窗口/回调；再次启用与目标重启分别验证，不能把“按钮关了”当恢复成功。

## 输出、反例与交接

将原始输入、命令、输出哈希、同帧截图/残差及生命周期事件证据存入当前项目的既有证据目录，关联相同 project/version/run；父域接回当前运行结论和所缺条件。换构建、帧、viewport或API必须重采样，禁止拼接旧矩阵与新坐标。运行日志放技能源目录之外；主代理负责正式导入、部署及新会话加载验证。

脚本退出0表示输入合法且完成计算，点被裁剪也可退出0；坏输入退出2，不产生成功结果。自测覆盖非对称矩阵转置反例、行/列存储和向量等价、负w/零w、分辨率变化、深度裁剪、NaN等拒绝路径。有限错误矩阵不会自动被识别为错误，必须用已知锚点残差反证。缺矩阵约定、身份不匹配、混帧、未知DPR、缺设备/截图、恢复证据不足时分别标为待补或未验证；几何通过不升级为真实引擎/Overlay/完整ESP已交付。
