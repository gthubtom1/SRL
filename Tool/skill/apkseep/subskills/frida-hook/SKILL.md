---
name: frida-hook
description: "Android Java/Native 有界动态观测、类与模块加载时机核对、插桩影响对照；真实凭据不进入 Agent。"
metadata:
  version: "2.1.0"
  target_runtimes: "Android ART / Frida；以实际客户端、服务端及 bridge 版本为准"
---

# Android 双层插桩

先读 [Frida 索引](../../references/dynamic-frida.md)、[环境与探针](../../references/dynamic-frida-1-setup-and-probe.md)、[失败与反插桩](../../references/dynamic-frida-2-failures-and-anti-instrumentation.md)。已有 `../../scripts/frida_probe.js`、`../../scripts/run_probe.py`、`../../scripts/lib_map.py`，先核对各入口及 `--help`，按实际任务选择；不把探针安装成功当关键路径已覆盖。

输入需绑定 APK/SO 哈希、包版本、设备/ART、实际执行 ABI、客户端和 frida-server 版本。`frida --version`、`frida-ps -U` 只证明相应工具/连接，不证明目标可插桩。客户目标运行确认、设备条件与正向控制缺一时先交静态定位。

## Java：默认保持原行为

下面仅用于自有合成夹具 `com.example.fixture.Checker`；命名方法不接收秘密。Frida 17 的独立编译 agent 需按打包方式引入 `frida-java-bridge`；REPL/frida-tools 常提供 Java bridge，先确认当前入口，不能在缺 `Java` 的环境照抄。

```javascript
Java.perform(function () {
    const Checker = Java.use('com.example.fixture.Checker');
    const original = Checker.acceptCount.overload('int');
    let calls = 0;
    original.implementation = function (count) {
        calls += 1;
        const result = original.call(this, count);
        if (calls <= 10) console.log('fixture call observed');
        return result;
    };
});
```

精确选重载并调用保存的原实现，避免误递归。类找不到先核 ClassLoader、加载时机和触发路径；一次零命中不能判反调试。日志只记允许的事件/计数，禁止打印 Token、Key、Salt、私钥、用户输入或返回对象全文；也不读取后散列来规避边界。实际账号由用户操作，只接收安全判定结果。没有工具侧字段筛选/过滤就停止敏感观测。

## Native：以当前模块对象 API 为例

```javascript
const mod = Process.findModuleByName('libfixture.so');
if (mod !== null) {
    const entry = mod.findExportByName('fixture_check');
    if (entry !== null) {
        Interceptor.attach(entry, {
            onEnter() { console.log('fixture native entry observed'); }
        });
    }
}
```

此例不读取参数/返回值。当前 Frida 模块对象提供 `findExportByName`；旧静态 `Module.findExportByName(module, symbol)`、`Module.findBaseAddress` 不能作为所有版本通用 API。目标尚未加载时用当前版本支持的模块观察器或一次有界的加载后安装；模块重载后旧地址作废。

非导出函数的地址须来自当前同构建 SO 的映射：文件 offset、RVA 与运行时 VA 分开，按 ELF PT_LOAD 计算 load bias。ARM Thumb 状态、指令边界、ABI/参数类型核实后再挂钩；不能随便 `base+0x12345`。偏移定位可请 softseep 辅助。

## 修改路线与失败边界

观察、替换返回值、修改证书验证分别是不同实验。只有当前目标需要改变行为时才设计单点修改与回滚、功能对照；默认不强制放行，也不全局拦截 libc 的 open/read/ptrace。TLS pinning 与 mTLS 分开：跳过客户端校验不能替代客户端私钥或服务端授权。优先合成会话/测试端点，真实 TLS 会话密钥不导入 Agent。

正例：夹具原始与观察版行为一致，正向控制 hook 命中，目标方法在指定操作后产生有界事件。反例：脚本加载返回成功却无事件；先查桥接、ABI、ClassLoader、模块加载、spawn/attach 时机与输入覆盖，不能写“已绕过”。attach 本身会改变时序，需未插桩基线；崩溃需归因到单变量。两次同形失败重判，设备缺失明确 blocked。

交付 hook 的适用版本、触发条件、事件计数、控制组和未覆盖路径。若修改则另验目标功能与邻接功能；“不崩”不是验收。协议字段交 protocol-plugin、JNI 语义交 softseep，安全输出回到原 project/version/run。
