---
name: lsposed-modern
description: "Android Modern libxposed (API 100/101) 模块骨架与动态 ClassLoader 拦截。适用于 Android 14/15+、Vector、LSPosed_mod 环境及加壳/延迟加载类的 Hook 探测。"
metadata:
  version: "2.0.0"
  target_runtimes: "Android 8.0 - Android 15 (ARM64 / x86_64)"
  api_standard: "libxposed API 100/101"
---

# Android Modern LSPosed 模块骨架与动态 Hook

## 1. 适用场景
- 目标运行在 Android 14/15+ 环境，传统 Xposed (API 82) 接口受限；
- 宿主环境为 Vector、LSPosed_mod 或支持 Modern libxposed 标准的框架；
- 目标 APK 存在加壳保护或插件分包延迟加载，普通入口处目标类尚未就绪，需要动态拦截 `BaseDexClassLoader`。

## 2. 核心生成命令

```bash
# 生成 Modern libxposed 模块工程（带加壳动态拦截）
python Tool/skill/apkseep/scripts/lsposed_scaffold.py \
    --api modern \
    --with-classloader-hook \
    --package com.seep.probe \
    --name "Auth Probe" \
    --hook-target com.target.app \
    --out work/module-probe
```

## 3. 工程结构与标准
- `AndroidManifest.xml`：声明 `xposedmodule=true`, `xposedminversion=100`, `xposedscope`；
- `META-INF/xposed/java_init.list`：包含完整的入口类名；
- `META-INF/xposed/module.prop`：声明 `minApiVersion=100`, `targetApiVersion=101`；
- 源码继承 `io.github.libxposed.api.XposedModule`。
