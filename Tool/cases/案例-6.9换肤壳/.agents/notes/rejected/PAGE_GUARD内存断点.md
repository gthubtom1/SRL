# Agent Note: 用 PAGE_GUARD 挂内存断点抓字符串访问

Status: rejected — 目标重度依赖 VirtualProtect + 内存自检，PAGE_GUARD 与其异常处理冲突，把目标搞崩。

## Problem

想定位"请输⼊正确订阅码"这类字符串被哪段代码引用，计划对字符串所在内存页装 PAGE_GUARD 捕获访问者 RIP。

## Proposal

注入 DLL，对目标字符串页装 PAGE_GUARD，靠 VEH 记录访问点。

## Alternatives considered

- **MinHook 钩标准 API / 直接内存 Dump** ——
  最强理由：不侵入目标的页保护机制；对"重度自修改/反调试"目标更稳。
  采纳原因：PAGE_GUARD 实测触发目标自身异常处理 → 弹"程式遇到致命錯誤"。

## Consequences

- **可复用判据**：**对重度自修改/反调试目标，不用侵入式内存页守卫**；改 MinHook/Detours 钩标准 API，或内存 Dump。
- **纪律**：内存打桩导致目标崩溃 2 次 → 强制转 Dump 或协议层，别硬刚。
