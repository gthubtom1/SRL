# .NET 真实练习样本（CrackMe 系列）

> 来源：[mrhery/CrackMe](https://github.com/mrhery/CrackMe)（**GPL-3.0**）。
> 5 个 .NET (CLR) 授权练习样本，覆盖不同授权模型，专为学习逆向设计，**非恶意程序**。

| 目录 | 授权模型 | 用来练什么 |
|---|---|---|
| `CrackMev1_-_Local_File_Licensing` | 本地文件授权 | .NET 反编译、文件校验定位 |
| `CrackMev2_-_Local_Enum_Licensing` | 本地枚举授权 | 枚举/状态位判定 |
| `CrackMev3_-_Simple_Remote_Licensing` | 简单远程授权 | 网络校验/回包 |
| `CrackMev4_-_Registration_Base_Licensing` | 注册码授权 | 注册码算法还原 |
| `CrackMev5_-_Trial_Version_Validation` | 试用期验证 | 时间/试用判定 |

用途：验证 .NET/CLR 样本识别（`seep_packer_detect` 的 has_clr、`seep_decompile_auto` 的 dotnet 降级链）、
dnSpy/ILSpy 类工具链的真实靶子。
