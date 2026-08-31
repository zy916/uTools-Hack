# uTools-Hack

本来想用于 Electron 应用的逆向工程研究，但是发现很简单，数据层 Patch 即可。

项目没有直接修改业务层控制流，而是先从前端分析本地数据的读写，再从 Native 层分析加解密逻辑，还原数据协议并重新实现加解密流程，最终在数据层完成 Patch。

实现了 uTools 所有本地功能解锁，没有做免登录。（实测 v7.8.0）

## 思路

```text
Native Analysis
    ↓
定位本地数据与加密逻辑
    ↓
还原 Key / Codec / 数据格式
    ↓
重写 Encrypt / Decrypt
    ↓
解析并 Patch 结构化数据
    ↓
重新加密写回
```

核心思想：

> **不修改程序如何判断，而是修改程序用于判断的数据。**

## 实现方式

项目通过 `version.dll` Proxy 进入目标进程，并使用 **SafetyHook** Hook：

```cpp
KernelBase.dll!CreateFileW
```

当程序访问本地 `settings` 文件时，在文件读取边界执行数据层 Patch：

```text
CreateFileW
    ↓
匹配 settings 路径
    ↓
读取本地数据
    ↓
解析 JSON
    ↓
解密 account.info
    ↓
Patch 结构化数据
    ↓
重新加密
    ↓
写回 settings
    ↓
继续执行原 CreateFileW
```

## 为什么自己重写加解密？

项目没有直接调用目标程序内部的加解密函数，而是通过 Native 分析还原其：

- Key Derivation
- 数据编码格式
- Nonce / MAC 布局
- Encrypt / Decrypt 流程

然后独立重写 Codec。

这样可以降低对目标程序内部函数地址、调用上下文和具体实现的依赖。
（其实主要因为是我用 IDA 分析完，懒得再去搜特征码定位了，不如直接重写来的方便）

## 技术栈

- DLL Proxy / AheadLibEx
- SafetyHook
- Zydis
- Monocypher
- nlohmann/json
- Win32 API
- C++23 / CMake

同时处理了 Hook 重入、并发访问和原始 `CreateFileW` 调用语义保持等问题。

## Disclaimer

本项目仅用于逆向工程、Native 分析、数据流研究和软件安全学习。

uTools 仅作为研究对象，本项目与 uTools 官方无关。

## License

MIT
