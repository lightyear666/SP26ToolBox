# 代理 DLL 构建

`assets/steam_api64.dll` 是配套代理，启动时转发全部 Steam API 到同目录的 `steam_api64_real.dll`，并在 `127.0.0.1:49700` 提供只读/写入/内存扫描通道。

## 依赖

- 64 位 MinGW-w64 GCC
- 源码：`agent.c`、`table.c`、`stubs.S`、`exports.def`

## 构建

```bash
gcc -shared -O2 -o steam_api64.dll agent.c table.c stubs.S exports.def -lws2_32 -static-libgcc
```

生成后把 `steam_api64.dll` 放到 `assets/`，重新打包工具箱。工具箱会用 `assets/steam_api64.dll` 的 MD5 作为期望值。

## 部署

游戏目录中需要：

- `steam_api64.dll`：本代理
- `steam_api64_real.dll`：原始 Steam API DLL 的备份

工具箱首次替换时，如果 `steam_api64_real.dll` 不存在，会把当前 `steam_api64.dll` 备份为该名称，然后再写入代理。
