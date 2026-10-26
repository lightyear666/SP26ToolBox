# SP26 Toolbox

《使命召唤》SP26 单人战役的内存研究/学习工具箱，包含 ESP 绘制、准星吸附、吸敌、阵营识别、武器刷取、无敌、无限弹药、飞行等功能。仅用于本机单人模式的学习与研究。

> 本仓库不包含游戏本体、游戏资源、原始 Steam API DLL 或任何破解补丁。游戏名称、商标及相关资产归其权利人所有。

## 目录

```
sp26_panel.py           主面板（Tk）
sp26_esp.py             ESP 覆盖层（GDI 分层窗口）
sp26_ent.py             实体数组读取
sp26_patch.py           代码补丁（无限弹药）
sp26_god6.py            无敌补丁
sp26_spawner.py         武器刷取
sp26_team_palette.py    队伍配色
sp26_dll_guard.py       代理 DLL 自检/备份/替换
sp26_startup.py         启动声明与选目录弹窗
ammo_probe.py           弹药/代理连接辅助
codtool/                代理客户端与进程访问层
assets/steam_api64.dll  配套代理 DLL（替换用）
proxy_src/              代理 DLL 源码
SP26Toolbox.spec        PyInstaller 单文件打包配置
```

## 使用

1. 完全退出游戏。
2. 运行 `SP26工具箱_源码版.bat`（需要 Python 3.12）或打包后的 `SP26工具箱.exe`。
3. 阅读并勾选同意启动时的开源/免责声明。
4. 在弹出的窗口中选择游戏目录（包含 `sp26-cod.exe` 的文件夹，或其上一级安装目录）。
5. 工具箱会检查 `steam_api64.dll`：
   - 已是配套代理：直接进入；
   - 不是：弹窗展示当前/期望 MD5，勾选确认后才会先备份为 `steam_api64_real.dll`，再替换；
   - 替换前请确保游戏已退出，否则写入会失败。
6. 启动游戏，进入单人关卡；工具箱会自动连接 `127.0.0.1:49700`。

游戏目录保存在运行目录的 `toolbox_config.json`；面板/ESP 设置分别保存在 `panel_config.json`、`esp_config.json`。这些文件是运行期配置，不属于源码。

## 构建

```bash
python -m pip install -r requirements.txt
python -m PyInstaller SP26Toolbox.spec --noconfirm
```

产物为 `dist/SP26Toolbox.exe`，`assets/steam_api64.dll` 会被嵌入单文件。

代理 DLL 的重建方式见 `proxy_src/BUILD.md`。

## 声明

- 仅用于单机离线环境的逆向学习。禁止联机作弊、绕过反作弊、商业售卖或侵犯他人权益。
- 修改游戏内存、替换 DLL 存在存档损坏、崩溃、账号受限等风险，由使用者自行承担。
- 本工具不提供任何明示或暗示的担保。
- 本工具不联网、不上传数据；只在本机通过 `127.0.0.1:49700` 与代理 DLL 通信。

## 许可证

源码采用 [SP26 Toolbox Non-Commercial License](LICENSE)：允许学习、修改与非商业分发，禁止商业使用、联机作弊与绕过反作弊。游戏本体、商标与原始 DLL 不在许可范围内。
