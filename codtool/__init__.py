"""codtool —— CoD SP26（cod26 / sp26 引擎）文件结构解析、修改器与 mod 工具。

模块
  proc      进程内存读写（Win32 / ctypes）
  scanner   AOB 特征码扫描 + 数值多轮扫描
  cvar      控制台变量定位与改写
  trainer   补丁包（mod pack）加载 / 冻结 / 热键
  ipak      IPAK v3 容器（.xpak/.xsub）结构解析
  peinfo    PE 结构报告与版本差异定位
  modtool   安装目录识别、settings.json、脚本覆盖、完整性校验
  gui       图形界面
  cli       命令行
"""

__version__ = "1.0.0"
