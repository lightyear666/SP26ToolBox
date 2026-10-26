"""代理 DLL 自检：确认游戏目录里的 steam_api64.dll 是工具箱配套代理，必要时备份并替换。

游戏目录由玩家在启动弹窗中手动选择，保存在 toolbox_config.json。
只在本机单人游戏环境使用；替换前必须由用户显式勾选授权。
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import time
from pathlib import Path

DLL_NAME = 'steam_api64.dll'
REAL_NAME = 'steam_api64_real.dll'
CONFIG_NAME = 'toolbox_config.json'
KNOWN_MD5 = '59dfc1c33ff657937a4dda330b0c4a9c'
GAME_EXE = 'sp26-cod.exe'


def app_dir() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def asset_path() -> Path:
    base = Path(getattr(sys, '_MEIPASS', app_dir()))
    p = base / 'assets' / DLL_NAME
    if p.is_file():
        return p
    return app_dir() / 'assets' / DLL_NAME


def load_config() -> dict:
    try:
        with open(app_dir() / CONFIG_NAME, encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_config(data: dict) -> None:
    try:
        with open(app_dir() / CONFIG_NAME, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def md5_file(path: Path):
    try:
        h = hashlib.md5()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def normalize_game_dir(path):
    if not path:
        return None
    try:
        d = Path(path).expanduser().resolve()
    except Exception:
        return None
    if (d / GAME_EXE).is_file():
        return d
    if (d / 'sp26' / GAME_EXE).is_file():
        return d / 'sp26'
    return None


def resolve_game_dir(hint=None):
    d = normalize_game_dir(hint)
    if d:
        return d
    return normalize_game_dir(load_config().get('game_dir'))


def expected_md5():
    p = asset_path()
    return md5_file(p) if p.is_file() else KNOWN_MD5


def inspect(hint=None) -> dict:
    game_dir = resolve_game_dir(hint)
    expected = expected_md5()
    asset_ok = asset_path().is_file()
    info = {
        'game_dir': str(game_dir) if game_dir else '',
        'dll': '',
        'real': '',
        'current_md5': None,
        'expected_md5': expected,
        'state': 'no_dir',
        'asset_ok': asset_ok,
        'can_replace': False,
        'message': '',
    }
    if not game_dir:
        info['message'] = '尚未选择有效的 SP26 游戏目录'
        return info
    dll = game_dir / DLL_NAME
    real = game_dir / REAL_NAME
    info['dll'] = str(dll)
    info['real'] = str(real)
    cur = md5_file(dll) if dll.is_file() else None
    info['current_md5'] = cur
    if cur == expected:
        if real.is_file():
            info.update(state='ok', can_replace=True, message='代理 DLL 已正确安装')
        else:
            info.update(state='real_missing',
                        message='代理已安装，但缺少原始 DLL 备份 steam_api64_real.dll')
    elif cur is None:
        if real.is_file():
            info.update(state='missing', can_replace=asset_ok,
                        message='游戏目录中缺少 steam_api64.dll，可安装代理')
        else:
            info.update(state='missing_original',
                        message='缺少原始 steam_api64.dll 及其备份，无法安全安装代理')
    elif not asset_ok:
        info.update(state='no_asset', message='工具箱缺少配套代理 DLL，无法自动修复')
    else:
        info.update(state='mismatch', can_replace=True,
                    message='当前 DLL 不是工具箱配套代理')
    return info


class DllError(RuntimeError):
    pass


def install_proxy(hint=None) -> dict:
    info = inspect(hint)
    if info['state'] == 'no_dir':
        raise DllError('未选择有效的游戏目录')
    if info['state'] == 'ok':
        save_config({**load_config(), 'game_dir': info['game_dir']})
        return {'ok': True, 'changed': False, 'info': info}
    if info['state'] == 'missing_original':
        raise DllError('缺少原始 DLL 与备份，无法安全安装代理；请先修复游戏文件')
    if not info['asset_ok']:
        raise DllError('工具箱缺少配套代理 DLL')
    if info['state'] == 'real_missing':
        raise DllError('缺少原始 DLL 备份，无法安全补齐；请先恢复原版 steam_api64.dll')

    game_dir = Path(info['game_dir'])
    dll = game_dir / DLL_NAME
    real = game_dir / REAL_NAME
    expected = info['expected_md5']
    backup = None
    if dll.is_file() and not real.is_file():
        shutil.copy2(dll, real)
        backup = str(real)

    tmp = game_dir / (DLL_NAME + '.tmp')
    try:
        shutil.copy2(asset_path(), tmp)
        try:
            os.replace(tmp, dll)
        except PermissionError:
            try:
                os.chmod(dll, stat.S_IWRITE)
            except OSError:
                pass
            os.replace(tmp, dll)
    except OSError as e:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise DllError(f'写入失败（游戏可能正在运行或文件被占用）：{e}') from e
    got = md5_file(dll)
    if got != expected:
        raise DllError(f'替换后校验失败：{got} != {expected}')
    save_config({**load_config(), 'game_dir': str(game_dir)})
    return {'ok': True, 'changed': True, 'backup': backup, 'info': inspect(str(game_dir))}


def _log(msg):
    try:
        with open(app_dir() / 'panel_runtime.log', 'a', encoding='utf-8') as f:
            f.write(time.strftime('%Y-%m-%d %H:%M:%S ') + '[dll] ' + str(msg) + '\n')
    except Exception:
        pass
