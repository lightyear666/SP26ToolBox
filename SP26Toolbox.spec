# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['sp26_panel.py'],
    pathex=['.'],
    binaries=[],
    datas=[('assets/steam_api64.dll', 'assets')],
    hiddenimports=['codtool.agent_client', 'codtool.proc', 'sp26_ent', 'sp26_esp', 'sp26_patch', 'sp26_god6', 'sp26_spawner', 'sp26_dll_guard', 'sp26_startup'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SP26Toolbox',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
