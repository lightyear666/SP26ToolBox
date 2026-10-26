"""启动门：开源/免责声明 + 手动选择游戏目录 + 代理 DLL 自检与授权替换。"""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox

import sp26_dll_guard as G

DISCLAIMER = """【开源声明】

本工具为单机游戏内存研究/学习工具，源码以非商业许可提供，仅供学习与交流。禁止将本工具或其修改版用于商业售卖、联机作弊、绕过反作弊、侵犯他人权益或违反当地法律法规的用途。

本仓库不包含游戏本体、游戏资源或原始 Steam API DLL。游戏名称、商标及相关资产归其权利人所有。

【免责声明】

使用本工具可能违反游戏的最终用户许可协议，并可能造成存档损坏、游戏崩溃、账号受限或其他不可预期后果。全部风险由使用者自行承担。

工具箱在获得你明确授权后，才会备份并替换游戏目录中的 steam_api64.dll（备份名 steam_api64_real.dll）。替换前请确认游戏已完全退出，并自行保留原始文件。

作者不对因使用或无法使用本工具造成的任何直接或间接损失承担责任；本工具不提供任何明示或暗示的担保。

点击“同意并继续”即表示你已阅读、理解并同意上述条款，并自行承担全部使用风险。"""


def _center(win, w, h):
    win.update_idletasks()
    x = max(0, (win.winfo_screenwidth() - w) // 2)
    y = max(0, (win.winfo_screenheight() - h) // 2)
    win.geometry(f'{w}x{h}+{x}+{y}')


def _modal(root, win):
    win.transient(root)
    win.grab_set()
    win.focus_force()
    root.wait_window(win)


def _font():
    return ('Microsoft YaHei', 10)


def show_disclaimer(root) -> bool:
    win = tk.Toplevel(root)
    win.title('SP26 工具箱 — 开源与免责声明')
    win.resizable(False, False)
    result = {'ok': False}
    win.protocol('WM_DELETE_WINDOW', win.destroy)

    body = ttk.Frame(win, padding=14)
    body.pack(fill='both', expand=True)
    ttk.Label(body, text='使用前请阅读并同意以下声明',
              font=('Microsoft YaHei', 12, 'bold')).pack(anchor='w', pady=(0, 8))

    text = tk.Text(body, width=80, height=20, wrap='word', font=_font(),
                   relief='solid', borderwidth=1, padx=8, pady=8)
    text.insert('1.0', DISCLAIMER)
    text.configure(state='disabled')
    text.pack(fill='both', expand=True)

    agree = tk.BooleanVar(value=False)
    ttk.Checkbutton(body, text='我已阅读并同意以上开源声明与免责声明', variable=agree).pack(
        anchor='w', pady=(10, 6))

    row = ttk.Frame(body)
    row.pack(fill='x')
    go = ttk.Button(row, text='同意并继续', state='disabled')
    ttk.Button(row, text='不同意并退出',
               command=lambda: (result.update(ok=False), win.destroy())).pack(side='right', padx=8)
    go.pack(side='right')

    def refresh(*_):
        go.configure(state='normal' if agree.get() else 'disabled')

    def accept():
        result['ok'] = True
        win.destroy()

    agree.trace_add('write', refresh)
    go.configure(command=accept)

    _center(win, 760, 560)
    _modal(root, win)
    return result['ok']


def choose_game_dir_dialog(root, initial='') -> str | None:
    win = tk.Toplevel(root)
    win.title('选择 SP26 游戏目录')
    win.resizable(False, False)
    result = {'dir': None}
    win.protocol('WM_DELETE_WINDOW', win.destroy)

    body = ttk.Frame(win, padding=16)
    body.pack(fill='both', expand=True)
    ttk.Label(body, text='请选择 SP26 游戏目录', font=('Microsoft YaHei', 12, 'bold')).pack(
        anchor='w', pady=(0, 8))
    ttk.Label(body, text='选择包含 sp26-cod.exe 的文件夹；也可以选择它的上一级安装目录。\n'
                        '工具箱会检查该目录下的 steam_api64.dll 是否为配套代理。',
              font=_font(), foreground='#333', justify='left').pack(anchor='w', pady=(0, 8))

    path_var = tk.StringVar(value=initial or '尚未选择')
    ttk.Label(body, textvariable=path_var, font=_font(), foreground='#555',
              wraplength=560).pack(anchor='w', pady=(0, 10))

    row = ttk.Frame(body)
    row.pack(fill='x')

    def choose():
        start = initial or G.load_config().get('game_dir') or ''
        if start and not G.normalize_game_dir(start):
            try:
                start = start if Path(start).is_dir() else ''
            except Exception:
                start = ''
        kw = {'parent': win, 'title': '选择 SP26 游戏目录', 'mustexist': True}
        if start:
            kw['initialdir'] = start
        d = filedialog.askdirectory(**kw)
        if not d:
            return
        norm = G.normalize_game_dir(d)
        if not norm:
            messagebox.showerror('目录无效',
                                 '所选目录中未找到 sp26-cod.exe。\n'
                                 '请选择游戏安装根目录或其 sp26 子目录。', parent=win)
            return
        G.save_config({**G.load_config(), 'game_dir': str(norm)})
        result['dir'] = str(norm)
        win.destroy()

    ttk.Button(row, text='选择游戏目录…', command=choose).pack(side='right')
    ttk.Button(row, text='退出工具箱',
               command=lambda: (result.update(dir=None), win.destroy())).pack(side='right', padx=8)

    _center(win, 620, 260)
    _modal(root, win)
    return result['dir']


def _dll_text(info):
    cur = info.get('current_md5') or '不存在/不可读'
    lines = [
        f"游戏目录：{info.get('game_dir') or '未选择'}",
        f"当前 DLL：{info.get('dll') or '—'}",
        f"当前 MD5：{cur}",
        f"期望代理：{info.get('expected_md5')}",
        f"状态：{info.get('message') or info.get('state')}",
    ]
    if info.get('state') == 'mismatch':
        lines += [
            '',
            '将执行：',
            '1. 若 steam_api64_real.dll 不存在，先把当前 DLL 备份为 steam_api64_real.dll',
            '2. 把工具箱内置的代理 DLL 写入 steam_api64.dll',
            '3. 替换后重新计算 MD5 校验',
        ]
    return '\n'.join(lines)


def _dll_dialog(root, info):
    win = tk.Toplevel(root)
    win.title('代理 DLL 检查')
    win.resizable(False, False)
    action = {'value': 'skip'}
    win.protocol('WM_DELETE_WINDOW', win.destroy)

    body = ttk.Frame(win, padding=14)
    body.pack(fill='both', expand=True)
    ttk.Label(body, text='游戏代理 DLL 自检', font=('Microsoft YaHei', 12, 'bold')).pack(
        anchor='w', pady=(0, 8))
    text = tk.Text(body, width=82, height=12, wrap='word', font=_font(),
                   relief='solid', borderwidth=1, padx=8, pady=8)
    text.insert('1.0', _dll_text(info))
    text.configure(state='disabled')
    text.pack(fill='both', expand=True)

    agree = tk.BooleanVar(value=False)
    can_replace = bool(info.get('can_replace'))
    if can_replace:
        ttk.Checkbutton(body, text='我已确认：先备份、再替换游戏目录中的 steam_api64.dll',
                        variable=agree).pack(anchor='w', pady=(10, 6))
    else:
        ttk.Label(body, text='当前状态不允许自动替换；可重新选择游戏目录，或按提示修复文件后点“重新检查”。',
                  foreground='#a00').pack(anchor='w', pady=(10, 6))

    row = ttk.Frame(body)
    row.pack(fill='x')

    def set_action(v):
        action['value'] = v
        win.destroy()

    def choose():
        d = choose_game_dir_dialog(root, info.get('game_dir') or '')
        action['value'] = 'refresh'
        if d:
            action['dir'] = d
        win.destroy()

    ttk.Button(row, text='重新选择游戏目录…', command=choose).pack(side='left')
    ttk.Button(row, text='暂不替换并继续', command=lambda: set_action('skip')).pack(
        side='right', padx=8)
    ttk.Button(row, text='重新检查', command=lambda: set_action('refresh')).pack(
        side='right', padx=8)
    if can_replace:
        rep = ttk.Button(row, text='自动替换', command=lambda: set_action('replace'),
                         state='disabled')
        rep.pack(side='right')

        def upd(*_):
            rep.configure(state='normal' if agree.get() else 'disabled')

        agree.trace_add('write', upd)

    _center(win, 780, 460)
    _modal(root, win)
    return action


def ensure_dll(root) -> bool:
    cfg_dir = G.load_config().get('game_dir')
    hint = G.normalize_game_dir(cfg_dir)
    if not hint:
        chosen = choose_game_dir_dialog(root, cfg_dir or '')
        if not chosen:
            return False
        hint = chosen
    for _ in range(20):
        info = G.inspect(hint)
        if info.get('state') == 'ok':
            G._log('DLL 检查通过 ' + info.get('dll', ''))
            return True
        G._log('DLL 检查未通过 state=%s msg=%s dir=%s' % (
            info.get('state'), info.get('message'), info.get('game_dir')))
        action = _dll_dialog(root, info)
        if action['value'] == 'exit':
            return False
        if action['value'] == 'skip':
            return True
        if action['value'] == 'refresh':
            hint = action.get('dir') or info.get('game_dir') or hint
            continue
        if action['value'] == 'replace':
            try:
                res = G.install_proxy(info.get('game_dir') or hint)
            except Exception as e:
                G._log('DLL 替换失败：' + str(e))
                messagebox.showerror('替换失败', str(e))
                hint = info.get('game_dir') or hint
                continue
            msg = '代理 DLL 已安装并通过校验。'
            if res.get('backup'):
                msg += f"\n原始文件已备份为：\n{res['backup']}"
            messagebox.showinfo('完成', msg)
            return True
    return False


def run_startup_gate() -> bool:
    root = tk.Tk()
    root.withdraw()
    try:
        if not show_disclaimer(root):
            return False
        return ensure_dll(root)
    finally:
        root.destroy()
