"""SP26 工具箱 — 功能汇总面板（Windows 窗口程序）。

统一控制：ESP 绘制、准星吸附、吸敌人、阵营识别/勾选、无限弹药、飞行。
ESP 覆盖层作为子进程启动/停止；其余功能通过代理 op 实时下发。

用法：python sp26_panel.py
"""
import importlib
import json
import math
import os
import queue
import struct
import subprocess
import sys
import threading
import traceback
import time
import tkinter as tk
from tkinter import ttk, colorchooser, messagebox

FROZEN = getattr(sys, 'frozen', False)
if FROZEN:
    HERE = os.path.dirname(os.path.abspath(sys.executable))
else:
    HERE = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(HERE, 'panel_runtime.log')


def log(msg):
    line = time.strftime('%Y-%m-%d %H:%M:%S ') + str(msg)
    try:
        print(line, flush=True)
    except Exception:
        pass
    try:
        with open(LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except Exception:
        pass


if sys.stdout is None or sys.stderr is None:
    try:
        _log = open(LOG_PATH, 'a', buffering=1, encoding='utf-8')
        sys.stdout = sys.stdout or _log
        sys.stderr = sys.stderr or _log
    except Exception:
        pass
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

sys.path.insert(0, HERE)

import ammo_probe
import sp26_team_palette as TP

CONFIG_ESP = os.path.join(HERE, 'esp_config.json')
CONFIG_PANEL = os.path.join(HERE, 'panel_config.json')
PY = sys.executable
CREATE_NO_WINDOW = 0x08000000
APP_VERSION = 'v1.3.1'

DEFAULT_KNOWN_TEAMS = (2, 3, 4, 5, 6, 7)

COLOR_DEFAULTS = {
    'friendly': [79, 195, 255],
    'friendly_txt': [168, 230, 255],
    'enemy': [255, 64, 64],
    'enemy_txt': [255, 208, 64],
    'unknown': [200, 200, 200],
    'hud': [0, 255, 144],
    'team_colors': {
        '2': [[255, 64, 64], [255, 170, 170]],
        '3': [[255, 150, 40], [255, 210, 140]],
        '4': [[255, 220, 60], [255, 245, 170]],
        '5': [[255, 90, 200], [255, 190, 235]],
        '6': [[190, 120, 255], [225, 190, 255]],
    },
}


def load_json(path, default):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def rgb_hex(c):
    return '#%02x%02x%02x' % (int(c[0]), int(c[1]), int(c[2]))


def hex_rgb(h):
    h = h.lstrip('#')
    return [int(h[i:i + 2], 16) for i in (0, 2, 4)]


def tint(c, f=0.45):
    return [int(c[i] + (255 - c[i]) * f) for i in range(3)]


def _run(cmd, timeout=90):
    try:
        p = subprocess.run(cmd, cwd=HERE, capture_output=True,
                           timeout=timeout, creationflags=CREATE_NO_WINDOW,
                           env={**os.environ, 'PYTHONUNBUFFERED': '1'})
        out = (p.stdout or b'') + (p.stderr or b'')
        for enc in ('utf-8', 'gbk'):
            try:
                return p.returncode, out.decode(enc).strip()
            except Exception:
                continue
        return p.returncode, out.decode('utf-8', 'replace').strip()
    except Exception as e:
        return -1, str(e)


def esp_cmd():
    if FROZEN:
        return [sys.executable, '--esp']
    return [PY, '-u', 'sp26_esp.py']


def patch_cmd(rest):
    if FROZEN:
        return [sys.executable, '--patch-ammo'] + list(rest)
    return [PY, '-u', 'sp26_patch.py'] + list(rest)


def god_cmd(rest):
    if FROZEN:
        return [sys.executable, '--god6'] + list(rest)
    return [PY, '-u', 'sp26_god6.py'] + list(rest)


def env_check():
    log('==== SP26 工具箱 启动自检 ====')
    log(f'版本={APP_VERSION} 打包={FROZEN} exe={sys.executable}')
    log(f'数据目录={HERE}')
    issues = []
    try:
        probe = os.path.join(HERE, '.write_test')
        with open(probe, 'w', encoding='utf-8') as f:
            f.write('x')
        os.remove(probe)
        log('目录写入 OK')
    except Exception as e:
        issues.append('目录不可写')
        log(f'目录写入失败：{e}')
    for mod in ('ammo_probe', 'sp26_ent', 'sp26_esp', 'sp26_patch', 'sp26_god6',
                'codtool.agent_client'):
        try:
            importlib.import_module(mod)
            log(f'内置模块 {mod} OK')
        except Exception as e:
            issues.append(f'缺少 {mod}')
            log(f'内置模块 {mod} 缺失：{e}')
    try:
        agent, info = ammo_probe.connect_readonly(ammo_probe.TOOLKIT, 49700)
        try:
            log(f"游戏代理 OK pid={info['pid']} name={info['name']} "
                f"base=0x{info['module_base']:X}")
        finally:
            agent.close()
    except Exception as e:
        issues.append('游戏代理未连接')
        log(f'游戏代理不可用：{e}')
    log('自检结果：' + ('正常' if not issues else ' | '.join(issues)))
    return issues


class AgentService:
    def __init__(self):
        self.a = None
        self.pid = 0
        self.base = 0
        self.lock = threading.Lock()
        self.err = ''

    def connect(self):
        try:
            a, info = ammo_probe.connect_readonly(ammo_probe.TOOLKIT, 49700)
            self.a = a
            self.pid = info.get('pid', 0)
            self.base = info.get('module_base', 0)
            self.err = ''
            return True
        except Exception as e:
            self.a = None
            self.pid = 0
            self.base = 0
            self.err = str(e)
            return False

    def call(self, name, *args, **kw):
        with self.lock:
            if self.a is None and not self.connect():
                raise RuntimeError('未连接游戏代理')
            try:
                return getattr(self.a, name)(*args, **kw)
            except Exception:
                try:
                    self.a.close()
                except Exception:
                    pass
                self.a = None
                raise


class EspManager:
    def __init__(self):
        self.proc = None
        self.log = open(os.path.join(HERE, 'panel_esp.log'), 'a', encoding='utf-8')

    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self):
        if self.running():
            return True
        try:
            self.proc = subprocess.Popen(
                esp_cmd(), cwd=HERE, creationflags=CREATE_NO_WINDOW,
                stdout=self.log, stderr=subprocess.STDOUT,
                env={**os.environ, 'PYTHONUNBUFFERED': '1'})
            return True
        except Exception:
            self.proc = None
            return False

    def stop(self):
        if self.running():
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                pass
        self.proc = None


class Poller(threading.Thread):
    def __init__(self, svc):
        super().__init__(daemon=True)
        self.svc = svc
        self.stop_flag = threading.Event()
        self.lock = threading.Lock()
        self.team_ok = None
        self.pid_seen = 0
        self.state = {'ok': False, 'pid': 0, 'aim': None, 'vac': None,
                      'team': None, 'team_ok': None, 'fly': None, 'err': ''}

    def _reconnect(self):
        try:
            if self.svc.a:
                self.svc.a.close()
        except Exception:
            pass
        self.svc.a = None
        return self.svc.connect()

    def run(self):
        while not self.stop_flag.is_set():
            st = dict(self.state)
            try:
                if self.svc.a is None:
                    if not self.svc.connect():
                        raise RuntimeError(self.svc.err)
                if self.svc.pid != self.pid_seen:
                    self.pid_seen = self.svc.pid
                    self.team_ok = None
                st['pid'] = self.svc.pid
                st['aim'] = self.svc.call('aim_get')
                st['vac'] = self.svc.call('vacuum_get')
                st['fly'] = self.svc.call('fly_get')
                if self.team_ok is None:
                    try:
                        st['team'] = self.svc.call('team_get')
                        self.team_ok = True
                    except Exception:
                        self.team_ok = False
                        st['team'] = None
                        self._reconnect()
                elif self.team_ok:
                    st['team'] = self.svc.call('team_get')
                else:
                    st['team'] = None
                st['team_ok'] = self.team_ok
                st['ok'] = True
                st['err'] = ''
            except Exception as e:
                st['ok'] = False
                st['err'] = str(e)
                self._reconnect()
            with self.lock:
                self.state = st
            self.stop_flag.wait(0.5)

    def get(self):
        with self.lock:
            return dict(self.state)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f'SP26 工具箱  {APP_VERSION}')
        self.geometry('820x680')
        self.minsize(820, 680)
        try:
            self.tk.call('tk', 'scaling', 1.2)
        except Exception:
            pass

        self.svc = AgentService()
        self.svc.connect()
        self.poller = Poller(self.svc)
        self.poller.start()
        self.esp = EspManager()

        self.settings = load_json(CONFIG_PANEL, {})
        self.colors = json.loads(json.dumps(COLOR_DEFAULTS))
        self.colors.update(self.settings.get('colors', {}))
        self.color_btns = {}
        self.color_frame = None
        self.drop_frame = None
        self.drop_vars = {}
        self._drop_selected = {2}
        self._known_teams = set(DEFAULT_KNOWN_TEAMS)
        self._scan_btns = []
        self._esp_team = None
        self._applied_pid = 0
        self._esp_desired = False
        self._esp_tries = 0
        self._esp_next_try = 0.0
        self._scan_queue = queue.Queue()
        self._god_queue = queue.Queue()
        self._spawn_queue = queue.Queue()
        self._god_busy = False
        self._god_want = False

        self._build()
        self._load_settings()
        self._esp_desired = bool(self.var_esp_on.get())
        self._issues = env_check()
        if self._issues:
            self.var_hint.set('启动自检：' + '；'.join(self._issues) + '（详见 panel_runtime.log）')
        else:
            self.var_hint.set('启动自检正常，游戏代理可用（日志 panel_runtime.log）')
        self.after(300, self._tick)
        self.protocol('WM_DELETE_WINDOW', self._on_close)

    # ---------------- UI ----------------
    def _build(self):
        bar = ttk.Frame(self, padding=(10, 6))
        bar.pack(fill='x')
        self.var_status = tk.StringVar(value='正在连接…')
        ttk.Label(bar, textvariable=self.var_status, font=('Microsoft YaHei', 10, 'bold')).pack(side='left')
        ttk.Button(bar, text='重连', width=6, command=self._reconnect).pack(side='right')

        nb = ttk.Notebook(self)
        nb.pack(fill='both', expand=True, padx=10, pady=(0, 8))
        self._tab_esp(nb)
        self._tab_aim(nb)
        self._tab_vac(nb)
        self._tab_team(nb)
        self._tab_tools(nb)
        self._tab_spawn(nb)

        self.var_hint = tk.StringVar(value='提示：ESP 覆盖层随面板启动/停止；取消勾选即可关闭。')
        ttk.Label(self, textvariable=self.var_hint, foreground='#666', padding=(10, 0, 10, 6)).pack(fill='x')

    def _tab_esp(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text='ESP 绘制')

        row = ttk.Frame(f)
        row.pack(fill='x', pady=(0, 6))
        self.var_esp_on = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text='启用 ESP', variable=self.var_esp_on,
                        command=self._toggle_esp).pack(side='left')
        self.lab_esp = ttk.Label(row, text='覆盖层：已停止', foreground='#a00')
        self.lab_esp.pack(side='left', padx=12)

        g = ttk.LabelFrame(f, text='显示选项', padding=8)
        g.pack(fill='x', pady=4)
        self.var_labels = tk.BooleanVar(value=True)
        self.var_corpse = tk.BooleanVar(value=True)
        self.var_livefov = tk.BooleanVar(value=False)
        self.var_draw_friend = tk.BooleanVar(value=True)
        self.var_draw_enemy = tk.BooleanVar(value=True)
        self.var_hud = tk.BooleanVar(value=True)
        ttk.Checkbutton(g, text='文字标签', variable=self.var_labels).grid(row=0, column=0, sticky='w')
        ttk.Checkbutton(g, text='尸体过滤', variable=self.var_corpse).grid(row=0, column=1, sticky='w')
        ttk.Checkbutton(g, text='实时 FOV', variable=self.var_livefov).grid(row=0, column=2, sticky='w')
        ttk.Checkbutton(g, text='绘制队友', variable=self.var_draw_friend).grid(row=0, column=3, sticky='w')
        ttk.Checkbutton(g, text='绘制敌人', variable=self.var_draw_enemy).grid(row=0, column=4, sticky='w')
        ttk.Checkbutton(g, text='绘制log', variable=self.var_hud).grid(row=0, column=5, sticky='w')
        ttk.Label(g, text='FOV').grid(row=1, column=0, sticky='e')
        self.var_fov = tk.StringVar(value='59')
        ttk.Spinbox(g, from_=40, to=110, textvariable=self.var_fov, width=6).grid(row=1, column=1, sticky='w')
        ttk.Label(g, text='ADS 倍率').grid(row=1, column=2, sticky='e')
        self.var_adszoom = tk.StringVar(value='1.955')
        ttk.Spinbox(g, from_=1.0, to=10.0, increment=0.05, textvariable=self.var_adszoom,
                    width=8).grid(row=1, column=3, sticky='w')
        ttk.Label(g, text='最大距离').grid(row=2, column=0, sticky='e')
        self.var_maxdist = tk.StringVar(value='2500')
        ttk.Spinbox(g, from_=200, to=10000, increment=100, textvariable=self.var_maxdist,
                    width=8).grid(row=2, column=1, sticky='w')
        ttk.Button(g, text='应用并重启 ESP', command=self._apply_esp).grid(
            row=2, column=3, sticky='e', padx=4)

        g2 = ttk.LabelFrame(f, text='颜色（点击色块修改）', padding=8)
        g2.pack(fill='x', pady=4)
        top2 = ttk.Frame(g2)
        top2.pack(fill='x', pady=(0, 4))
        self.btn_esp_scan = ttk.Button(top2, text='刷新队伍', command=self._scan_teams_async)
        self.btn_esp_scan.pack(side='left')
        self._scan_btns.append(self.btn_esp_scan)
        self.var_esp_teams = tk.StringVar(value='队伍色块按识别到的 team 生成')
        ttk.Label(top2, textvariable=self.var_esp_teams, foreground='#666').pack(side='left', padx=8)
        self.color_frame = ttk.Frame(g2)
        self.color_frame.pack(fill='x')
        self._rebuild_color_btns()
        self._refresh_color_btns()

        g3 = ttk.LabelFrame(f, text='游戏内快捷键（ESP 覆盖层运行时生效）', padding=8)
        g3.pack(fill='x', pady=4)
        ttk.Label(g3, text='F4 无敌      F5 无限弹药      F6 飞行      F7 方框      F8 自瞄',
                  foreground='#333').pack(anchor='w')
        ttk.Label(g3, text='每次切换会在游戏画面左上角显示 1 秒提示。',
                  foreground='#666').pack(anchor='w', pady=(2, 0))

    def _tab_aim(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text='准星吸附')
        row = ttk.Frame(f)
        row.pack(fill='x')
        self.var_aim_on = tk.BooleanVar(value=False)
        self.var_aim_hold = tk.BooleanVar(value=True)
        ttk.Checkbutton(row, text='启用吸附', variable=self.var_aim_on).pack(side='left')
        ttk.Checkbutton(row, text='按住右键触发（取消=常开）',
                        variable=self.var_aim_hold).pack(side='left', padx=16)
        ttk.Button(row, text='应用', command=self._apply_aim).pack(side='right')
        ttk.Button(row, text='标定说明',
                   command=lambda: self._flash('标定：开镜时自动标定；F8 现在是自瞄开关，按下会重置增益并自动重标')).pack(
            side='right', padx=6)

        g = ttk.LabelFrame(f, text='参数', padding=8)
        g.pack(fill='x', pady=6)
        self.aim_vars = {}
        specs = [('speed', '速度 ms', 4, 100, 1, 12),
                 ('strength', '力度 %', 10, 100, 5, 60),
                 ('smooth', '平滑 %', 0, 90, 5, 0),
                 ('lead', '提前量 ms', 0, 200, 5, 40)]
        for i, (k, label, lo, hi, step, dflt) in enumerate(specs):
            ttk.Label(g, text=label).grid(row=i, column=0, sticky='e', pady=2)
            var = tk.DoubleVar(value=dflt)
            ttk.Scale(g, from_=lo, to=hi, variable=var, orient='horizontal', length=220).grid(
                row=i, column=1, sticky='w')
            lab = ttk.Label(g, text=str(dflt), width=5)
            lab.grid(row=i, column=2, sticky='w')
            var.trace_add('write', lambda *a, v=var, l=lab: l.configure(text=f'{v.get():.0f}'))
            self.aim_vars[k] = var
        ttk.Label(g, text='角度锥').grid(row=0, column=3, sticky='e')
        self.var_cone = tk.StringVar(value='8')
        ttk.Spinbox(g, from_=0.5, to=90.0, increment=0.5, textvariable=self.var_cone,
                    width=7).grid(row=0, column=4, sticky='w')
        ttk.Label(g, text='最大距离').grid(row=1, column=3, sticky='e')
        self.var_aim_max = tk.StringVar(value='3000')
        ttk.Spinbox(g, from_=100, to=10000, increment=100, textvariable=self.var_aim_max,
                    width=7).grid(row=1, column=4, sticky='w')
        self.var_chain = tk.BooleanVar(value=True)
        ttk.Checkbutton(g, text='连吸', variable=self.var_chain).grid(row=3, column=3, sticky='w')
        self.var_chain_r = tk.StringVar(value='600')
        ttk.Spinbox(g, from_=50, to=5000, increment=50, textvariable=self.var_chain_r,
                    width=7).grid(row=3, column=4, sticky='w')

        tg = ttk.LabelFrame(f, text='玩家阵营（勾选你所在的阵营，自瞄将跳过它）', padding=8)
        tg.pack(fill='x', pady=6)
        top = ttk.Frame(tg)
        top.pack(fill='x')
        self.btn_scan = ttk.Button(top, text='识别阵营', command=self._scan_teams_async)
        self.btn_scan.pack(side='left')
        self.var_aim_scan = tk.StringVar(value='点“识别阵营”扫描当前关卡的活体 NPC')
        ttk.Label(top, textvariable=self.var_aim_scan, foreground='#666').pack(side='left', padx=10)
        self.var_aim_team = tk.StringVar(value='7')
        self.aim_team_frame = ttk.Frame(tg)
        self.aim_team_frame.pack(fill='x', pady=(6, 0))
        self._aim_teams = {}
        self._scan_busy = False

        self.lab_aim = ttk.Label(f, text='自瞄状态：—')
        self.lab_aim.pack(fill='x', pady=(8, 0))

    def _tab_vac(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text='吸敌人')
        row = ttk.Frame(f)
        row.pack(fill='x')
        self.var_vac_on = tk.BooleanVar(value=False)
        ttk.Checkbutton(row, text='启用吸敌人', variable=self.var_vac_on).pack(side='left')
        ttk.Button(row, text='应用', command=self._apply_vac).pack(side='right')
        g = ttk.LabelFrame(f, text='参数', padding=8)
        g.pack(fill='x', pady=6)
        pairs = [('距离 m', 'dist', '4.0'), ('上抬 m', 'up', '0.0'),
                 ('圆环 m', 'ring', '0.6'), ('永久排除 team', 'excl', '7'),
                 ('只吸 team（0=全部）', 'only', '0')]
        self.vac_vars = {}
        for i, (label, key, dflt) in enumerate(pairs):
            ttk.Label(g, text=label).grid(row=i // 3, column=(i % 3) * 2, sticky='e', padx=4, pady=3)
            v = tk.StringVar(value=dflt)
            ttk.Entry(g, textvariable=v, width=8).grid(row=i // 3, column=(i % 3) * 2 + 1,
                                                       sticky='w', pady=3)
            self.vac_vars[key] = v
        self.var_vac_head = tk.BooleanVar(value=True)
        ttk.Checkbutton(g, text='头部跟随', variable=self.var_vac_head).grid(
            row=2, column=0, columnspan=2, sticky='w', pady=3)
        self.lab_vac = ttk.Label(f, text='吸敌状态：—')
        self.lab_vac.pack(fill='x', pady=(8, 0))

    def _tab_team(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text='阵营识别')
        g = ttk.LabelFrame(f, text='友军阵营（自动识别 + 手动勾选）', padding=8)
        g.pack(fill='x')
        self.var_team_auto = tk.BooleanVar(value=True)
        ttk.Checkbutton(g, text='自动识别（每关开局采样最近 3 个 NPC）',
                        variable=self.var_team_auto, command=self._team_auto_changed).pack(anchor='w')
        row = ttk.Frame(g)
        row.pack(fill='x', pady=4)
        ttk.Label(row, text='友军 team：').pack(side='left')
        self.var_team_manual = tk.StringVar(value='7')
        self.cmb_team = ttk.Combobox(row, textvariable=self.var_team_manual, width=6,
                                     values=[str(i) for i in range(32)])
        self.cmb_team.pack(side='left')
        ttk.Button(row, text='重采样', command=self._team_resample).pack(side='left', padx=8)
        ttk.Button(row, text='应用阵营设置', command=self._apply_team).pack(side='right')
        self.lab_team = ttk.Label(g, text='阵营识别：—', foreground='#333')
        self.lab_team.pack(anchor='w', pady=(4, 0))

        g2 = ttk.LabelFrame(f, text='额外丢弃的阵营（勾选后 ESP/自瞄/吸敌都不处理）', padding=8)
        g2.pack(fill='x', pady=8)
        top2 = ttk.Frame(g2)
        top2.pack(fill='x', pady=(0, 4))
        self.btn_team_scan = ttk.Button(top2, text='刷新队伍', command=self._scan_teams_async)
        self.btn_team_scan.pack(side='left')
        self._scan_btns.append(self.btn_team_scan)
        self.var_team_teams = tk.StringVar(value='列表来自识别结果与已保存配置')
        ttk.Label(top2, textvariable=self.var_team_teams, foreground='#666').pack(side='left', padx=8)
        self.drop_frame = ttk.Frame(g2)
        self.drop_frame.pack(fill='x')
        self._rebuild_drop_teams()
        ttk.Label(f, text='说明：自动识别失败时，勾选正确的友军 team 后点“应用阵营设置”即可。\n'
                          '该设置同时作用于 ESP 颜色、自瞄和吸敌人。',
                  foreground='#666').pack(anchor='w', pady=4)

    def _tab_tools(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text='变态功能')
        g0 = ttk.LabelFrame(f, text='无敌（god6：只让本地玩家免伤，敌人正常受伤）', padding=8)
        g0.pack(fill='x')
        self.var_god = tk.BooleanVar(value=False)
        self.chk_god = ttk.Checkbutton(g0, text='开启无敌', variable=self.var_god,
                                       command=self._god_toggle)
        self.chk_god.pack(side='left')
        ttk.Button(g0, text='刷新状态', command=self._god_refresh).pack(side='left', padx=8)
        self.lab_god = ttk.Label(g0, text='状态：未知')
        self.lab_god.pack(side='left', padx=6)

        g = ttk.LabelFrame(f, text='无限弹药', padding=8)
        g.pack(fill='x')
        ttk.Button(g, text='开启', command=lambda: self._ammo(True)).pack(side='left')
        ttk.Button(g, text='关闭', command=lambda: self._ammo(False)).pack(side='left', padx=8)
        self.lab_ammo = ttk.Label(g, text='状态未知')
        self.lab_ammo.pack(side='left', padx=12)

        g2 = ttk.LabelFrame(f, text='飞行（DLL 内，Space 上升 / C 下降）', padding=8)
        g2.pack(fill='x', pady=8)
        self.var_fly = tk.BooleanVar(value=False)
        ttk.Checkbutton(g2, text='启用飞行', variable=self.var_fly).pack(side='left')
        ttk.Label(g2, text='速度倍率').pack(side='left', padx=(16, 4))
        self.var_fly_spd = tk.StringVar(value='4.0')
        ttk.Spinbox(g2, from_=1.0, to=10.0, increment=0.5, textvariable=self.var_fly_spd,
                    width=6).pack(side='left')
        ttk.Button(g2, text='应用', command=self._apply_fly).pack(side='left', padx=8)
        self.lab_fly = ttk.Label(g2, text='飞行：—')
        self.lab_fly.pack(side='left', padx=8)

        g3 = ttk.LabelFrame(f, text='日志 / 配置', padding=8)
        g3.pack(fill='x', pady=8)
        ttk.Button(g3, text='打开 ESP 日志', command=lambda: os.startfile(
            os.path.join(HERE, 'panel_esp.log'))).pack(side='left')
        ttk.Button(g3, text='打开运行日志', command=lambda: os.startfile(
            LOG_PATH)).pack(side='left', padx=8)
        ttk.Button(g3, text='打开代理日志', command=lambda: os.startfile(
            os.path.join(os.environ.get('TEMP', '.'), 'codtool_agent.log'))).pack(side='left', padx=8)
        ttk.Button(g3, text='打开配置目录', command=lambda: os.startfile(HERE)).pack(side='left')

        ttk.Label(f, text='注意：无敌与弹药都是运行时补丁，游戏重启后自然失效，需重新开启；\n'
                          '无敌关闭面板后仍然生效，必须取消勾选或点“刷新状态”确认。',
                  foreground='#a00').pack(anchor='w', pady=8)

    def _tab_spawn(self, nb):
        f = ttk.Frame(nb, padding=10)
        nb.add(f, text='刷枪')
        row = ttk.Frame(f)
        row.pack(fill='x', pady=(0, 6))
        ttk.Button(row, text='刷新枪表', command=self._spawn_refresh).pack(side='left')
        self.lab_spawn = ttk.Label(row, text='未读取')
        self.lab_spawn.pack(side='left', padx=12)

        body = ttk.Frame(f)
        body.pack(fill='both', expand=True)
        self.spawn_list = tk.Listbox(body, height=12, exportselection=False)
        sb = ttk.Scrollbar(body, orient='vertical', command=self.spawn_list.yview)
        self.spawn_list.configure(yscrollcommand=sb.set)
        self.spawn_list.pack(side='left', fill='both', expand=True)
        sb.pack(side='right', fill='y')

        gf = ttk.LabelFrame(f, text='未注册武器页（合成注册；禁止开 F5；发射器暂不支持）', padding=8)
        gf.pack(fill='both', expand=True, pady=6)
        self.page_list = tk.Listbox(gf, height=6, exportselection=False)
        sb2 = ttk.Scrollbar(gf, orient='vertical', command=self.page_list.yview)
        self.page_list.configure(yscrollcommand=sb2.set)
        self.page_list.pack(side='left', fill='both', expand=True)
        sb2.pack(side='right', fill='y')
        ttk.Button(gf, text='合成刷枪', command=self._synth_selected).pack(side='right', padx=4)
        ttk.Button(gf, text='刷新页表', command=self._spawn_pages_refresh).pack(side='right', padx=4)

        g = ttk.LabelFrame(f, text='发枪参数', padding=8)
        g.pack(fill='x', pady=6)
        ttk.Label(g, text='弹匣').pack(side='left')
        self.var_spawn_mag = tk.StringVar(value='30')
        ttk.Spinbox(g, from_=1, to=300, textvariable=self.var_spawn_mag,
                    width=6).pack(side='left', padx=(2, 12))
        ttk.Label(g, text='备弹').pack(side='left')
        self.var_spawn_reserve = tk.StringVar(value='210')
        ttk.Spinbox(g, from_=0, to=999, textvariable=self.var_spawn_reserve,
                    width=6).pack(side='left', padx=(2, 12))
        self.btn_spawn = ttk.Button(g, text='刷到手上', command=self._spawn_selected)
        self.btn_spawn.pack(side='left')
        self.lab_spawn_status = ttk.Label(g, text='—')
        self.lab_spawn_status.pack(side='left', padx=10)

        ttk.Label(f, text='说明：选中一把枪后点“刷到手上”，脚下会生成可拾取武器，低头按拾取键即可。\n'
                          '本关没有可拾取的 type-3 实体时，会自动改为直接装备到当前槽（跳过拾取）。\n'
                          '拾取/直装都会替换当前手持槽；只列出本关已加载的武器（含任务配件）。',
                  foreground='#666').pack(anchor='w', pady=4)
        self._spawn_rows = []
        self._page_rows = []

    # ---------------- actions ----------------
    def _svc_act(self, name, *args, **kw):
        try:
            return self.svc.call(name, *args, **kw)
        except Exception as e:
            self._flash(f'操作失败：{e}')
            return None

    def _flash(self, text):
        self.var_hint.set(text)

    def _spawn_refresh(self):
        self.lab_spawn.configure(text='读取中…')

        def work():
            try:
                import sp26_spawner as S
                sp = S.Spawner(lambda a, n: self.svc.call('read', a, n),
                               lambda a, d: self.svc.call('write', a, d), self.svc.base)
                rows = sp.armory()
                self._spawn_queue.put(('rows', rows))
            except Exception as exc:
                self._spawn_queue.put(('error', '读取枪表失败：' + str(exc)))

        threading.Thread(target=work, daemon=True).start()

    def _render_armory(self, rows):
        self._spawn_rows = rows
        self.spawn_list.delete(0, 'end')
        for r in rows:
            self.spawn_list.insert('end',
                                   f"{r['label']:<14} h{r['handle']:<3} v{r['variant']} "
                                   f"att {r['attachments']:016X} refs {r['refs']}")
        self.lab_spawn.configure(text=f'{len(rows)} 把可用武器')

    def _spawn_selected(self):
        sel = self.spawn_list.curselection()
        if not sel:
            self._flash('先刷新枪表并选中一把武器')
            return
        row = self._spawn_rows[sel[0]]
        try:
            mag = max(1, int(self.var_spawn_mag.get()))
            reserve = max(0, int(self.var_spawn_reserve.get()))
        except ValueError:
            self._flash('弹药参数必须是整数')
            return
        self.btn_spawn.configure(state='disabled')
        self.lab_spawn_status.configure(text='生成中…', foreground='#333')

        def work():
            try:
                import sp26_spawner as S
                sp = S.Spawner(lambda a, n: self.svc.call('read', a, n),
                               lambda a, d: self.svc.call('write', a, d), self.svc.base)

                def prog(m):
                    self._spawn_queue.put(('status', m))

                try:
                    res = sp.spawn(row['handle'], mag=mag, reserve=reserve, timeout=20,
                                   progress=prog)
                except S.SpawnError as exc:
                    msg = str(exc)
                    if ('没有可用的 type-3 供体' in msg or '没有空闲供体' in msg
                            or '未检测到拾取' in msg):
                        prog('本关无拾取物，改用直接装备')
                        res = sp.direct_equip(row['handle'], mag=mag, reserve=reserve,
                                              progress=prog)
                    else:
                        raise
                self._spawn_queue.put(('done', res))
            except Exception as exc:
                self._spawn_queue.put(('error', '发枪失败：' + str(exc)))
            finally:
                self._spawn_queue.put(('btn', 'normal'))

        threading.Thread(target=work, daemon=True).start()

    def _spawn_done(self, res):
        if res.get('mode') == 'direct':
            self.lab_spawn_status.configure(
                text=f"直接装备 {res['name']} h{res['handle']} 槽{res['slot']} "
                     f"{res['mag']}/{res['reserve']}", foreground='#080')
            self._flash('本关无拾取物：已直接装备到当前槽')
        else:
            self.lab_spawn_status.configure(
                text=f"已发枪 {res['name']} h{res['handle']} 槽{res['slot']} "
                     f"{res['mag']}/{res['reserve']}", foreground='#080')
            self._flash('发枪成功，已装备到当前槽')

    def _spawn_failed(self, msg):
        self.lab_spawn_status.configure(text=msg, foreground='#a00')
        self._flash(msg)

    def _spawn_pages_refresh(self):
        def work():
            try:
                import sp26_spawner as S
                sp = S.Spawner(lambda a, n: self.svc.call('read', a, n),
                               lambda a, d: self.svc.call('write', a, d), self.svc.base)
                pages = sp.weapon_pages()
                self._spawn_queue.put(('pages', pages))
            except Exception as exc:
                self._spawn_queue.put(('error', '页表读取失败：' + str(exc)))

        threading.Thread(target=work, daemon=True).start()

    def _render_pages(self, pages):
        self._page_rows = pages
        self.page_list.delete(0, 'end')
        for p in pages:
            tag = '已注册' if p['live'] else '未注册'
            self.page_list.insert('end', f"{p['label']:<14} page {p['page']:>3} {tag}")

    def _synth_selected(self):
        sel = self.page_list.curselection()
        if not sel:
            self._flash('先刷新页表并选中一个武器页')
            return
        row = self._page_rows[sel[0]]
        try:
            mag = max(1, int(self.var_spawn_mag.get()))
            reserve = max(0, int(self.var_spawn_reserve.get()))
        except ValueError:
            self._flash('弹药参数必须是整数')
            return
        self.btn_spawn.configure(state='disabled')
        self.lab_spawn_status.configure(text='合成注册中…', foreground='#333')

        def work():
            try:
                import sp26_spawner as S
                sp = S.Spawner(lambda a, n: self.svc.call('read', a, n),
                               lambda a, d: self.svc.call('write', a, d), self.svc.base)
                rows = sp.armory()
                if not rows:
                    raise RuntimeError('没有可用的模板武器')
                prefix = '_'.join(row['name'].split('_')[:2])
                cands = [r for r in rows if r['name'].startswith(prefix)]
                if not cands and '_me_' in row['name']:
                    cands = [r for r in rows if '_me_' in r['name']]
                if not cands:
                    cands = [r for r in rows if r['name'].startswith('rex_')
                             and not r['name'].startswith('rex_me_')]
                template = (cands or rows)[0]['handle']
                prog = lambda m: self._spawn_queue.put(('status', m))
                try:
                    res = sp.synthetic_spawn(
                        row['page'], template, mag=mag, reserve=reserve, timeout=20,
                        progress=prog)
                except S.SpawnError as exc:
                    msg = str(exc)
                    if ('没有可用的 type-3 供体' in msg or '没有空闲供体' in msg
                            or '未检测到拾取' in msg):
                        prog('本关无拾取物，改用合成后直接装备')
                        res = sp.synthetic_direct_equip(
                            row['page'], template, mag=mag, reserve=reserve,
                            progress=prog)
                    else:
                        raise
                self._spawn_queue.put(('synth', res))
            except Exception as exc:
                self._spawn_queue.put(('error', '合成刷枪失败：' + str(exc)))
            finally:
                self._spawn_queue.put(('btn', 'normal'))

        threading.Thread(target=work, daemon=True).start()

    def _synth_done(self, res):
        if res.get('mode') == 'direct':
            self.lab_spawn_status.configure(
                text=f"合成+直接装备 {res['name']} page{res['page']} h{res['handle']} "
                     f"槽{res['slot']} {res['mag']}/{res['reserve']}", foreground='#080')
            self._flash('本关无拾取物：已合成注册并直接装备；请勿开启 F5')
        else:
            self.lab_spawn_status.configure(
                text=f"合成注册 {res['name']} page{res['page']} h{res['handle']} 槽{res['slot']} "
                     f"{res['mag']}/{res['reserve']}", foreground='#080')
            self._flash('合成刷枪成功；请勿开启 F5 无限弹药')

    def _reconnect(self):
        self.svc.connect()
        self.poller.state['team_ok'] = None

    def _toggle_esp(self):
        want = bool(self.var_esp_on.get())
        self._esp_desired = want
        if want:
            self._write_esp_config()
            if not self.esp.start():
                self._esp_desired = False
                self.var_esp_on.set(False)
                self._flash('ESP 启动失败，请查看 panel_esp.log')
                return
            self._esp_tries = 0
            self._flash('ESP 覆盖层已启动')
        else:
            self.esp.stop()
            self._flash('ESP 覆盖层已停止')

    def _write_esp_config(self):
        cfg = load_json(CONFIG_ESP, {})
        try:
            vf = float(self.var_fov.get())
        except Exception:
            vf = float(cfg.get('vfov', 59.0))
        cfg['vfov'] = vf
        cfg.pop('f_px', None)          # 让覆盖层按实际客户区高度重算 f
        cfg['live_fov'] = bool(self.var_livefov.get())
        try:
            cfg['ads_zoom'] = float(self.var_adszoom.get())
        except Exception:
            pass
        try:
            cfg['max_dist'] = float(self.var_maxdist.get())
        except Exception:
            pass
        cfg['labels'] = bool(self.var_labels.get())
        cfg['corpse_filter'] = bool(self.var_corpse.get())
        cfg['draw_friendly'] = bool(self.var_draw_friend.get())
        cfg['draw_enemy'] = bool(self.var_draw_enemy.get())
        cfg['hud'] = bool(self.var_hud.get())
        try:
            cfg['aim'] = {
                'on': bool(self.var_aim_on.get()),
                'hold': bool(self.var_aim_hold.get()),
                'cone': float(self.var_cone.get()),
                'max_dist': int(float(self.var_aim_max.get())),
                'team': int(self.var_aim_team.get() or 7),
                'chain': bool(self.var_chain.get()),
                'chain_radius': int(float(self.var_chain_r.get())),
                'speed': int(self.aim_vars['speed'].get()),
                'strength': int(self.aim_vars['strength'].get()),
                'smooth': int(self.aim_vars['smooth'].get()),
                'lead': int(self.aim_vars['lead'].get()),
            }
            cfg['fly_speed'] = float(self.var_fly_spd.get())
        except Exception:
            pass
        cfg['team'] = int(self.var_team_manual.get() or 7)
        cfg['known_teams'] = sorted(self._known_teams)
        cfg['drop'] = [t for t, v in self.drop_vars.items() if v.get()]
        cfg['colors'] = {k: v for k, v in self.colors.items() if k != 'team_colors'}
        cfg['colors']['team_colors'] = self.colors.get('team_colors', {})
        save_json(CONFIG_ESP, cfg)

    def _apply_esp(self):
        self._write_esp_config()
        if self.esp.running():
            self.esp.stop()
            time.sleep(0.2)
            self.esp.start()
        self._flash('ESP 设置已应用' + ('（已重启覆盖层）' if self.var_esp_on.get() else ''))

    def _pick_color(self, key):
        if key.startswith('t'):
            k = key[1:]
            pair = self.colors.get('team_colors', {}).get(k)
            cur0 = pair[0] if pair else list(TP.team_rgb(int(k))[0])
        else:
            cur0 = self.colors.get(key) or [255, 255, 255]
        c = colorchooser.askcolor(color=rgb_hex(cur0), title='选择颜色')
        if not c or not c[0]:
            return
        rgbv = [int(x) for x in c[0]]
        if key.startswith('t'):
            t = key[1:]
            self.colors.setdefault('team_colors', {})[t] = [rgbv, tint(rgbv)]
        else:
            self.colors[key] = rgbv
            if key == 'friendly':
                self.colors['friendly_txt'] = tint(rgbv)
            elif key == 'enemy':
                self.colors['enemy_txt'] = tint(rgbv)
        self._refresh_color_btns()

    def _refresh_color_btns(self):
        for key, btn in self.color_btns.items():
            try:
                if key.startswith('t'):
                    c = self.colors.get('team_colors', {}).get(
                        key[1:], [list(TP.team_rgb(int(key[1:]))[0])])[0]
                else:
                    c = self.colors.get(key, [255, 255, 255])
                btn.configure(bg=rgb_hex(c))
            except Exception:
                pass

    def _rebuild_color_btns(self):
        if self.color_frame is None:
            return
        for w in self.color_frame.winfo_children():
            w.destroy()
        self.color_btns = {}
        items = [('friendly', '队友'), ('enemy', '敌人默认'), ('unknown', '未知'),
                 ('hud', 'HUD')]
        cfg_t = {int(k) for k in self.colors.get('team_colors', {}) if str(k).isdigit()}
        teams = sorted({t for t in self._known_teams if 0 <= t < 32} | cfg_t)
        items += [(f't{t}', f'T{t}') for t in teams]
        for i, (key, label) in enumerate(items):
            r, c = divmod(i, 6)
            cell = ttk.Frame(self.color_frame)
            cell.grid(row=r, column=c, padx=6, pady=3, sticky='w')
            ttk.Label(cell, text=label).pack(side='left')
            b = tk.Button(cell, width=4, relief='raised', command=lambda k=key: self._pick_color(k))
            b.pack(side='left', padx=3)
            self.color_btns[key] = b

    def _refresh_known_teams(self, teams=()):
        added = set()
        for t in teams:
            try:
                t = int(t)
            except Exception:
                continue
            if 0 <= t < 32 and t not in self._known_teams:
                self._known_teams.add(t)
                added.add(t)
        if added or not self.color_btns:
            self._rebuild_drop_teams()
            self._rebuild_color_btns()
            self._refresh_color_btns()
        return added

    def _rebuild_drop_teams(self):
        if self.drop_frame is None:
            return
        if self.drop_vars:
            sel = {t for t, v in self.drop_vars.items() if v.get()}
        else:
            sel = {t for t in self._drop_selected if 0 <= t < 32}
        teams = {t for t in self._known_teams if 0 <= t < 32} | sel | set(self.drop_vars)
        if not teams:
            teams = set(DEFAULT_KNOWN_TEAMS)
        self._drop_selected = set(sel)
        for w in self.drop_frame.winfo_children():
            w.destroy()
        self.drop_vars = {}
        for i, t in enumerate(sorted(teams)):
            v = tk.BooleanVar(value=(t in sel))
            ttk.Checkbutton(self.drop_frame, text=f'T{t}', variable=v).grid(
                row=i // 8, column=i % 8, sticky='w', padx=8, pady=2)
            self.drop_vars[t] = v

    def _apply_aim(self):
        try:
            on = bool(self.var_aim_on.get())
            hold = bool(self.var_aim_hold.get())
            if not self._svc_act('aim_set', on, hold=hold, vk=0x02,
                                 cone10=int(float(self.var_cone.get()) * 10),
                                 max_dist=int(float(self.var_aim_max.get())),
                                 team=int(self.var_aim_team.get() or 7), head_dz=62.0):
                return
            self._svc_act('aim_cfg', int(self.aim_vars['speed'].get()),
                          int(self.aim_vars['strength'].get()),
                          int(self.aim_vars['smooth'].get()),
                          int(self.aim_vars['lead'].get()))
            self._svc_act('aim_chain', bool(self.var_chain.get()),
                          int(float(self.var_chain_r.get())))
            self._write_esp_config()
            self._flash('自瞄参数已应用')
        except Exception as e:
            self._flash(f'自瞄参数错误：{e}')

    def _scan_teams_async(self):
        if self._scan_busy:
            return
        self._scan_busy = True
        for b in self._scan_btns:
            b.configure(state='disabled')
        self.btn_scan.configure(state='disabled')
        self.var_aim_scan.set('识别中…')
        try:
            self.var_team_teams.set('识别中…')
            self.var_esp_teams.set('识别中…')
        except Exception:
            pass
        threading.Thread(target=self._scan_teams_worker, daemon=True).start()

    def _scan_teams_worker(self):
        counts, err = {}, ''
        try:
            import sp26_ent as E
            agent, base, ent_base, _cnt = E.connect()
            try:
                for r in E.read_slots(agent, ent_base, 2048):
                    if r['idx'] == 0 or not (0 < r['hp'] <= 10000):
                        continue
                    cls = r['p180']
                    if not (base + 0x1000 <= cls < base + 0x20000000):
                        continue
                    d = agent.read(cls + 0x24, 4)
                    if not d or len(d) != 4:
                        continue
                    team = struct.unpack('<I', d)[0]
                    if team < 32:
                        counts[team] = counts.get(team, 0) + 1
            finally:
                agent.close()
        except Exception as e:
            err = str(e)
        self._scan_queue.put((counts, err))

    def _scan_teams_done(self, counts, err):
        self._scan_busy = False
        for b in self._scan_btns:
            b.configure(state='normal')
        self.btn_scan.configure(state='normal')
        if err:
            self.var_aim_scan.set('识别失败：' + err)
            for v in ('var_team_teams', 'var_esp_teams'):
                try:
                    getattr(self, v).set('识别失败：' + err)
                except Exception:
                    pass
            return
        if not counts:
            self._render_team_radios({})
            self.var_aim_scan.set('未识别到活体阵营（进关卡后再试）')
            for v in ('var_team_teams', 'var_esp_teams'):
                try:
                    getattr(self, v).set('未识别到活体阵营（进关卡后再试）')
                except Exception:
                    pass
            return
        self._render_team_radios(counts)
        added = self._refresh_known_teams(counts)
        teams = sorted(counts)
        detail = '  '.join(f'T{t}×{counts[t]}' for t in teams)
        log(f'手动识别阵营：{detail}')
        note = f'识别到 {detail}' + (f'；新增 T{",T".join(map(str, sorted(added)))}' if added else '')
        self.var_aim_scan.set(f'{note}；已勾选 T{self.var_aim_team.get()}，点“应用”生效')
        try:
            self.var_team_teams.set(note)
            self.var_esp_teams.set(note)
        except Exception:
            pass

    def _render_team_radios(self, teams):
        for w in self.aim_team_frame.winfo_children():
            w.destroy()
        self._aim_teams = dict(teams)
        if not teams:
            ttk.Label(self.aim_team_frame, text='（无）', foreground='#a00').pack(side='left')
            return
        names = [str(t) for t in teams]
        if self.var_aim_team.get() not in names:
            det = None
            st = self.poller.get().get('team')
            if st and len(st) > 2 and isinstance(st[2], int) and st[2] >= 0:
                det = str(st[2])
            if det in names:
                self.var_aim_team.set(det)
            else:
                best = max(teams, key=lambda t: teams[t] or 0)
                self.var_aim_team.set(str(best))
        for i, t in enumerate(sorted(teams)):
            n = teams[t]
            txt = f'T{t}' + (f'  ×{n}' if n else '')
            ttk.Radiobutton(self.aim_team_frame, text=txt, variable=self.var_aim_team,
                            value=str(t), command=self._aim_team_picked).grid(
                row=i // 6, column=i % 6, sticky='w', padx=6, pady=2)

    def _aim_team_picked(self):
        self._flash(f'已勾选玩家阵营 T{self.var_aim_team.get()}，点“应用”生效')

    def _apply_vac(self):
        try:
            on = bool(self.var_vac_on.get())
            dist = int(round(float(self.vac_vars['dist'].get()) * 100))
            up = int(round(float(self.vac_vars['up'].get()) * 100))
            ring = int(round(float(self.vac_vars['ring'].get()) * 100))
            excl = int(self.vac_vars['excl'].get())
            only = int(self.vac_vars['only'].get())
            flags = 7 if self.var_vac_head.get() else 6
            if self._svc_act('vacuum_set', on, dist, up, ring, excl, only, flags) is None:
                return
            self._flash('吸敌参数已应用')
        except Exception as e:
            self._flash(f'吸敌参数错误：{e}')

    def _team_auto_changed(self):
        self.cmb_team.configure(state='disabled' if self.var_team_auto.get() else 'readonly')

    def _team_mask(self):
        m = 0
        for t, v in self.drop_vars.items():
            if v.get():
                m |= 1 << t
        return m

    def _apply_team(self, resample=False, restart_esp=True):
        auto = bool(self.var_team_auto.get())
        try:
            manual = int(self.var_team_manual.get())
        except Exception:
            manual = 7
        if not auto:
            manual = max(1, min(31, manual))
        ok = self._svc_act('team_cfg', auto, self._team_mask(),
                           manual if not auto else 0, resample)
        if ok is None:
            return
        self._write_esp_config()
        if restart_esp and self.esp.running():
            self.esp.stop()
            time.sleep(0.2)
            self.esp.start()
        self._flash('阵营设置已应用' + ('（重采样中）' if resample else ''))

    def _apply_all_saved(self):
        self._apply_aim()
        self._apply_vac()
        self._apply_team(restart_esp=False)
        self._apply_fly()
        if self._esp_desired and not self.esp.running():
            self._write_esp_config()
            self.esp.start()
        self._god_refresh()
        self._flash('已按保存的设置重新挂载到当前游戏进程')

    def _team_resample(self):
        if self.var_team_auto.get():
            self._apply_team(resample=True)
        else:
            self._flash('自动识别已关闭：手动选择友军 team 后点“应用阵营设置”')

    def _ammo(self, on):
        code, out = _run(patch_cmd(['on' if on else 'off', 'ammo']))
        tail = out.splitlines()[-1] if out else ''
        self.lab_ammo.configure(text=('成功：' if code == 0 else f'失败({code})：') + tail,
                                foreground='#080' if code == 0 else '#a00')

    def _god_toggle(self):
        self._god_want = bool(self.var_god.get())
        self._god_run('on' if self._god_want else 'off')

    def _god_refresh(self):
        self._god_run('status')

    def _god_run(self, mode):
        if self._god_busy:
            self.var_god.set(self._god_want)
            return
        self._god_busy = True
        self.chk_god.configure(state='disabled')
        self.var_god.set(self._god_want)
        busy = {'on': '正在开启…', 'off': '正在关闭…'}.get(mode, '查询中…')
        self.lab_god.configure(text='状态：' + busy, foreground='#666')
        threading.Thread(target=self._god_worker, args=(mode,), daemon=True).start()

    def _god_worker(self, mode):
        code, out = _run(god_cmd([mode]), timeout=40)
        self._god_queue.put((mode, code, out))

    def _god_done(self, mode, code, out):
        self._god_busy = False
        self.chk_god.configure(state='normal')
        tail = out.splitlines()[-1] if out else ''
        if code != 0:
            if mode in ('on', 'off'):
                self._god_want = not self._god_want
                self.var_god.set(self._god_want)
            self.lab_god.configure(text=f'状态：失败({code}) {tail}', foreground='#a00')
            log(f'无敌 {mode} 失败 code={code}：{tail}')
            return
        if mode == 'status':
            first = (out.splitlines() or [''])[0]
            if '已生效' in first:
                self._god_want = True
                self.var_god.set(True)
                self.lab_god.configure(text='状态：已开启', foreground='#080')
            elif '原始' in first:
                self._god_want = False
                self.var_god.set(False)
                self.lab_god.configure(text='状态：未开启', foreground='#333')
            else:
                self.lab_god.configure(text='状态：未知（字节不符）', foreground='#a80')
        else:
            on = mode == 'on'
            self._god_want = on
            self.var_god.set(on)
            self.lab_god.configure(text='状态：已开启' if on else '状态：已关闭',
                                   foreground='#080' if on else '#333')
            log(f'无敌 {"开启" if on else "关闭"}：{tail}')

    def _apply_fly(self):
        try:
            on = bool(self.var_fly.get())
            mult = float(self.var_fly_spd.get())
            if self._svc_act('fly_set', on, 0, int(round(mult * 10)), 0x20, 0x43,
                             0, 0) is None:
                return
            self._write_esp_config()
            self._flash('飞行设置已应用')
        except Exception as e:
            self._flash(f'飞行参数错误：{e}')

    # ---------------- polling ----------------
    def _tick(self):
        try:
            counts, err = self._scan_queue.get_nowait()
        except queue.Empty:
            pass
        else:
            self._scan_teams_done(counts, err)
        try:
            mode, code, out = self._god_queue.get_nowait()
        except queue.Empty:
            pass
        else:
            self._god_done(mode, code, out)
        while True:
            try:
                kind, payload = self._spawn_queue.get_nowait()
            except queue.Empty:
                break
            except Exception:
                break
            if kind == 'rows':
                self._render_armory(payload)
            elif kind == 'status':
                self.lab_spawn_status.configure(text=payload)
            elif kind == 'done':
                self._spawn_done(payload)
            elif kind == 'error':
                self._spawn_failed(payload)
            elif kind == 'btn':
                self.btn_spawn.configure(state=payload)
            elif kind == 'pages':
                self._render_pages(payload)
            elif kind == 'synth':
                self._synth_done(payload)
        st = self.poller.get()
        if st.get('ok'):
            pid = st.get('pid', 0)
            if pid and pid != self._applied_pid:
                self._applied_pid = pid
                self.after(400, self._apply_all_saved)
            aim = st.get('aim') or {}
            vac = st.get('vac')
            team = st.get('team')
            self.var_status.set(
                f"已连接  pid={st.get('pid')}   "
                f"自瞄={'开' if aim.get('on') else '关'}  "
                f"吸敌={'开' if (vac and vac[0]) else '关'}  "
                + (f"友军=T{team[2]}" if team and team[2] >= 0 else
                   ('阵营=自动识别中' if team else '')))
            if aim:
                tgt = f"槽{aim['slot']} hp={aim['hp']}" if aim.get('has_tgt') else '无目标'
                self.lab_aim.configure(
                    text=f"自瞄状态：{'已标定' if aim.get('calib') else '未标定'}  {tgt}  "
                         f"误差=({aim['err_yaw']:+.2f},{aim['err_pitch']:+.2f})°  "
                         f"增益=({aim['gain_x']:+.1f},{aim['gain_y']:+.1f})  tick={aim['ticks']}")
            if vac:
                self.lab_vac.configure(
                    text=f"吸敌状态：目标={vac[2]} 写入={vac[3]}  "
                         f"漂移={vac[4] * 2.54:.1f}cm  头点差={vac[5] * 2.54:.1f}cm  "
                         f"距离={vac[6] / 100:.2f}m")
            if team:
                stt = {0: '空闲', 1: '采样中', 2: '已锁定', 3: '失败'}.get(team[1], str(team[1]))
                self.lab_team.configure(
                    text=f"阵营识别：{stt}  友军={('T' + str(team[2])) if team[2] >= 0 else '?'}  "
                         f"丢弃掩码={team[3]:#x}  样本={team[4]}")
                det = team[2]
                if det >= 0 and self.var_team_auto.get():
                    if str(det) != self.var_team_manual.get():
                        self.var_team_manual.set(str(det))
                        self.cmb_team.configure(state='disabled')
                    if self.esp.running() and self._esp_team != det:
                        self._esp_team = det
                        self._write_esp_config()
                        self.esp.stop()
                        self.esp.start()
            elif st.get('team_ok') is False:
                self.lab_team.configure(text='阵营识别：旧 DLL 不支持（重启游戏加载新 DLL）')
            fly = st.get('fly')
            if fly:
                self.lab_fly.configure(
                    text=f"飞行：{'开' if fly.get('on') else '关'}  "
                         f"z={fly.get('z', 0):.1f} 目标={fly.get('tz', 0):.1f}")
        else:
            self.var_status.set(f"未连接  {st.get('err', '')}")
            self.lab_esp.configure(
                text=f"覆盖层：{'运行中' if self.esp.running() else '已停止'}",
                foreground='#080' if self.esp.running() else '#a00')
        if self._esp_desired:
            if self.esp.running():
                self._esp_tries = 0
                self.lab_esp.configure(text='覆盖层：运行中', foreground='#080')
            else:
                now = time.time()
                if st.get('ok') and now >= self._esp_next_try:
                    self._esp_next_try = now + 2.0
                    if self._esp_tries >= 30:
                        self._esp_desired = False
                        self.var_esp_on.set(False)
                        self._flash('ESP 多次启动失败，已自动关闭；请查看 panel_esp.log')
                    else:
                        self._esp_tries += 1
                        log(f'启动 ESP 覆盖层（第 {self._esp_tries} 次）cmd={esp_cmd()}')
                        self._write_esp_config()
                        self.esp.start()
                self.lab_esp.configure(
                    text='覆盖层：等待游戏连接' if not self.esp.running() else '覆盖层：运行中',
                    foreground='#080' if self.esp.running() else '#a80')
        else:
            self.var_esp_on.set(False)
            self.lab_esp.configure(text='覆盖层：运行中' if self.esp.running() else '已停止',
                                   foreground='#080' if self.esp.running() else '#a00')
        self.after(500, self._tick)

    def _on_close(self):
        try:
            self.esp.stop()
        except Exception:
            pass
        try:
            self.poller.stop_flag.set()
        except Exception:
            pass
        self.destroy()

    # ---------------- settings ----------------
    def _load_settings(self):
        s = self.settings
        try:
            self.var_labels.set(bool(s.get('labels', True)))
            self.var_corpse.set(bool(s.get('corpse_filter', True)))
            self.var_livefov.set(bool(s.get('live_fov', False)))
            self.var_draw_friend.set(bool(s.get('draw_friendly', True)))
            self.var_draw_enemy.set(bool(s.get('draw_enemy', True)))
            self.var_hud.set(bool(s.get('hud', True)))
            self.var_fov.set(str(s.get('vfov', 59)))
            self.var_adszoom.set(str(s.get('ads_zoom', 1.955)))
            self.var_maxdist.set(str(s.get('max_dist', 2500)))
            self.var_team_auto.set(bool(s.get('team_auto', True)))
            self.var_team_manual.set(str(s.get('team_manual', 7)))
            self.cmb_team.configure(state='disabled' if self.var_team_auto.get() else 'readonly')
            known = {int(x) for x in s.get('known_teams', []) if str(x).lstrip('-').isdigit()}
            self._known_teams = set(DEFAULT_KNOWN_TEAMS) | known
            self._known_teams |= {int(k) for k in self.colors.get('team_colors', {})
                                  if str(k).isdigit()}
            self._drop_selected = {int(x) for x in s.get('drop', [2])
                                   if str(x).lstrip('-').isdigit()}
            self.drop_vars = {}
            self._rebuild_drop_teams()
            self._rebuild_color_btns()
            self._refresh_color_btns()
            av = s.get('aim', {})
            self.var_aim_on.set(bool(av.get('on', False)))
            self.var_aim_hold.set(bool(av.get('hold', True)))
            self.var_cone.set(str(av.get('cone', 8)))
            self.var_aim_max.set(str(av.get('max_dist', 3000)))
            self.var_aim_team.set(str(av.get('team', av.get('excl', 7))))
            self._render_team_radios({int(self.var_aim_team.get() or 7): 0})
            self.var_chain.set(bool(av.get('chain', True)))
            self.var_chain_r.set(str(av.get('chain_radius', 600)))
            for k, dflt in (('speed', 12), ('strength', 60), ('smooth', 0), ('lead', 40)):
                self.aim_vars[k].set(int(av.get(k, dflt)))
            vv = s.get('vac', {})
            self.var_vac_on.set(bool(vv.get('on', False)))
            self.var_vac_head.set(bool(vv.get('head', True)))
            for k, dflt in (('dist', '4.0'), ('up', '0.0'), ('ring', '0.6'),
                            ('excl', '7'), ('only', '0')):
                self.vac_vars[k].set(str(vv.get(k, dflt)))
            fl = s.get('fly', {})
            self.var_fly.set(bool(fl.get('on', False)))
            self.var_fly_spd.set(str(fl.get('speed', 4.0)))
            self.var_esp_on.set(bool(s.get('esp_on', False)))
        except Exception as e:
            import traceback
            traceback.print_exc()

    def _save_settings(self):
        self.settings = {
            'labels': bool(self.var_labels.get()),
            'corpse_filter': bool(self.var_corpse.get()),
            'live_fov': bool(self.var_livefov.get()),
            'draw_friendly': bool(self.var_draw_friend.get()),
            'draw_enemy': bool(self.var_draw_enemy.get()),
            'hud': bool(self.var_hud.get()),
            'vfov': self.var_fov.get(),
            'ads_zoom': self.var_adszoom.get(),
            'max_dist': self.var_maxdist.get(),
            'team_auto': bool(self.var_team_auto.get()),
            'team_manual': self.var_team_manual.get(),
            'known_teams': sorted(self._known_teams),
            'drop': [t for t, v in self.drop_vars.items() if v.get()],
            'colors': self.colors,
            'aim': {
                'on': bool(self.var_aim_on.get()),
                'hold': bool(self.var_aim_hold.get()),
                'cone': self.var_cone.get(),
                'max_dist': self.var_aim_max.get(),
                'team': self.var_aim_team.get(),
                'chain': bool(self.var_chain.get()),
                'chain_radius': self.var_chain_r.get(),
                **{k: int(v.get()) for k, v in self.aim_vars.items()},
            },
            'vac': {
                'on': bool(self.var_vac_on.get()),
                'head': bool(self.var_vac_head.get()),
                **{k: v.get() for k, v in self.vac_vars.items()},
            },
            'fly': {'on': bool(self.var_fly.get()), 'speed': self.var_fly_spd.get()},
            'esp_on': bool(self.var_esp_on.get()),
        }
        save_json(CONFIG_PANEL, self.settings)


_NOT_CHILD = object()


def _child_main(argv):
    try:
        if '--esp' in argv:
            log('子进程模式：ESP 覆盖层')
            import sp26_esp
            sys.argv = ['sp26_esp.py'] + [a for a in argv[1:] if a != '--esp']
            rc = sp26_esp.main()
            log(f'ESP 子进程退出 rc={rc}')
            return rc
        if '--god6' in argv:
            import sp26_god6 as G
            i = argv.index('--god6')
            rest = argv[i + 1:]
            cmd = rest[0] if rest else 'status'
            log(f'子进程模式：无敌 {cmd}')
            if cmd == 'on':
                return G.cmd_on()
            if cmd == 'off':
                return G.cmd_off()
            return G.cmd_status()
        if '--patch-ammo' in argv:
            log(f'子进程模式：弹药补丁 {argv[argv.index("--patch-ammo") + 1:]}')
            import sp26_patch as P
            i = argv.index('--patch-ammo')
            rest = argv[i + 1:]
            cmd = rest[0] if rest else 'check'
            if cmd == 'check':
                return P.cmd_check()
            if cmd == 'status':
                return P.cmd_status()
            if cmd == 'on' and len(rest) > 1:
                return P.cmd_on(rest[1])
            if cmd == 'off':
                return P.cmd_off(rest[1] if len(rest) > 1 else 'all')
            return 2
    except BaseException:
        log('子进程异常:\n' + traceback.format_exc())
        return 2
    return _NOT_CHILD


if __name__ == '__main__':
    _rc = _child_main(sys.argv)
    if _rc is not _NOT_CHILD:
        sys.exit(_rc if isinstance(_rc, int) else 0)
    try:
        import sp26_startup
        if not sp26_startup.run_startup_gate():
            sys.exit(0)
    except SystemExit:
        raise
    except BaseException:
        log('启动门异常（已中止，避免跳过声明与 DLL 检查）:\n' + traceback.format_exc())
        sys.exit(1)
    app = App()
    try:
        app.mainloop()
    finally:
        try:
            app._save_settings()
        except Exception:
            pass
