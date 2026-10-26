"""ESP 覆盖层 v4：原生分层窗口（GDI 绘制），不抢焦点、点击穿透。

- 后台线程读内存（姿态/玩家/实体），主循环 30Hz 用 GDI 画到分层窗口
- 窗口创建即带 WS_EX_NOACTIVATE|TOPMOST|TRANSPARENT|LAYERED，透明色 RGB(1,2,3)
- 只按游戏客户区投影；[ / ] 调垂直 FOV（游戏档案 Fov=90 即垂直），L 开关文本，F9 退出
- 游戏非前台时自动隐藏；队友(f24=7) 蓝色，敌军红色

用法：python sp26_esp.py [--fov 90] [--max-dist 2500] [--team 7]
      python sp26_esp.py --dump
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import math
import os
import struct
import subprocess
import sys
import threading
import time
import traceback
import unicodedata

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

import ammo_probe
import sp26_ent as E
import sp26_team_palette as TP

if getattr(sys, 'frozen', False):
    HERE = os.path.dirname(os.path.abspath(sys.executable))
else:
    HERE = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, HERE)
LABELS = os.path.join(HERE, 'esp_labels.json')
CONFIG = os.path.join(HERE, 'esp_config.json')
POS_RVA = 0xF224F5C
FOV_RVA = 0xF225000          # 世界相机结构：+0 为垂直半 FOV（弧度），开镜时变化
KEYREF = 0x00030201          # RGB(1,2,3) COLORREF
WS_EX_TOPMOST = 0x8
WS_EX_TRANSPARENT = 0x20
WS_EX_TOOLWINDOW = 0x80
WS_EX_LAYERED = 0x80000
WS_EX_NOACTIVATE = 0x08000000
LWA_COLORKEY = 1
SW_SHOWNOACTIVATE = 4
SW_HIDE = 0
SRCCOPY = 0x00CC0020
NULL_BRUSH = 5
NULL_PEN = 8
TRANSPARENT = 1

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32
kernel32 = ctypes.windll.kernel32
LONG_PTR = ctypes.c_ssize_t


class RECT(ctypes.Structure):
    _fields_ = [('left', ctypes.c_long), ('top', ctypes.c_long),
                ('right', ctypes.c_long), ('bottom', ctypes.c_long)]


class WNDCLASSW(ctypes.Structure):
    _fields_ = [('style', ctypes.c_uint), ('lpfnWndProc', ctypes.c_void_p),
                ('cbClsExtra', ctypes.c_int), ('cbWndExtra', ctypes.c_int),
                ('hInstance', ctypes.c_void_p), ('hIcon', ctypes.c_void_p),
                ('hCursor', ctypes.c_void_p), ('hbrBackground', ctypes.c_void_p),
                ('lpszMenuName', ctypes.c_wchar_p), ('lpszClassName', ctypes.c_wchar_p)]


user32.DefWindowProcW.restype = LONG_PTR
user32.CreateWindowExW.argtypes = [ctypes.c_uint, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                   ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_void_p]
user32.CreateWindowExW.restype = ctypes.c_void_p
user32.SetLayeredWindowAttributes.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                              ctypes.c_ubyte, ctypes.c_uint]
user32.GetDC.argtypes = [ctypes.c_void_p]
user32.GetDC.restype = ctypes.c_void_p
user32.ReleaseDC.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
user32.ShowWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
user32.SetWindowPos.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                                ctypes.c_int, ctypes.c_int, ctypes.c_uint]
user32.FillRect.argtypes = [ctypes.c_void_p, ctypes.POINTER(RECT), ctypes.c_void_p]
user32.GetForegroundWindow.restype = ctypes.c_void_p
user32.IsIconic.argtypes = [ctypes.c_void_p]
user32.GetAsyncKeyState.argtypes = [ctypes.c_int]
user32.GetAsyncKeyState.restype = ctypes.c_short

gdi32.CreateCompatibleDC.argtypes = [ctypes.c_void_p]
gdi32.CreateCompatibleDC.restype = ctypes.c_void_p
gdi32.CreateCompatibleBitmap.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
gdi32.CreateCompatibleBitmap.restype = ctypes.c_void_p
gdi32.SelectObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
gdi32.SelectObject.restype = ctypes.c_void_p
gdi32.CreateSolidBrush.argtypes = [ctypes.c_uint]
gdi32.CreateSolidBrush.restype = ctypes.c_void_p
gdi32.CreatePen.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint]
gdi32.CreatePen.restype = ctypes.c_void_p
gdi32.GetStockObject.argtypes = [ctypes.c_int]
gdi32.GetStockObject.restype = ctypes.c_void_p
gdi32.SetTextColor.argtypes = [ctypes.c_void_p, ctypes.c_uint]
gdi32.SetBkMode.argtypes = [ctypes.c_void_p, ctypes.c_int]
gdi32.TextOutW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                           ctypes.c_wchar_p, ctypes.c_int]
gdi32.Rectangle.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int]
gdi32.MoveToEx.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
gdi32.LineTo.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
gdi32.BitBlt.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                         ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
gdi32.CreateFontW.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                              ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint,
                              ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint,
                              ctypes.c_uint, ctypes.c_wchar_p]
gdi32.CreateFontW.restype = ctypes.c_void_p
gdi32.DeleteObject.argtypes = [ctypes.c_void_p]


def rgb(r, g, b):
    return r | (g << 8) | (b << 16)


class GdiOverlay:
    def __init__(self, x, y, w, h):
        hinst = kernel32.GetModuleHandleW(None)
        cls = 'SP26ESP_OVL'
        wc = WNDCLASSW()
        wc.style = 0
        wc.lpfnWndProc = ctypes.cast(user32.DefWindowProcW, ctypes.c_void_p)
        wc.hInstance = hinst
        wc.hCursor = None
        wc.hbrBackground = None
        wc.lpszClassName = cls
        user32.RegisterClassW(ctypes.byref(wc))
        self.w, self.h = w, h
        self.hwnd = user32.CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
            cls, 'SP26ESP', 0x80000000, x, y, w, h, None, None, hinst, None)
        user32.SetLayeredWindowAttributes(self.hwnd, KEYREF, 0, LWA_COLORKEY)
        user32.ShowWindow(self.hwnd, SW_SHOWNOACTIVATE)
        user32.SetWindowPos(self.hwnd, ctypes.c_void_p(-1), 0, 0, 0, 0,
                            0x0001 | 0x0002 | 0x0010)
        self.hdc = user32.GetDC(self.hwnd)
        self.mem = gdi32.CreateCompatibleDC(self.hdc)
        self.bmp = gdi32.CreateCompatibleBitmap(self.hdc, w, h)
        gdi32.SelectObject(self.mem, self.bmp)
        self.font = gdi32.CreateFontW(-15, 0, 0, 0, 700, 0, 0, 0, 0x86, 0, 0, 0, 0, 'Microsoft YaHei')
        gdi32.SelectObject(self.mem, self.font)
        gdi32.SetBkMode(self.mem, TRANSPARENT)
        self.keybrush = gdi32.CreateSolidBrush(KEYREF)
        self.pens = {}
        self.hollow = gdi32.GetStockObject(NULL_BRUSH)

    def visible(self, v):
        user32.ShowWindow(self.hwnd, SW_SHOWNOACTIVATE if v else SW_HIDE)

    def begin(self):
        r = RECT(0, 0, self.w, self.h)
        user32.FillRect(self.mem, ctypes.byref(r), self.keybrush)

    def pen(self, color, width=2):
        key = (color, width)
        p = self.pens.get(key)
        if p is None:
            p = gdi32.CreatePen(0, width, color)
            self.pens[key] = p
        gdi32.SelectObject(self.mem, p)
        return p

    def box(self, x0, y0, x1, y1, color, width=2):
        self.pen(color, width)
        gdi32.SelectObject(self.mem, self.hollow)
        gdi32.Rectangle(self.mem, int(x0), int(y0), int(x1), int(y1))

    def line(self, x0, y0, x1, y1, color, width=2):
        self.pen(color, width)
        gdi32.MoveToEx(self.mem, int(x0), int(y0), None)
        gdi32.LineTo(self.mem, int(x1), int(y1))

    def text(self, x, y, s, color):
        gdi32.SetTextColor(self.mem, color)
        gdi32.TextOutW(self.mem, int(x), int(y), s, len(s))

    def end(self):
        gdi32.BitBlt(self.hdc, 0, 0, self.w, self.h, self.mem, 0, 0, SRCCOPY)

    def close(self):
        for p in self.pens.values():
            gdi32.DeleteObject(p)
        gdi32.DeleteObject(self.bmp)
        gdi32.DeleteObject(self.mem)
        user32.ReleaseDC(self.hwnd, self.hdc)
        user32.DestroyWindow(self.hwnd)


def find_hwnd():
    u = user32
    best, best_area = 0, 0

    @ctypes.WINFUNCTYPE(ctypes.c_bool, wt.HWND, wt.LPARAM)
    def cb(h, l):
        nonlocal best, best_area
        if not u.IsWindowVisible(h):
            return True
        n = u.GetWindowTextLengthW(h)
        if not n:
            return True
        buf = ctypes.create_unicode_buffer(n + 1)
        u.GetWindowTextW(h, buf, n + 1)
        t = ''.join(c for c in buf.value if unicodedata.category(c) != 'Cf')
        if 'Call of Duty' not in t and 'Modern Warfare' not in t:
            return True
        r = RECT()
        u.GetClientRect(h, ctypes.byref(r))
        area = (r.right - r.left) * (r.bottom - r.top)
        if area > best_area:
            best, best_area = h, area
        return True
    u.EnumWindows(cb, 0)
    return best


def client_rect(hwnd):
    r = RECT()
    user32.GetClientRect(hwnd, ctypes.byref(r))
    p = wt.POINT(0, 0)
    user32.ClientToScreen(hwnd, ctypes.byref(p))
    return p.x, p.y, r.right - r.left, r.bottom - r.top


def norm(v):
    n = math.sqrt(sum(c * c for c in v)) or 1.0
    return (v[0] / n, v[1] / n, v[2] / n)


def cross(a, b):
    return (a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0])


def dot(a, b):
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]


def load_json(path, default):
    if os.path.isfile(path):
        try:
            with open(path, encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return default


def save_config(updates):
    c = load_json(CONFIG, {})
    c.update(updates)
    try:
        with open(CONFIG, 'w', encoding='utf-8') as f:
            json.dump(c, f, ensure_ascii=False)
    except Exception:
        pass


class Reader(threading.Thread):
    def __init__(self, agent, base, team_id, max_dist):
        super().__init__(daemon=True)
        self.a = agent
        self.b = base
        self.team = team_id
        self.max_dist = max_dist
        self.labels = load_json(LABELS, {})
        self.lock = threading.Lock()
        self.snap = {'eye': (0, 0, 0), 'f': (1, 0, 0), 'r': (0, 1, 0), 'u': (0, 0, 1),
                     'half_v': 0.0, 'ads': 0.0, 'origin': (0, 0, 0), 'ents': [], 't': 0.0}
        self.stop_flag = threading.Event()
        self.g = self.c = 0
        self.meta = {}
        self.slots = set()
        self.errors = 0
        self.hist = []
        self.lead = 0.0
        self.pose_src = 'input'

    def resolve(self):
        gd = self.a.read(self.b + E.ENT_ARRAY_RVA, 8)
        if not gd:
            return False
        g = struct.unpack('<Q', gd)[0]
        if not g:
            return False
        cd = self.a.read(g + E.O_PTR178, 8)
        if not cd:
            return False
        c = struct.unpack('<Q', cd)[0]
        if not c:
            return False
        self.g, self.c = g, c
        return True

    def read_pose(self):
        d = self.a.read(self.b + POS_RVA, 24)
        if not d or len(d) != 24:
            return None
        eye = struct.unpack_from('<3f', d, 0)
        if self.pose_src == 'input' and self.c:
            cv = self.a.read(self.c + 0x430, 20)
            if not cv or len(cv) < 20:
                return None
            _, pitch, yaw, _, _ = struct.unpack('<5f', cv)
            # 连射后坐力只出现在渲染相机里：输入角 + 超出呼吸幅度的偏移
            look = struct.unpack_from('<3f', d, 12)
            fx, fy, fz = look[0] - eye[0], look[1] - eye[1], look[2] - eye[2]
            fn = math.sqrt(fx * fx + fy * fy + fz * fz) or 1.0
            pc_yaw = math.degrees(math.atan2(fy, fx))
            pc_pitch = math.degrees(math.asin(max(-1.0, min(1.0, -fz / fn))))
            dpy = (pc_yaw - yaw + 540.0) % 360.0 - 180.0
            dpp = pc_pitch - pitch
            if dpp > 0.8:
                pitch += dpp - 0.8
            elif dpp < -0.8:
                pitch += dpp + 0.8
            if dpy > 0.8:
                yaw += dpy - 0.8
            elif dpy < -0.8:
                yaw += dpy + 0.8
        else:
            look = struct.unpack_from('<3f', d, 12)
            fx, fy, fz = look[0] - eye[0], look[1] - eye[1], look[2] - eye[2]
            n = math.sqrt(fx * fx + fy * fy + fz * fz) or 1.0
            yaw = math.degrees(math.atan2(fy, fx))
            pitch = math.degrees(math.asin(max(-1.0, min(1.0, -fz / n))))
        now = time.perf_counter()
        self.hist.append((now, yaw, pitch))
        if len(self.hist) > 8:
            self.hist.pop(0)
        if self.lead > 0 and len(self.hist) >= 3:
            t0 = self.hist[0][0]
            ts = [h[0] - t0 for h in self.hist]
            ys = [h[1] for h in self.hist]
            ys = [y - 360.0 * round((y - ys[0]) / 360.0) for y in ys]
            ps = [h[2] for h in self.hist]
            k = len(ts)
            mt = sum(ts) / k
            my = sum(ys) / k
            mp = sum(ps) / k
            den = sum((t - mt) ** 2 for t in ts) or 1e-9
            vy = sum((ts[i] - mt) * (ys[i] - my) for i in range(k)) / den
            vp = sum((ts[i] - mt) * (ps[i] - mp) for i in range(k)) / den
            vy = max(-720.0, min(720.0, vy))
            vp = max(-720.0, min(720.0, vp))
            yaw += vy * self.lead
            pitch += vp * self.lead
        cp = math.cos(math.radians(pitch))
        f = (math.cos(math.radians(yaw)) * cp, math.sin(math.radians(yaw)) * cp,
             -math.sin(math.radians(pitch)))
        r = norm(cross(f, (0.0, 0.0, 1.0)))
        fd = self.a.read(self.b + FOV_RVA, 4)
        half_v = struct.unpack('<f', fd)[0] if fd and len(fd) == 4 else 0.0
        ad = self.a.read(self.c + 0x5B0, 4) if self.c else None
        ads = 1.0 if ad and len(ad) == 4 and abs(struct.unpack('<f', ad)[0] - 1.0) < 0.01 else 0.0
        return eye, f, r, cross(r, f), half_v, ads

    def full_scan(self):
        blob = self.a.read(self.g, 2000 * E.STRIDE)
        if not blob:
            return
        ox, oy, oz = self.snap['origin']
        live = set()
        n = min(2000, len(blob) // E.STRIDE)
        for i in range(1, n):
            off = i * E.STRIDE
            hp = struct.unpack_from('<i', blob, off + E.O_HEALTH)[0]
            if hp <= 0:
                continue
            cls = struct.unpack_from('<Q', blob, off + E.O_PTR180)[0]
            if not cls or not (self.b + 0x1000 <= cls < self.b + 0x20000000):
                continue
            x, y, z = struct.unpack_from('<3f', blob, off + E.O_ORIG_A)
            dx, dy, dz = x - ox, y - oy, z - oz
            if dx * dx + dy * dy + dz * dz > self.max_dist * self.max_dist:
                continue
            live.add(i)
            if i not in self.meta or self.meta[i][0] != cls:
                cd = self.a.read(cls, 0x60)
                if cd and len(cd) >= 0x60:
                    f24 = struct.unpack_from('<I', cd, 0x24)[0]
                    sig = '-'.join(f'{struct.unpack_from("<I", cd, o)[0]:X}'
                                   for o in (0x24, 0x54, 0x58, 0x5C))
                    self.meta[i] = (cls, f24, sig)
        for i in list(self.meta):
            if i not in live:
                del self.meta[i]
        self.slots = live

    def read_active(self):
        ox, oy, oz = self.snap['origin']
        out = []
        for i in sorted(self.slots):
            meta = self.meta.get(i)
            if not meta:
                continue
            d = self.a.read(self.g + i * E.STRIDE, 0x1E8)
            if not d or len(d) < 0x1E8:
                continue
            hp = struct.unpack_from('<i', d, E.O_HEALTH)[0]
            if hp <= 0:
                continue
            cls = struct.unpack_from('<Q', d, E.O_PTR180)[0]
            if cls != meta[0]:
                continue
            f10 = struct.unpack_from('<I', d, E.O_F10)[0]
            x, y, z = struct.unpack_from('<3f', d, E.O_ORIG_A)
            dx, dy, dz = x - ox, y - oy, z - oz
            dist = math.sqrt(dx * dx + dy * dy + dz * dz)
            if dist < 2.0 or dist > self.max_dist:
                continue
            head = None
            actor = struct.unpack_from('<Q', d, 0x198)[0]
            if actor:
                hb = self.a.read(actor + 0x19C, 12)
                if hb and len(hb) == 12:
                    hx, hy, hz = struct.unpack('<3f', hb)
                    if (abs(hx - x) < 100 and abs(hy - y) < 100 and
                            -20 < hz - z < 130):
                        head = (hx, hy, hz)
            unknown = hp > 10000
            if unknown and not head:
                continue
            out.append({'slot': i, 'hp': hp if not unknown else -1, 'unknown': unknown,
                        'pos': (x, y, z), 'dist': dist,
                        'team': meta[1], 'sig': meta[2], 'f10': f10, 'head': head})
        out.sort(key=lambda e: e['dist'])
        return out

    def run(self):
        t_pose = t_origin = t_full = t_ent = 0.0
        while not self.stop_flag.is_set():
            try:
                now = time.time()
                if not self.g or not self.c:
                    if not self.resolve():
                        time.sleep(0.5)
                        continue
                if now - t_pose > 0.008:
                    t_pose = now
                    pose = self.read_pose()
                    if pose:
                        with self.lock:
                            self.snap['eye'], self.snap['f'], self.snap['r'], self.snap['u'] = pose[:4]
                            self.snap['half_v'] = pose[4]
                            self.snap['ads'] = pose[5]
                if now - t_origin > 0.1:
                    t_origin = now
                    od = self.a.read(self.c + 0x58, 12)
                    if od and len(od) == 12:
                        with self.lock:
                            self.snap['origin'] = struct.unpack('<3f', od)
                if now - t_full > 1.5 and self.snap['origin'] != (0.0, 0.0, 0.0):
                    t_full = now
                    self.full_scan()
                if now - t_ent > 0.012:
                    t_ent = now
                    ents = self.read_active()
                    with self.lock:
                        self.snap['ents'] = ents
                        self.snap['t'] = now
            except Exception:
                self.errors += 1
                if self.errors < 4:
                    traceback.print_exc()
                self.g = self.c = 0
                time.sleep(0.5)
            time.sleep(0.002)

    def get(self):
        with self.lock:
            return dict(self.snap)


def project(p, eye, f, r, u, fpx, rs, W, H):
    d = (p[0] - eye[0], p[1] - eye[1], p[2] - eye[2])
    z = dot(f, d)
    if z < 1.0:
        return None
    return (W / 2 + rs * dot(r, d) / z * fpx, H / 2 - dot(u, d) / z * fpx, z)


def dump_mode(agent, base, team, max_dist):
    rd = Reader(agent, base, team, max_dist)
    for _ in range(50):
        if rd.resolve():
            break
        time.sleep(0.1)
    if not rd.g:
        print('无法解析玩家 client 块')
        return 2
    od = agent.read(rd.c + 0x58, 12)
    rd.snap['origin'] = struct.unpack('<3f', od) if od else (0, 0, 0)
    rd.snap['origin'] = (rd.snap['origin'][0], rd.snap['origin'][1], rd.snap['origin'][2])
    rd.full_scan()
    ents = rd.read_active()
    print(f'玩家 {tuple(round(v) for v in rd.snap["origin"])}  活体 {len(ents)}')
    groups = {}
    for e in ents:
        groups.setdefault((e['team'], e['sig']), []).append(e)
    print('team  sig                     数量  最近(米)  槽位')
    for (tm, sig), lst in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        print(f'  {tm:2d}  {sig:22s} {len(lst):4d}  {lst[0]["dist"] * 0.0254:7.1f}  '
              f'{[x["slot"] for x in lst[:8]]}')
    return 0


class Hotkeys:
    """游戏内热键：F4 无敌 / F5 弹药 / F6 飞行 / F7 方框 / F8 自瞄。

    只有游戏在前台时才响应；每次成功切换在左上角显示 1 秒文字。
    """
    VK = {'god': 0x73, 'ammo': 0x74, 'fly': 0x75, 'boxes': 0x76, 'aim': 0x77}
    LABEL = {'god': '无敌', 'ammo': '无限弹药', 'fly': '飞行', 'boxes': '方框', 'aim': '自瞄'}

    def __init__(self, agent, cfg):
        self.agent = agent
        self.cfg = cfg
        self.prev = {}
        self.busy = set()
        self.lock = threading.Lock()
        self.god_on = None
        self.ammo_on = None
        self.boxes_on = True
        self.toast = ''
        self.toast_until = 0.0
        threading.Thread(target=self._init_states, daemon=True).start()

    def say(self, text, sec=1.0):
        self.toast = text
        self.toast_until = time.time() + sec

    @staticmethod
    def _run(cmd, timeout=40):
        try:
            p = subprocess.run(cmd, cwd=HERE, capture_output=True, timeout=timeout,
                               creationflags=0x08000000,
                               env={**os.environ, 'PYTHONUNBUFFERED': '1'})
            out = (p.stdout or b'') + (p.stderr or b'')
            for enc in ('utf-8', 'gbk'):
                try:
                    return p.returncode, out.decode(enc)
                except Exception:
                    continue
            return p.returncode, out.decode('utf-8', 'replace')
        except Exception as e:
            return -1, str(e)

    @staticmethod
    def _cmd(kind, mode):
        if getattr(sys, 'frozen', False):
            if kind == 'god':
                return [sys.executable, '--god6', mode]
            return [sys.executable, '--patch-ammo', mode, 'ammo']
        if kind == 'god':
            return [sys.executable, '-u', os.path.join(HERE, 'sp26_god6.py'), mode]
        return [sys.executable, '-u', os.path.join(HERE, 'sp26_patch.py'), mode, 'ammo']

    def _init_states(self):
        code, out = self._run(self._cmd('god', 'status'))
        if code == 0:
            self.god_on = '已生效' in out
        code, out = self._run(self._cmd('ammo', 'status'))
        if code == 0:
            line = next((l for l in out.splitlines() if l.startswith('ammo')), '')
            self.ammo_on = '已生效' in line

    def _tool_toggle(self, kind):
        with self.lock:
            if kind in self.busy:
                return
            state = self.god_on if kind == 'god' else self.ammo_on
            if state is None:
                self.say(f'{self.LABEL[kind]}：状态未知', 1.0)
                return
            on = not state
            self.busy.add(kind)
        self.say(f'{self.LABEL[kind]}：{"开启中…" if on else "关闭中…"}', 0.8)

        def work():
            code, out = self._run(self._cmd(kind, 'on' if on else 'off'))
            with self.lock:
                self.busy.discard(kind)
                if code == 0:
                    if kind == 'god':
                        self.god_on = on
                    else:
                        self.ammo_on = on
                    self.say(f'{self.LABEL[kind]}：{"开" if on else "关"}', 1.0)
                else:
                    tail = out.strip().splitlines()[-1] if out.strip() else ''
                    print(f'热键 {kind} 失败 code={code}: {tail}')
                    self.say(f'{self.LABEL[kind]}切换失败', 1.0)
        threading.Thread(target=work, daemon=True).start()

    def _fly(self):
        try:
            fs = self.agent.fly_get()
            on = not fs.get('on')
            spd = int(round(float(self.cfg.get('fly_speed', 4.0) or 4.0) * 10))
            ok = self.agent.fly_set(on, 0, spd, 0x20, 0x43, 0, 0)
            self.say(f'飞行：{"开" if on else "关"}' if ok else '飞行切换失败')
        except Exception:
            self.say('飞行切换失败')

    def _aim(self):
        try:
            a = self.agent.aim_get()
            on = not a.get('on')
            ac = self.cfg.get('aim') or {}
            ok = self.agent.aim_set(
                on, hold=bool(ac.get('hold', True)), vk=0x02,
                cone10=int(float(ac.get('cone', 8)) * 10),
                max_dist=int(ac.get('max_dist', 3000)),
                team=int(ac.get('team', 7)), head_dz=62.0)
            if ok and on:
                self.agent.aim_cfg(int(ac.get('speed', 12)), int(ac.get('strength', 60)),
                                   int(ac.get('smooth', 0)), int(ac.get('lead', 40)))
                self.agent.aim_chain(bool(ac.get('chain', True)),
                                     int(ac.get('chain_radius', 600)))
            self.say(f'自瞄：{"开" if on else "关"}' if ok else '自瞄切换失败')
        except Exception:
            self.say('自瞄切换失败')

    def _boxes(self):
        self.boxes_on = not self.boxes_on
        self.say('方框：' + ('开' if self.boxes_on else '关'))

    def poll(self):
        for name, vk in self.VK.items():
            down = bool(user32.GetAsyncKeyState(vk) & 0x8000)
            if down and not self.prev.get(name, False):
                if name in ('god', 'ammo'):
                    self._tool_toggle(name)
                elif name == 'fly':
                    self._fly()
                elif name == 'aim':
                    self._aim()
                else:
                    self._boxes()
            self.prev[name] = down


def draw_mode(agent, base, team, max_dist, vfov0, drop=()):
    hwnd = find_hwnd()
    if not hwnd:
        print('未找到游戏窗口')
        return 2
    cfg = load_json(CONFIG, {})
    team = int(cfg.get('team', team))
    max_dist = float(cfg.get('max_dist', max_dist))
    dcfg = cfg.get('drop')
    if isinstance(dcfg, list):
        drop = {int(x) for x in dcfg}
    draw_friend = bool(cfg.get('draw_friendly', True))
    draw_enemy = bool(cfg.get('draw_enemy', True))
    draw_log = bool(cfg.get('hud', True))
    x0, y0, W, H = client_rect(hwnd)
    print(f'游戏窗口 0x{hwnd:X} 客户区 {W}x{H} @ ({x0},{y0})')
    rd = Reader(agent, base, team, max_dist)
    rd.start()
    for _ in range(100):
        if rd.g:
            break
        time.sleep(0.05)
    if not rd.g:
        print('无法解析玩家 client 块')
        return 2

    vf = float(cfg.get('vfov', vfov0))
    fpx = float(cfg.get('f_px') or ((H / 2) / math.tan(math.radians(vf) / 2)))
    # 标定模型 u = k*f*tan(α-yaw)；k=-1 恰好对应 right=cross(forward,up) 且取正号。
    st = {'vfov': vf, 'fpx': fpx, 'rs': 1 if int(cfg.get('right_sign', -1)) < 0 else -1,
          'rs_raw': int(cfg.get('right_sign', -1)),
          'half_v': 0.0, 'live_fov': bool(cfg.get('live_fov', False)),
          'lead': float(cfg.get('pose_lead', 0.02)),
          'ads_zoom': float(cfg.get('ads_zoom', 1.0)), 'ads_on': 0.0,
          't_key': 0.0, 'labels': bool(cfg.get('labels', True)),
          'corpse_filter': bool(cfg.get('corpse_filter', True)),
          'aim': None, 't_aim': 0.0, 'aim_last': '',
          'fps': 0.0, 'frames': 0, 't_stat': time.time(), 'vis': None}
    rd.lead = st['lead']
    rd.pose_src = str(cfg.get('pose_src', 'input'))

    ov = GdiOverlay(x0, y0, W, H)
    hk = Hotkeys(agent, cfg)
    print(f'覆盖层 hwnd=0x{ov.hwnd:X} 已显示；F9 退出')

    colcfg = cfg.get('colors', {}) or {}

    def c3(key, dflt):
        v = colcfg.get(key, dflt)
        try:
            return rgb(int(v[0]), int(v[1]), int(v[2]))
        except Exception:
            return rgb(*dflt)

    COL_TEAM = c3('friendly', [79, 195, 255])
    COL_TEAM_TXT = c3('friendly_txt', [168, 230, 255])
    COL_HUD = c3('hud', [0, 255, 144])
    COL_UNKNOWN = c3('unknown', [200, 200, 200])
    TEAM_COLORS = {}
    for t in range(32):
        base, txt = TP.team_rgb(t)
        TEAM_COLORS[t] = (rgb(*base), rgb(*txt))
    tccfg = colcfg.get('team_colors', {}) or cfg.get('team_colors', {}) or {}
    for k, v in tccfg.items():
        if not str(k).isdigit():
            continue
        if isinstance(v, list) and len(v) == 2:
            try:
                TEAM_COLORS[int(k)] = (rgb(int(v[0][0]), int(v[0][1]), int(v[0][2])),
                                       rgb(int(v[1][0]), int(v[1][1]), int(v[1][2])))
            except Exception:
                pass
    COL_ENEMY = c3('enemy', [255, 64, 64])
    COL_ENEMY_TXT = c3('enemy_txt', [255, 208, 64])
    legend_ids = {int(k) for k in tccfg if str(k).isdigit()}
    for t in (cfg.get('known_teams') or []):
        if str(t).isdigit():
            legend_ids.add(int(t))
    legend_ids |= {0, 1, 2, 3, 4, 5, 6}
    legend_ids = sorted(t for t in legend_ids if 0 <= t < 32)
    legend_txt = '队伍色 ' + ' '.join(f'T{t}' for t in legend_ids)

    try:
        while True:
            now = time.time()
            if user32.GetAsyncKeyState(0x78) & 0x8000:      # F9
                break
            if user32.GetAsyncKeyState(0x4C) & 0x8000 and now - st['t_key'] > 0.25:
                st['t_key'] = now
                st['labels'] = not st['labels']
            step = 0.0
            if user32.GetAsyncKeyState(0xDB) & 0x8000:
                step -= 0.5
            if user32.GetAsyncKeyState(0xDD) & 0x8000:
                step += 0.5
            lead_step = 0.0
            if user32.GetAsyncKeyState(0xBC) & 0x8000:      # ,
                lead_step -= 0.005
            if user32.GetAsyncKeyState(0xBE) & 0x8000:      # .
                lead_step += 0.005
            zoom_step = 0.0
            if user32.GetAsyncKeyState(0x39) & 0x8000:      # 9
                zoom_step -= 0.05
            if user32.GetAsyncKeyState(0x30) & 0x8000:      # 0
                zoom_step += 0.05
            if (step or lead_step or zoom_step) and now - st['t_key'] > 0.03:
                st['t_key'] = now
                if step:
                    st['vfov'] = round(max(40.0, min(110.0, st['vfov'] + step)), 1)
                    st['fpx'] = (H / 2) / math.tan(math.radians(st['vfov']) / 2)
                if lead_step:
                    st['lead'] = round(max(0.0, min(0.12, st['lead'] + lead_step)), 3)
                    rd.lead = st['lead']
                if zoom_step:
                    st['ads_zoom'] = round(max(1.0, min(6.0, st['ads_zoom'] + zoom_step)), 3)
                save_config({'vfov': st['vfov'], 'f_px': round(st['fpx'], 1),
                             'right_sign': st['rs_raw'], 'live_fov': st['live_fov'],
                             'pose_lead': st['lead'], 'pose_src': rd.pose_src,
                             'ads_zoom': st['ads_zoom']})

            vis = (user32.GetForegroundWindow() == hwnd and not user32.IsIconic(hwnd))
            if vis != st['vis']:
                st['vis'] = vis
                ov.visible(vis)
            if not vis:
                time.sleep(0.15)
                continue
            hk.poll()

            snap = rd.get()
            if now - st['t_aim'] > 0.2:
                st['t_aim'] = now
                try:
                    st['aim'] = rd.a.aim_get()
                except Exception:
                    st['aim'] = None
                a = st['aim']
                if a:
                    aline = (f"on={int(a['on'])} cal={int(a['calib'])} "
                             f"tgt={a['slot'] if a['has_tgt'] else '-'} hp={a['hp']} "
                             f"err=({a['err_yaw']:+.2f},{a['err_pitch']:+.2f}) "
                             f"gain=({a['gain_x']:+.1f},{a['gain_y']:+.1f}) "
                             f"tick={a['ticks']} ads={snap.get('ads', 0.0):.2f}")
                    if aline != st['aim_last']:
                        st['aim_last'] = aline
                        try:
                            with open(os.path.join(HERE, 'aim_hud.log'), 'a', encoding='utf-8') as f:
                                f.write(time.strftime('%H:%M:%S ') + aline + '\n')
                        except Exception:
                            pass
            eye, f, r, up = snap['eye'], snap['f'], snap['r'], snap['u']
            hv = snap.get('half_v', 0.0)
            ads = snap.get('ads', 0.0)
            if st['live_fov'] and 0.03 < hv < 1.3:
                st['half_v'] = hv
                base_f = (H / 2) / math.tan(hv)
            else:
                st['half_v'] = 0.0
                base_f = st['fpx']
            st['ads_on'] = ads
            st['fpx_use'] = base_f * (st['ads_zoom'] if ads else 1.0)
            ov.begin()
            for e in (snap['ents'] if hk.boxes_on else ()):
                if int(e['team']) in drop:
                    continue
                if e['team'] == team:
                    if not draw_friend:
                        continue
                elif not draw_enemy:
                    continue
                if (not e.get('unknown') and st['corpse_filter'] and
                        e['hp'] <= 1 and (e.get('f10', 0) & 0x01004000)):
                    continue
                x, y, z = e['pos']
                feet = project((x, y, z), eye, f, r, up, st['fpx_use'], st['rs'], W, H)
                hw = e.get('head') or (x, y, z + 70.0)
                head = project(hw, eye, f, r, up, st['fpx_use'], st['rs'], W, H)
                if not feet or not head:
                    continue
                sx, sy, _ = feet
                hx, hy, _ = head
                if not (-100 <= sx <= W + 100 and -100 <= sy <= H + 100):
                    continue
                hgt = max(abs(sy - hy), 10.0)
                wid = max(hgt * 0.42, 6.0)
                friendly = e['team'] == team
                if e.get('unknown'):
                    col, tc = COL_UNKNOWN, COL_UNKNOWN
                elif friendly:
                    col, tc = COL_TEAM, COL_TEAM_TXT
                else:
                    col, tc = TEAM_COLORS.get(int(e['team']), (COL_ENEMY, COL_ENEMY_TXT))
                ov.box(sx - wid / 2, hy, sx + wid / 2, sy, col, 2)
                ov.line(sx - 7, hy, sx + 7, hy, col, 2)
                if st['labels']:
                    if e.get('unknown'):
                        lab = '状态未知'
                    elif friendly:
                        lab = '队友'
                    else:
                        lab = rd.labels.get(str(e['team'])) or f"T{e['team']}"
                    hptxt = '?' if e.get('unknown') else str(e['hp'])
                    ov.text(sx - wid / 2, hy - 18, f"{lab} {hptxt} {e['dist'] * 0.0254:.0f}m", tc)
            st['frames'] += 1
            if now - st['t_stat'] > 0.5:
                st['fps'] = st['frames'] / (now - st['t_stat'])
                st['frames'] = 0
                st['t_stat'] = now
            hf = math.degrees(2 * math.atan((W / 2) / st['fpx_use']))
            fsrc = f"LIVE {math.degrees(2 * st['half_v']):.1f}deg" if st['half_v'] else 'CFG'
            adstxt = f"  ADS x{st['ads_zoom']:.2f}" if st['ads_on'] else ''
            if draw_log:
                ov.text(16, 14, f"ESP  VFOV={st['vfov']:.1f}  HFOV={hf:.1f}  f={st['fpx_use']:.0f} [{fsrc}]{adstxt}"
                                f"  实体={len(snap['ents'])}  FPS={st['fps']:.0f}  lead={st['lead'] * 1000:.0f}ms"
                                f"  {legend_txt}", COL_HUD)
                ov.text(16, 32, f"F4无敌 F5弹药 F6飞行 F7框 F8自瞄    "
                                f"[ ]FOV  , .预判  9 0倍率  L文本  J尸体过滤{'开' if st['corpse_filter'] else '关'}  F9退出",
                        COL_HUD)
                a = st.get('aim')
                if a:
                    ov.text(16, 50, f"AIM on={int(a['on'])} cal={int(a['calib'])} "
                                    f"tgt={a['slot'] if a['has_tgt'] else '-'} hp={a['hp']} "
                                    f"err=({a['err_yaw']:+.2f},{a['err_pitch']:+.2f}) "
                                    f"gain=({a['gain_x']:+.1f},{a['gain_y']:+.1f}) tick={a['ticks']}", COL_HUD)
            if hk.toast_until > time.time():
                ov.text(16, 68 if draw_log else 14, hk.toast, COL_HUD)
            ov.end()
            time.sleep(0.006)
    finally:
        rd.stop_flag.set()
        ov.close()
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dump', action='store_true')
    ap.add_argument('--fov', type=float, default=90.0, help='垂直 FOV（游戏档案 Fov 值）')
    ap.add_argument('--max-dist', type=float, default=2500.0)
    ap.add_argument('--team', type=int, default=7)
    ap.add_argument('--drop', default='2',
                    help='不绘制的阵营，逗号分隔（默认 2：无模型的幽灵实体）')
    a = ap.parse_args()
    drop = {int(x) for x in str(a.drop).split(',') if x.strip()}
    agent, proc = ammo_probe.connect_readonly(ammo_probe.TOOLKIT, 49700)
    try:
        base = proc['module_base']
        if a.dump:
            return dump_mode(agent, base, a.team, a.max_dist)
        return draw_mode(agent, base, a.team, a.max_dist, a.fov, drop)
    finally:
        agent.close()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(2)
