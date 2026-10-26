"""进程内代理客户端：通过本地端口读写游戏内存。

与 codtool.proc.Process 保持同样的读写接口，因此 scanner / trainer / gui
无需改动即可复用。使用前提：游戏已加载 agent 代理 DLL（见 install_proxy.py）。
"""

from __future__ import annotations

import socket
import struct
import threading
from dataclasses import dataclass
from typing import Iterator, Optional

from .proc import (
    MEM_COMMIT, Module, Region, WRITABLE_PROTECTS, READABLE_PROTECTS,
    PAGE_GUARD, ProcessError,
)

OP_READ, OP_WRITE, OP_INFO, OP_REGIONS, OP_PING = 1, 2, 3, 4, 5
MAX_CHUNK = 4 * 1024 * 1024


class AgentProcess:
    """实现与 Process 相同的读取/写入/区域枚举接口。"""

    max_chunk = MAX_CHUNK
    fast_scan = False

    def __init__(self, sock: socket.socket, pid: int, name: str, base: int, size: int):
        self.sock = sock
        # 冻结线程与扫描线程可能并发发请求；单连接必须串行化，否则会串包
        self._lock = threading.RLock()
        self.pid = pid
        self.handle = 0
        self._mod = Module(name, "", base, size)

    # ---------- 连接 ----------
    @classmethod
    def connect(cls, host: str = "127.0.0.1", port: int = 49700, timeout: float = 5.0) -> "AgentProcess":
        try:
            s = socket.create_connection((host, port), timeout=timeout)
        except OSError as e:
            raise ProcessError(
                f"连不上进程内代理 {host}:{port} —— {e}\n"
                "可能原因：游戏没加载代理 DLL，或游戏未运行。"
            ) from None
        s.settimeout(timeout)
        obj = cls(s, 0, "?", 0, 0)
        try:
            pid = obj.ping()
            base, size, name = obj.info()
            obj.pid = pid
            obj._mod = Module(name, "", base, size)
            # 探测 DLL 是否带进程内扫描引擎（v1 没有），不能只看 hasattr
            try:
                obj.scan_clear()
                obj.fast_scan = True
            except Exception:
                obj.fast_scan = False
            return obj
        except Exception:
            # 探测失败必须关闭 socket，否则会留下"已连接但没协议往来"的死连接，
            # 把代理的连接槽占死（表现为后续连接一直接超时）
            try:
                s.close()
            except OSError:
                pass
            raise

    def ping(self) -> int:
        with self._lock:
            self.sock.sendall(b"\x05")
            d = self._recv(5)
            if not d[0]:
                raise ProcessError("PING 失败")
            return struct.unpack_from("<I", d, 1)[0]

    def info(self) -> tuple[int, int, str]:
        with self._lock:
            self.sock.sendall(b"\x03")
            head = self._recv(21)
            if not head[0]:
                raise ProcessError("INFO 失败")
            base, size, nlen = struct.unpack_from("<QQI", head, 1)
            name = self._recv(nlen).decode("mbcs", "replace") if nlen else "?"
            return base, size, name

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "AgentProcess":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _recv(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            b = self.sock.recv(n - len(buf))
            if not b:
                raise ProcessError("代理连接中断")
            buf += b
        return bytes(buf)

    # ---------- 读写 ----------
    def read(self, addr: int, size: int) -> Optional[bytes]:
        with self._lock:
            return self._read(addr, size)

    def _read(self, addr: int, size: int) -> Optional[bytes]:
        out = bytearray()
        remain = size
        cur = addr
        while remain > 0:
            n = min(remain, MAX_CHUNK)
            self.sock.sendall(b"\x01" + struct.pack("<QI", cur, n))
            r = self._recv(5)
            got = struct.unpack_from("<I", r, 1)[0]
            data = self._recv(got) if got else b""
            if not r[0] or got != n:
                # 部分成功时返回已拿到的部分，调用方按长度判断
                out += data
                return bytes(out) if out else None
            out += data
            cur += n
            remain -= n
        return bytes(out)

    def read_or_raise(self, addr: int, size: int) -> bytes:
        d = self.read(addr, size)
        if d is None:
            raise ProcessError(f"代理读取 0x{addr:X}+{size} 失败")
        return d

    def read_fmt(self, addr: int, fmt: str):
        n = struct.calcsize(fmt)
        d = self.read(addr, n)
        if d is None or len(d) != n:
            return None
        return struct.unpack(fmt, d)[0]

    def read_ptr(self, addr: int) -> Optional[int]:
        return self.read_fmt(addr, "<Q")

    def read_cstring(self, addr: int, max_len: int = 256) -> str:
        out = bytearray()
        while len(out) < max_len:
            chunk = self.read(addr + len(out), 64)
            if not chunk:
                break
            i = chunk.find(b"\x00")
            if i >= 0:
                out += chunk[:i]
                break
            out += chunk
        return out.decode("utf-8", "replace")

    def write(self, addr: int, data: bytes) -> bool:
        with self._lock:
            return self._write(addr, data)

    def _write(self, addr: int, data: bytes) -> bool:
        total = 0
        while total < len(data):
            part = data[total:total + MAX_CHUNK]
            self.sock.sendall(b"\x02" + struct.pack("<QI", addr + total, len(part)) + part)
            r = self._recv(5)
            if not r[0]:
                return False
            total += struct.unpack_from("<I", r, 1)[0]
        return total == len(data)

    def write_fmt(self, addr: int, fmt: str, value) -> bool:
        return self.write(addr, struct.pack(fmt, value))

    # ---------- 进程内扫描（v2） ----------
    def _long_op(self, fn, timeout: float = 300.0):
        """长操作（全内存扫描）期间临时放宽 socket 超时；默认 5 秒会把 50 秒的扫描误判成超时。"""
        old = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        try:
            return fn()
        finally:
            try:
                self.sock.settimeout(old)
            except OSError:
                pass

    def scan_begin(self, dsize: int, mode: int, v1: float, v2: float = 0.0,
                   writable_only: bool = True) -> tuple[int, bool]:
        """在进程内全内存扫描。mode 0=按位精确（v1 由 raw_to_double 打包），1=范围。"""
        def run():
            self.sock.sendall(b"\x06" + struct.pack("<IIddI", dsize, mode, v1, v2,
                                                    1 if writable_only else 0))
            d = self._recv(6)
            if not d[0]:
                raise ProcessError("SCAN_BEGIN 失败")
            return struct.unpack_from("<I", d, 1)[0], bool(d[5])
        with self._lock:
            return self._long_op(run)

    def scan_filter(self, mode: int, v1: float = 0.0, v2: float = 0.0) -> int:
        """mode: 0变化 1未变 2变大 3变小 4精确 5范围"""
        def run():
            self.sock.sendall(b"\x07" + struct.pack("<Idd", mode, v1, v2))
            d = self._recv(5)
            if not d[0]:
                raise ProcessError("SCAN_FILTER 失败")
            return struct.unpack_from("<I", d, 1)[0]
        with self._lock:
            return self._long_op(run, 120.0)

    def scan_get(self, start: int = 0, count: int = 65536) -> list[tuple[int, int]]:
        with self._lock:
            self.sock.sendall(b"\x08" + struct.pack("<II", start, count))
            head = self._recv(5)
            if not head[0]:
                raise ProcessError("SCAN_GET 失败")
            n = struct.unpack_from("<I", head, 1)[0]
            payload = self._recv(n * 16) if n else b""
            return [struct.unpack_from("<QQ", payload, i * 16) for i in range(n)]

    def scan_all(self, limit: int = 200000) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        start = 0
        while len(out) < limit:
            chunk = self.scan_get(start, min(65536, limit - len(out)))
            if not chunk:
                break
            out.extend(chunk)
            start += len(chunk)
        return out

    def scan_clear(self) -> None:
        with self._lock:
            self.sock.sendall(b"\x09")
            self._recv(1)

    def scan_write(self, dsize: int, raw: int) -> int:
        with self._lock:
            self.sock.sendall(b"\x0c" + struct.pack("<IQ", dsize, raw))
            d = self._recv(5)
            return struct.unpack_from("<I", d, 1)[0] if d[0] else 0

    def snap(self, addr: int, size: int) -> int:
        with self._lock:
            self.sock.sendall(b"\x0a" + struct.pack("<QI", addr, size))
            d = self._recv(5)
            return struct.unpack_from("<I", d, 1)[0] if d[0] else 0

    def diff(self, min_delta: int = 0) -> list[tuple[int, int, int]]:
        """与上次 snap 比较，返回 [(偏移, 旧值(int32), 新值(int32))]（只比 4 字节整数）。"""
        with self._lock:
            self.sock.sendall(b"\x0b" + struct.pack("<I", min_delta))
            head = self._recv(5)
            if not head[0]:
                raise ProcessError("DIFF 失败")
            n = struct.unpack_from("<I", head, 1)[0]
            payload = self._recv(n * 20) if n else b""
            return [struct.unpack_from("<Iqq", payload, i * 20) for i in range(n)]

    def hash_begin(self, writable_only: bool = True) -> int:
        """全内存按页哈希采样（4 KiB/页），用于"不知道值也能找变化"。"""
        def run():
            self.sock.sendall(b"\x0d" + struct.pack("<I", 1 if writable_only else 0))
            d = self._recv(5)
            if not d[0]:
                raise ProcessError("HASH_BEGIN 失败")
            return struct.unpack_from("<I", d, 1)[0]
        with self._lock:
            return self._long_op(run)

    def hash_diff(self) -> list[int]:
        """与上次采样比较，返回内容发生过变化的页地址列表。"""
        def run():
            self.sock.sendall(b"\x0e")
            head = self._recv(5)
            if not head[0]:
                raise ProcessError("HASH_DIFF 失败")
            n = struct.unpack_from("<I", head, 1)[0]
            payload = self._recv(n * 8) if n else b""
            return [struct.unpack_from("<Q", payload, i * 8)[0] for i in range(n)]
        with self._lock:
            return self._long_op(run)

    # ---------- 页保护写断点 ----------
    def bp_arm(self, watch_addr: int) -> bool:
        """把 watch_addr 所在页临时设为只读，捕获写入指令（异步，稍后用 bp_get 取）。"""
        with self._lock:
            self.sock.sendall(b"\x0f" + struct.pack("<Q", watch_addr))
            d = self._recv(1)
            return bool(d[0])

    def bp_get(self) -> list[tuple[int, int, int]]:
        """返回 [(rip, 模块内RVA, 被写地址)]。"""
        with self._lock:
            self.sock.sendall(b"\x10")
            head = self._recv(5)
            if not head[0]:
                raise ProcessError("BP_GET 失败")
            n = struct.unpack_from("<I", head, 1)[0]
            payload = self._recv(n * 24) if n else b""
            return [struct.unpack_from("<QQQ", payload, i * 24) for i in range(n)]

    def bp_disarm(self) -> None:
        with self._lock:
            self.sock.sendall(b"\x11")
            self._recv(1)

    # ---------- 硬件写断点（DR0，精确到地址） ----------
    def env(self):
        """返回 (PEB, ImageBase)。PEB 用于解密游戏内部的加密指针表。"""
        with self._lock:
            self.sock.sendall(b"")
            d = self._recv(17)
            if not d[0]:
                raise ProcessError("ENV 失败")
            return struct.unpack_from("<QQ", d, 1)

    def bp_hw_set(self, addr: int) -> bool:
        with self._lock:
            self.sock.sendall(b"\x12" + struct.pack("<Q", addr))
            d = self._recv(1)
            return bool(d[0])

    def bp_hw_get(self):
        """返回 [(rip, rva, tid, rsp, rcx, rdx, rsi, rdi)]。"""
        with self._lock:
            self.sock.sendall(b"")
            head = self._recv(5)
            if not head[0]:
                raise ProcessError("BP_HW_GET 失败")
            n = struct.unpack_from("<I", head, 1)[0]
            payload = self._recv(n * 60) if n else b""
            out = []
            for i in range(n):
                o = i * 60
                rip, rva = struct.unpack_from("<QQ", payload, o)
                tid = struct.unpack_from("<I", payload, o + 16)[0]
                rsp, rcx, rdx, rsi, rdi = struct.unpack_from("<QQQQQ", payload, o + 20)
                out.append((rip, rva, tid, rsp, rcx, rdx, rsi, rdi))
            return out

    def hook_call(self, site: int, fn: int, ret: int, filt: int = 0) -> bool:
        """把 site 处的 call 换成跳板；只有 ecx 低16位 == filt 时才记录寄存器。"""
        with self._lock:
            self.sock.sendall(b"" + struct.pack("<QQQI", site, fn, ret, filt))
            d = self._recv(1)
            return bool(d[0])

    def hook_enter(self, fn: int, patch_len: int = 7, filt: int = 0xFFFFFFFF) -> bool:
        """在函数入口下通用跳板：搬运前 patch_len 字节，filt=0xFFFFFFFF 表示不过滤。"""
        with self._lock:
            self.sock.sendall(b"" + struct.pack("<QII", fn, patch_len, filt))
            d = self._recv(1)
            return bool(d[0])

    def hook_get(self):
        """返回 (rsi, rcx, rdx, hits)。"""
        with self._lock:
            self.sock.sendall(b"")
            d = self._recv(33)
            if not d[0]:
                raise ProcessError("HOOK_GET 失败")
            return struct.unpack_from("<QQQQ", d, 1)

    def hook_clr(self) -> None:
        with self._lock:
            self.sock.sendall(b"")
            self._recv(1)

    def lock_add(self, addr: int, size: int, raw: int, interval: int = 1) -> bool:
        """在代理内部用 interval 毫秒循环写该值（低开销冻结）。"""
        with self._lock:
            self.sock.sendall(b"" + struct.pack("<QIQI", addr, size, raw, interval))
            d = self._recv(1)
            return bool(d[0])

    def lock_clr(self) -> None:
        with self._lock:
            self.sock.sendall(b"")
            self._recv(1)

    def fly_set(self, enable: bool = True, mode: int = 0, scale10: int = 40,
                vk_up: int = 0x20, vk_down: int = 0x43,
                vk_toggle: int = 0x76, vk_speed: int = 0x77) -> bool:
        """开启/关闭进程内飞行循环（mode 0=钉高度 1=noclip）。"""
        with self._lock:
            self.sock.sendall(b"\x20" + struct.pack(
                "<BBIIIII", 1 if enable else 0, mode, scale10,
                vk_up, vk_down, vk_toggle, vk_speed))
            d = self._recv(1)
            return bool(d and d[0])

    def fly_get(self):
        with self._lock:
            self.sock.sendall(b"\x21")
            d = self._recv(36)
        if not d or len(d) < 36:
            return None
        z, tz, bz, ticks, hp = struct.unpack_from("<fffii", d, 4)
        return {
            "on": bool(d[1]), "mode": d[2], "err": d[3],
            "z": z, "tz": tz, "bz": bz, "ticks": ticks, "hp": hp,
            "client": struct.unpack_from("<Q", d, 24)[0],
            "scale10": struct.unpack_from("<I", d, 32)[0],
        }

    def fly_clr(self) -> None:
        with self._lock:
            self.sock.sendall(b"\x22")
            self._recv(1)

    def fly_nudge(self, dz: float) -> bool:
        """给飞行目标高度叠加一个增量（自测用）。"""
        with self._lock:
            self.sock.sendall(b"\x23" + struct.pack("<f", dz))
            d = self._recv(1)
            return bool(d and d[0])

    def aim_set(self, enable: bool = True, hold: bool = True, vk: int = 0x02,
                cone10: int = 80, max_dist: int = 3000, team: int = 7,
                head_dz: float = 62.0) -> bool:
        """开启/关闭准星吸附（进程内相对鼠标注入 + 自动标定）。"""
        with self._lock:
            self.sock.sendall(b"\x24" + struct.pack(
                "<BBIIIIf", 1 if enable else 0, 1 if hold else 0, vk,
                cone10, max_dist, team, head_dz))
            d = self._recv(1)
            return bool(d and d[0])

    def aim_get(self):
        with self._lock:
            self.sock.sendall(b"\x25")
            d = self._recv(40)
        if not d or len(d) < 40:
            return None
        dist, ey, ep, gx, gy, ticks, err = struct.unpack_from("<fffffii", d, 12)
        return {
            "on": bool(d[1]), "calib": bool(d[2]), "has_tgt": bool(d[3]),
            "slot": struct.unpack_from("<i", d, 4)[0],
            "hp": struct.unpack_from("<i", d, 8)[0],
            "dist": dist, "err_yaw": ey, "err_pitch": ep,
            "gain_x": gx, "gain_y": gy, "ticks": ticks, "err": err,
        }

    def aim_clr(self) -> None:
        with self._lock:
            self.sock.sendall(b"\x26")
            self._recv(1)

    def aim_mouse(self, dx: int, dy: int) -> bool:
        """调试用：注入相对鼠标移动（限 ±400）。"""
        with self._lock:
            self.sock.sendall(b"\x27" + struct.pack("<ii", dx, dy))
            d = self._recv(1)
            return bool(d and d[0])

    def aim_btn(self, btn: int = 2, down: bool = True) -> bool:
        """调试用：注入鼠标按键（1 左 / 2 右）。"""
        with self._lock:
            self.sock.sendall(b"\x28" + struct.pack("<BB", btn, 1 if down else 0))
            d = self._recv(1)
            return bool(d and d[0])

    def aim_cfg(self, interval_ms: int = 14, strength: int = 50,
                smooth: int = 0, lead_ms: int = 40) -> bool:
        """瞄准调节：指令间隔(ms)、力度(%)、平滑(%)、头部速度提前量(ms)。"""
        with self._lock:
            self.sock.sendall(b"\x29" + struct.pack(
                "<IIII", interval_ms, strength, smooth, lead_ms))
            d = self._recv(1)
            return bool(d and d[0])

    def aim_chain(self, enable: bool = True, radius: int = 600) -> bool:
        """连续吸附：目标死亡后就近换敌，radius 为搜索半径（游戏单位）。"""
        with self._lock:
            self.sock.sendall(b"\x2a" + struct.pack(
                "<II", 1 if enable else 0, radius))
            d = self._recv(1)
            return bool(d and d[0])

    def vacuum_set(self, enable: bool = True, dist_cm: int = 400, up_cm: int = 0,
                   ring_cm: int = 60, team_excl: int = 7, team_only: int = 3,
                   flags: int = 7) -> bool:
        """吸敌人：把敌对 NPC 钉到镜头前方 dist_cm 处，默认 0.6m 圆环、只吸 team 3。
        flags: bit0 头部跟随 / bit1 写 +0x140 / bit2 写 +0x158。"""
        with self._lock:
            self.sock.sendall(b"\x2b" + struct.pack(
                "<IIIIIII", 1 if enable else 0, dist_cm, up_cm & 0xFFFFFFFF,
                ring_cm, team_excl, team_only, flags))
            d = self._recv(1)
            return bool(d and d[0])

    def vacuum_get(self):
        """返回 (on, ticks, n, writes, drift, head_err, dist_cm, flags)。"""
        with self._lock:
            self.sock.sendall(b"\x2c")
            r = self._recv(32)
            if not r or not r[0]:
                return None
            on = bool(r[1])
            ticks, n, writes = struct.unpack_from("<iii", r, 4)
            drift, head_err = struct.unpack_from("<ff", r, 16)
            dist, flags = struct.unpack_from("<II", r, 24)
            return on, ticks, n, writes, drift, head_err, dist, flags

    def team_cfg(self, auto: bool = True, extra_mask: int = 1 << 2,
                 manual: int = 0, resample: bool = False) -> bool:
        """阵营自动识别：auto=开局采样最近 3 个 NPC；extra_mask=额外排除位（默认 team 2）；
        manual=强制友军 team（1..31，0=不强制）；resample=立即重采样。"""
        with self._lock:
            self.sock.sendall(b"\x2d" + struct.pack(
                "<IIII", 1 if auto else 0, extra_mask & 0xFFFFFFFF,
                manual, 1 if resample else 0))
            d = self._recv(1)
            return bool(d and d[0])

    def team_get(self):
        """返回 (auto, state, friendly, extra_mask, samples, ticks)。
        state: 0空闲 1采样中 2已锁定 3失败。"""
        with self._lock:
            self.sock.sendall(b"\x2e")
            r = self._recv(20)
            if not r or not r[0]:
                return None
            auto, state = bool(r[1]), r[2]
            friendly, mask, samples, ticks = struct.unpack_from("<iIii", r, 4)
            return auto, state, friendly, mask, samples, ticks

    def bp_sw_set(self, addr: int) -> bool:
        """INT3 软件断点（不挂线程、不碰调试寄存器，最安全）。"""
        with self._lock:
            self.sock.sendall(b"" + struct.pack("<Q", addr))
            d = self._recv(1)
            return bool(d[0])

    def bp_sw_clr(self) -> None:
        with self._lock:
            self.sock.sendall(b"")
            self._recv(1)

    def bp_hw_exec(self, addr: int) -> bool:
        """执行断点：命中点在指令执行之前，此时 [rsp] 就是调用方返回地址。"""
        with self._lock:
            self.sock.sendall(b"" + struct.pack("<Q", addr))
            d = self._recv(1)
            return bool(d[0])

    def bp_hw_clr(self) -> None:
        with self._lock:
            self.sock.sendall(b"\x14")
            self._recv(1)

    # ---------- 区域 ----------
    def regions(self, writable_only: bool = True) -> Iterator[Region]:
        # 先在锁内取完快照，再在锁外迭代：避免调用方长时间占用连接
        with self._lock:
            items = list(self._regions(writable_only))
        yield from items

    def _regions(self, writable_only: bool = True) -> Iterator[Region]:
        cur = 0
        while True:
            self.sock.sendall(b"\x04" + struct.pack("<Q", cur))
            head = self._recv(13)
            if not head[0]:
                return
            count, nxt = struct.unpack_from("<IQ", head, 1)
            payload = self._recv(count * 24) if count else b""
            for i in range(count):
                base, size, prot, typ = struct.unpack_from("<QQII", payload, i * 24)
                r = Region(base, size, prot, typ)
                if (r.writable if writable_only else r.readable):
                    yield r
            if not nxt or count == 0:
                return
            cur = nxt

    # ---------- 模块（代理只暴露主模块） ----------
    @property
    def modules(self) -> list[Module]:
        return [self._mod]

    def module(self, name: str) -> Optional[Module]:
        if not name or name.lower() in (self._mod.name.lower(), "sp26-cod.exe"):
            return self._mod
        return None

    def main_module(self) -> Module:
        return self._mod

    def base(self, module: str = "") -> int:
        m = self.module(module) or self._mod
        return m.base

    def is_wow64(self) -> bool:
        return False
