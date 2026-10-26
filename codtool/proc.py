"""Win32 进程内存访问层（ctypes 实现，无第三方依赖）。

面向 64 位目标进程（cod.exe / sp26-cod.exe）设计：
  * 打开进程（含降级权限链）
  * 枚举模块（模块基址 + 大小，用于模块内 RVA 定位）
  * 枚举内存区域（VirtualQueryEx），按保护属性过滤
  * 读/写内存（支持一次批量读）
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import struct
from dataclasses import dataclass
from typing import Iterator, Optional

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# ---- 访问权限 ----
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_ALL_ACCESS = 0x1F0FFF

# ---- 内存常量 ----
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200

WRITABLE_PROTECTS = (PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY)
READABLE_PROTECTS = WRITABLE_PROTECTS + (PAGE_READONLY, PAGE_EXECUTE_READ, PAGE_EXECUTE)

TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
MAX_PATH = 260
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wt.DWORD),
        ("__alignment1", wt.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
        ("__alignment2", wt.DWORD),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", wt.WCHAR * 256),
        ("szExePath", wt.WCHAR * MAX_PATH),
    ]


kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = (wt.DWORD, wt.BOOL, wt.DWORD)
kernel32.CloseHandle.argtypes = (wt.HANDLE,)
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.ReadProcessMemory.argtypes = (wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
kernel32.WriteProcessMemory.restype = wt.BOOL
kernel32.WriteProcessMemory.argtypes = (wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.VirtualQueryEx.argtypes = (wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION64), ctypes.c_size_t)
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = (wt.DWORD, wt.DWORD)
kernel32.Module32FirstW.restype = wt.BOOL
kernel32.Module32FirstW.argtypes = (wt.HANDLE, ctypes.POINTER(MODULEENTRY32W))
kernel32.Module32NextW.restype = wt.BOOL
kernel32.Module32NextW.argtypes = (wt.HANDLE, ctypes.POINTER(MODULEENTRY32W))
kernel32.IsWow64Process.restype = wt.BOOL
kernel32.IsWow64Process.argtypes = (wt.HANDLE, ctypes.POINTER(wt.BOOL))


@dataclass(frozen=True)
class Region:
    """一段已提交内存区域。"""
    base: int
    size: int
    protect: int
    type: int

    @property
    def end(self) -> int:
        return self.base + self.size

    @property
    def writable(self) -> bool:
        return (self.protect & 0xFF) in WRITABLE_PROTECTS

    @property
    def readable(self) -> bool:
        return (self.protect & 0xFF) in READABLE_PROTECTS and not (self.protect & PAGE_GUARD)


@dataclass(frozen=True)
class Module:
    name: str
    path: str
    base: int
    size: int

    def __contains__(self, addr: int) -> bool:
        return self.base <= addr < self.base + self.size

    def rva(self, addr: int) -> int:
        return addr - self.base


class ProcessError(RuntimeError):
    pass


def is_elevated() -> bool:
    """当前进程是否以管理员（高完整性级别）运行。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _probe_rights(pid: int) -> dict[str, bool]:
    out = {}
    for name, acc in (("qlim", PROCESS_QUERY_LIMITED_INFORMATION),
                      ("query", PROCESS_QUERY_INFORMATION),
                      ("vm_read", PROCESS_VM_READ),
                      ("vm_write", PROCESS_VM_WRITE),
                      ("all", PROCESS_ALL_ACCESS)):
        h = kernel32.OpenProcess(acc, False, pid)
        out[name] = bool(h)
        if h:
            kernel32.CloseHandle(h)
    return out


def diagnose_access(pid: int) -> str:
    """区分「完整性级别不足」与「驱动/保护拦截」，给出可直接照做的结论。"""
    r = _probe_rights(pid)
    if not r["qlim"]:
        return ("连 PROCESS_QUERY_LIMITED_INFORMATION 都被拒：目标进程已退出，"
                "或属于其他用户 / 受 PPL 保护。")
    if r["vm_read"] or r["vm_write"]:
        return "读写权限正常。"
    elevated = is_elevated()
    if not elevated:
        return ("诊断：QUERY_LIMITED 可过、VM_READ/VM_WRITE 被拒 —— 这是 Windows 的"
                "「no-read-up」策略：目标进程的完整性级别(HIGH)高于本进程(MEDIUM)。\n"
                "典型原因：游戏是从管理员控制台（或右键以管理员身份运行的 bat）启动的。\n"
                "解决：以管理员身份重新运行本工具，让两侧同为 HIGH。")
    return ("诊断：本进程已提权，但目标仍拒绝 VM_READ/VM_WRITE —— 说明是内核驱动"
            "（如 Randgrid.sys）在 ObRegisterCallbacks 里剥离了句柄权限，"
            "属于主动保护，需要走进程内注入（代理 DLL）路线。")


class Process:
    """目标进程句柄包装。"""

    def __init__(self, pid: int, handle: int, name: str = "", path: str = ""):
        self.pid = pid
        self.handle = handle
        self.name = name
        self.path = path
        self._modules: Optional[list[Module]] = None

    # ---------- 生命周期 ----------
    @classmethod
    def open(cls, pid: int, write: bool = True) -> "Process":
        access = PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ
        if write:
            access |= PROCESS_VM_WRITE
        handle = kernel32.OpenProcess(access, False, pid)
        if not handle:
            # 降级：某些场景只允许最小权限，先确认进程是否还活着
            err = ctypes.get_last_error()
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
            if not handle:
                raise ProcessError(
                    f"OpenProcess(pid={pid}) 失败，GetLastError={err}。\n"
                    + diagnose_access(pid)
                )
        return cls(pid, handle)

    @classmethod
    def by_name(cls, name: str, write: bool = True) -> "Process":
        pids = find_pids(name)
        if not pids:
            raise ProcessError(f"未找到进程: {name}")
        last: Optional[Exception] = None
        for pid in pids:
            try:
                return cls.open(pid, write=write)
            except ProcessError as e:
                last = e
        raise last  # type: ignore[misc]

    def close(self) -> None:
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = 0

    def __enter__(self) -> "Process":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------- 内存区域 ----------
    def regions(self, writable_only: bool = True) -> Iterator[Region]:
        return _iter_regions(self.handle, writable_only)

    # ---------- 读 ----------
    def read(self, addr: int, size: int) -> Optional[bytes]:
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(self.handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(read))
        if not ok or read.value != size:
            return None
        return buf.raw

    def read_or_raise(self, addr: int, size: int) -> bytes:
        data = self.read(addr, size)
        if data is None:
            err = ctypes.get_last_error()
            raise ProcessError(f"读取 0x{addr:X} 失败，GetLastError={err}")
        return data

    def read_fmt(self, addr: int, fmt: str):
        size = struct.calcsize(fmt)
        data = self.read(addr, size)
        if data is None:
            return None
        return struct.unpack(fmt, data)[0]

    def read_ptr(self, addr: int) -> Optional[int]:
        return self.read_fmt(addr, "<Q")

    def read_cstring(self, addr: int, max_len: int = 256) -> str:
        out = bytearray()
        while len(out) < max_len:
            chunk = self.read(addr + len(out), 64)
            if not chunk:
                break
            idx = chunk.find(b"\x00")
            if idx >= 0:
                out += chunk[:idx]
                break
            out += chunk
        return out.decode("utf-8", "replace")

    # ---------- 写 ----------
    def write(self, addr: int, data: bytes) -> bool:
        buf = ctypes.create_string_buffer(data, len(data))
        written = ctypes.c_size_t(0)
        ok = kernel32.WriteProcessMemory(self.handle, ctypes.c_void_p(addr), buf, len(data), ctypes.byref(written))
        return bool(ok) and written.value == len(data)

    def write_fmt(self, addr: int, fmt: str, value) -> bool:
        return self.write(addr, struct.pack(fmt, value))

    # ---------- 模块 ----------
    @property
    def modules(self) -> list[Module]:
        if self._modules is None:
            mods = list(_enum_modules(self.pid))
            if not mods:
                # Toolhelp 被拦时（部分反作弊会挡快照），改用 psapi 枚举
                mods = _enum_modules_psapi(self.handle)
            if not mods:
                # 两条都被拦：按映射文件名反向定位镜像
                mods = _find_image_modules_by_map(self.handle)
            self._modules = mods
        return self._modules

    def module(self, name: str) -> Optional[Module]:
        lname = name.lower()
        for m in self.modules:
            if m.name.lower() == lname:
                return m
        for m in self.modules:
            if lname in m.name.lower():
                return m
        return None

    def main_module(self) -> Module:
        mods = self.modules
        if not mods:
            raise ProcessError("无法枚举模块（权限不足？）")
        return mods[0]

    def base(self, module: str = "") -> int:
        return self.module(module).base if module else self.main_module().base

    def is_wow64(self) -> bool:
        wow = wt.BOOL(0)
        kernel32.IsWow64Process(self.handle, ctypes.byref(wow))
        return bool(wow.value)


def _iter_regions(handle: int, writable_only: bool = True) -> Iterator[Region]:
    addr = 0
    mbi = MEMORY_BASIC_INFORMATION64()
    max_addr = 0x7FFF_FFFF_FFFF
    while addr < max_addr:
        got = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not got:
            break
        if mbi.State == MEM_COMMIT and mbi.RegionSize:
            r = Region(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, mbi.Type)
            if (r.writable if writable_only else r.readable):
                yield r
        addr = mbi.BaseAddress + max(mbi.RegionSize, 0x1000)


def _enum_modules(pid: int) -> Iterator[Module]:
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        ok = kernel32.Module32FirstW(snap, ctypes.byref(entry))
        while ok:
            yield Module(entry.szModule, entry.szExePath, entry.modBaseAddr or 0, entry.modBaseSize)
            entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
            ok = kernel32.Module32NextW(snap, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snap)


def _mapped_file_name(handle: int, addr: int) -> str:
    """GetMappedFileNameW：查某个地址属于哪个映射文件（不受模块快照被拦影响）。"""
    try:
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
    except OSError:
        return ""
    psapi.GetMappedFileNameW.restype = wt.DWORD
    psapi.GetMappedFileNameW.argtypes = (wt.HANDLE, ctypes.c_void_p, wt.LPWSTR, wt.DWORD)
    buf = ctypes.create_unicode_buffer(MAX_PATH * 2)
    n = psapi.GetMappedFileNameW(handle, ctypes.c_void_p(addr), buf, len(buf))
    return buf.value if n else ""


def _find_image_modules_by_map(handle: int, hint: str = "") -> list[Module]:
    """兜底模块定位：遍历 MEM_IMAGE 区域，按映射文件名归并成一个 Module。

    用于 Toolhelp / psapi 都被反作弊拦截、但内存读写仍然可用的场景。
    """
    groups: dict[str, list[int]] = {}
    names: dict[str, str] = {}
    for r in _iter_regions(handle, writable_only=False):
        if r.type != MEM_IMAGE:
            continue
        name = _mapped_file_name(handle, r.base)
        if not name:
            continue
        key = name.lower()
        names.setdefault(key, name)
        g = groups.setdefault(key, [r.base, r.base + r.size])
        g[0] = min(g[0], r.base)
        g[1] = max(g[1], r.base + r.size)
    out = []
    for key, (lo, hi) in groups.items():
        full = names[key]
        base = os.path.basename(full.replace("\\", "/"))
        out.append(Module(base, full, lo, hi - lo))
    out.sort(key=lambda m: m.base)
    if hint:
        hl = hint.lower()
        out.sort(key=lambda m: 0 if m.name.lower() == hl else 1)
    return out


def _enum_modules_psapi(handle: int) -> list[Module]:
    """psapi 枚举模块（备用路径）。需要 QUERY_INFORMATION|VM_READ 句柄。"""
    try:
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
    except OSError:
        return []

    class MODULEINFO(ctypes.Structure):
        _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                    ("SizeOfImage", wt.DWORD),
                    ("EntryPoint", ctypes.c_void_p)]

    LIST_MODULES_ALL = 0x03
    psapi.EnumProcessModulesEx.restype = wt.BOOL
    psapi.EnumProcessModulesEx.argtypes = (wt.HANDLE, ctypes.POINTER(wt.HMODULE),
                                          wt.DWORD, ctypes.POINTER(wt.DWORD), wt.DWORD)
    psapi.GetModuleBaseNameW.restype = wt.DWORD
    psapi.GetModuleBaseNameW.argtypes = (wt.HANDLE, wt.HMODULE, wt.LPWSTR, wt.DWORD)
    psapi.GetModuleFileNameExW.restype = wt.DWORD
    psapi.GetModuleFileNameExW.argtypes = (wt.HANDLE, wt.HMODULE, wt.LPWSTR, wt.DWORD)
    psapi.GetModuleInformation.restype = wt.BOOL
    psapi.GetModuleInformation.argtypes = (wt.HANDLE, wt.HMODULE,
                                           ctypes.POINTER(MODULEINFO), wt.DWORD)

    needed = wt.DWORD(0)
    buf = (wt.HMODULE * 2048)()
    if not psapi.EnumProcessModulesEx(handle, buf, ctypes.sizeof(buf), ctypes.byref(needed), LIST_MODULES_ALL):
        return []
    count = min(needed.value // ctypes.sizeof(wt.HMODULE), 2048)
    out: list[Module] = []
    for i in range(count):
        hmod = buf[i]
        name = ctypes.create_unicode_buffer(MAX_PATH)
        path = ctypes.create_unicode_buffer(MAX_PATH)
        psapi.GetModuleBaseNameW(handle, hmod, name, MAX_PATH)
        psapi.GetModuleFileNameExW(handle, hmod, path, MAX_PATH)
        mi = MODULEINFO()
        size = 0
        base = int(hmod or 0)
        if psapi.GetModuleInformation(handle, hmod, ctypes.byref(mi), ctypes.sizeof(mi)):
            base = int(mi.lpBaseOfDll or base)
            size = int(mi.SizeOfImage)
        out.append(Module(name.value or "?", path.value or "", base, size))
    return out


def find_pids(name: str) -> list[int]:
    """按 exe 名（不含路径，可省略 .exe）查找 PID。"""
    target = name.lower()
    if not target.endswith(".exe"):
        target += ".exe"
    result: list[int] = []
    snap = kernel32.CreateToolhelp32Snapshot(2, 0)  # TH32CS_SNAPPROCESS
    if not snap or snap == INVALID_HANDLE_VALUE:
        return result

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wt.DWORD),
            ("cntUsage", wt.DWORD),
            ("th32ProcessID", wt.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wt.DWORD),
            ("cntThreads", wt.DWORD),
            ("th32ParentProcessID", wt.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wt.DWORD),
            ("szExeFile", wt.WCHAR * MAX_PATH),
        ]

    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            if pe.szExeFile.lower() == target:
                result.append(pe.th32ProcessID)
            ok = kernel32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        kernel32.CloseHandle(snap)
    return result


kernel32.Process32FirstW.restype = wt.BOOL
kernel32.Process32FirstW.argtypes = (wt.HANDLE, ctypes.c_void_p)
kernel32.Process32NextW.restype = wt.BOOL
kernel32.Process32NextW.argtypes = (wt.HANDLE, ctypes.c_void_p)
