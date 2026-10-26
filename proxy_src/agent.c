/*
 * codtool in-process agent  (v2)
 * ------------------------------------------------------------------
 * 作为 steam_api64.dll 的代理层被游戏加载：全部导出转发到
 * steam_api64_real.dll（同目录），并在进程内提供控制端口。
 *
 * v2 新增：
 *   - 每个连接独立线程（v1 单客户端，旧连接不释放就会让新连接超时）
 *   - 进程内扫描引擎：全内存扫描在进程里做，只回传命中地址
 *     （8 GB 约 5-15 s，而不是通过 socket 传 8 GB 数据要 2 分钟）
 *   - 快照/差分（SNAP/DIFF）：用于加密数值——不猜值，直接看哪 4 字节变了
 *
 * 协议（little-endian）
 *   1 READ        u64 addr, u32 len                 -> u8 ok, u32 n, data
 *   2 WRITE       u64 addr, u32 len, data           -> u8 ok, u32 n
 *   3 INFO                                          -> u8 ok, u64 base, u64 size, u32 nlen, name
 *   4 REGIONS     u64 start                         -> u8 ok, u32 count, u64 next, count*(u64,u64,u32,u32)
 *   5 PING                                          -> u8 ok, u32 pid
 *   6 SCAN_BEGIN  u32 dsize, u32 mode, f64 v1, f64 v2, u32 writable_only
 *                                                   -> u8 ok, u32 count, u8 capped
 *   7 SCAN_FILTER u32 mode, f64 v1, f64 v2          -> u8 ok, u32 count
 *   8 SCAN_GET    u32 start, u32 count              -> u8 ok, u32 n, n*(u64 addr, u64 raw)
 *   9 SCAN_CLEAR                                    -> u8 ok
 *  10 SNAP        u64 addr, u32 size                -> u8 ok, u32 size
 *  11 DIFF        u32 min_delta                     -> u8 ok, u32 n, n*(u32 off, i64 oldv, i64 newv)
 *
 * mode (SCAN_BEGIN): 0=精度(按位相等, v1 的低位是原始字节), 1=范围([v1,v2])
 * mode (SCAN_FILTER):0=变化 1=未变 2=变大 3=变小 4=精确 5=范围
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>

#define AGENT_PORT   49700
#define MAX_XFER     (8 * 1024 * 1024)
#define SCAN_CAP     4000000u          /* 候选上限：addrs+vals 约 64 MB */
#define SNAP_CAP     (512 * 1024)

typedef struct { const char *name; void **slot; } proxy_entry;
extern proxy_entry g_tbl[];
extern int g_tbl_count;
void proxy_resolve(void);
void proxy_null_stub(void) { }

/* ---------------- 日志 ---------------- */
static CRITICAL_SECTION g_log_cs;
static FILE *g_log = NULL;

static void logf_(const char *fmt, ...)
{
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    EnterCriticalSection(&g_log_cs);
    if (!g_log) {
        char path[MAX_PATH];
        DWORD n = GetTempPathA(MAX_PATH, path);
        if (n) {
            strncat(path, "codtool_agent.log", MAX_PATH - n - 1);
            g_log = fopen(path, "a");
        }
    }
    if (g_log) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_log, "[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, line);
        fflush(g_log);
    }
    LeaveCriticalSection(&g_log_cs);
}

/* ---------------- 扫描状态 ---------------- */
static CRITICAL_SECTION g_scan_cs;
static uint64_t *g_addrs = NULL;
static uint64_t *g_vals  = NULL;
static uint32_t  g_count = 0;
static uint32_t  g_dtype = 4;
static int       g_capped = 0;

/* 全内存页哈希表：不知道加密值也能定位变化 */
#define PAGE_SZ   4096u
#define HASH_CAP  4000000u
static uint64_t *g_ph_addr = NULL;
static uint64_t *g_ph_hash = NULL;
static uint32_t  g_ph_count = 0;

static uint64_t fnv1a(const unsigned char *p, size_t n)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

typedef void (*page_cb)(uint64_t addr, const unsigned char *buf, size_t len, uint32_t idx);

static uint32_t walk_pages(int writable_only, page_cb cb, uint32_t limit)
{
    MEMORY_BASIC_INFORMATION mbi;
    unsigned long long addr = 0;
    unsigned char buf[PAGE_SZ];
    uint32_t idx = 0;
    while (addr < 0x7FFFFFFF0000ULL) {
        SIZE_T got = VirtualQueryEx(GetCurrentProcess(), (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi));
        if (!got) break;
        int readable = mbi.State == MEM_COMMIT && mbi.RegionSize &&
                       (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                       PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
                       !(mbi.Protect & PAGE_GUARD);
        int is_w = (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        if (readable && (!writable_only || is_w)) {
            unsigned long long a = (unsigned long long)(uintptr_t)mbi.BaseAddress;
            unsigned long long end = a + mbi.RegionSize;
            while (a < end) {
                SIZE_T want = (SIZE_T)((end - a) >= PAGE_SZ ? PAGE_SZ : (end - a));
                SIZE_T read = 0;
                if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(uintptr_t)a, buf, want, &read) && read) {
                    if (cb) cb((uint64_t)a, buf, read, idx);
                    idx++;
                    if (limit && idx >= limit) return idx;
                }
                a += want;
            }
        }
        addr = (unsigned long long)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    return idx;
}

static void cb_store(uint64_t addr, const unsigned char *buf, size_t len, uint32_t idx)
{
    if (idx < HASH_CAP) {
        g_ph_addr[idx] = addr;
        g_ph_hash[idx] = fnv1a(buf, len);
    }
}

/* ================= 页保护写断点（找"谁在写这个地址"） =================
 * 把目标地址所在 4 KiB 页临时设为只读；引擎每帧写该地址时会触发 AV，
 * VEH 里取 ContextRecord->Rip 记录调用点，然后立刻恢复可写让游戏继续。
 * 只用 VirtualProtect + 读寄存器，无分配、无锁，尽量降低崩溃风险。
 */
static uint64_t g_mod_base = 0, g_mod_size = 0;
static volatile LONG g_hw_active = 0;
static volatile LONG g_hw_ever = 0;
static uint64_t      g_hw_addr = 0;
static volatile LONG g_hw_hits = 0;
static uint64_t      g_hw_rips[16];
static uint64_t      g_hw_rvas[16];
static uint32_t      g_hw_tids[16];
static uint64_t      g_hw_rsp[16];
static uint64_t      g_hw_regs[16][4];   /* rcx, rdx, rsi, rdi */

/* 软件断点（INT3）：不挂起线程、不碰调试寄存器，最安全 */
static unsigned char *g_sw_addr = NULL;
static unsigned char  g_sw_orig = 0;
static volatile LONG  g_sw_active = 0;
static volatile LONG  g_sw_pending = 0;
static DWORD          g_sw_oldprot = 0;

static PVOID          g_veh = NULL;
static volatile LONG  g_bp_armed = 0;
static volatile LONG  g_bp_active = 0;
static volatile LONG  g_bp_hits = 0;       /* 命中「目标地址」的次数 */
static volatile LONG  g_bp_total = 0;      /* 页内所有写入次数（仅统计） */
static unsigned char *g_bp_page = NULL;
static DWORD          g_bp_oldprot = 0;
static uint64_t       g_bp_watch = 0;
static uint64_t       g_bp_rips[16];
static uint64_t       g_bp_addrs[16];

static LONG CALLBACK bp_handler(EXCEPTION_POINTERS *ep)
{
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        if (!g_sw_addr) return EXCEPTION_CONTINUE_SEARCH;
        {
            unsigned char *rip = (unsigned char *)(uintptr_t)ep->ContextRecord->Rip;
            /* 不同路径下 Rip 可能指向断点本身或其后一字节，两种都认 */
            if (rip != g_sw_addr && rip - 1 != g_sw_addr)
                return EXCEPTION_CONTINUE_SEARCH;
        }
        LONG n = InterlockedIncrement(&g_hw_hits);
        if (n <= 16) {
            uint64_t rip = (uint64_t)(uintptr_t)g_sw_addr;
            g_hw_rips[n - 1] = rip;
            g_hw_rvas[n - 1] = (rip >= g_mod_base && rip < g_mod_base + g_mod_size) ? rip - g_mod_base : 0;
            g_hw_tids[n - 1] = GetCurrentThreadId();
            g_hw_rsp[n - 1] = (uint64_t)ep->ContextRecord->Rsp;
            g_hw_regs[n - 1][0] = (uint64_t)ep->ContextRecord->Rcx;
            g_hw_regs[n - 1][1] = (uint64_t)ep->ContextRecord->Rdx;
            g_hw_regs[n - 1][2] = (uint64_t)ep->ContextRecord->Rsi;
            g_hw_regs[n - 1][3] = (uint64_t)ep->ContextRecord->Rdi;
        }
        *g_sw_addr = g_sw_orig;                       /* 还原被 INT3 覆盖的字节 */
        ep->ContextRecord->Rip = (DWORD64)(uintptr_t)g_sw_addr;
        ep->ContextRecord->EFlags |= 0x100;            /* TF：执行完这一条再陷一次 */
        InterlockedExchange(&g_sw_pending, 1);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        /* 关键：只要历史上武装过，就必须清 DR 并吞掉。
           否则 bp_hw_clr 与 trap 的竞态会让单步异常冒到游戏里 → 0x80000004 崩溃。 */
        if (g_hw_ever) {
            if (g_hw_active) {
                LONG n = InterlockedIncrement(&g_hw_hits);
                if (n <= 16) {
                    uint64_t rip = (uint64_t)ep->ContextRecord->Rip;
                    uint64_t rva = (rip >= g_mod_base && rip < g_mod_base + g_mod_size) ? rip - g_mod_base : 0;
                    g_hw_rips[n - 1] = rip;
                    g_hw_rvas[n - 1] = rva;
                    g_hw_tids[n - 1] = GetCurrentThreadId();
                    g_hw_rsp[n - 1] = (uint64_t)ep->ContextRecord->Rsp;
                    g_hw_regs[n - 1][0] = (uint64_t)ep->ContextRecord->Rcx;
                    g_hw_regs[n - 1][1] = (uint64_t)ep->ContextRecord->Rdx;
                    g_hw_regs[n - 1][2] = (uint64_t)ep->ContextRecord->Rsi;
                    g_hw_regs[n - 1][3] = (uint64_t)ep->ContextRecord->Rdi;
                }
            }
            ep->ContextRecord->Dr0 = 0;
            ep->ContextRecord->Dr7 = 0;
            ep->ContextRecord->Dr6 = 0;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (g_sw_pending && g_sw_addr) {   /* 即使已撤断点，待处理的单步也必须兜底 */
            ep->ContextRecord->EFlags &= ~0x100;
            InterlockedExchange(&g_sw_pending, 0);
            if (g_sw_active) {
                if (g_hw_hits >= 8) InterlockedExchange(&g_sw_active, 0);
                else *g_sw_addr = 0xCC;                /* 抓够就停，减少干扰 */
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        if (!g_hw_active) return EXCEPTION_CONTINUE_SEARCH;
        LONG n = InterlockedIncrement(&g_hw_hits);
        if (n <= 16) {
            uint64_t rip = (uint64_t)ep->ContextRecord->Rip;
            uint64_t rva = (rip >= g_mod_base && rip < g_mod_base + g_mod_size) ? rip - g_mod_base : 0;
            g_hw_rips[n - 1] = rip;
            g_hw_rvas[n - 1] = rva;
            g_hw_tids[n - 1] = GetCurrentThreadId();
            g_hw_rsp[n - 1] = (uint64_t)ep->ContextRecord->Rsp;   /* 用于回溯调用方 */
            g_hw_regs[n - 1][0] = (uint64_t)ep->ContextRecord->Rcx;
            g_hw_regs[n - 1][1] = (uint64_t)ep->ContextRecord->Rdx;
            g_hw_regs[n - 1][2] = (uint64_t)ep->ContextRecord->Rsi;
            g_hw_regs[n - 1][3] = (uint64_t)ep->ContextRecord->Rdi;
        }
        ep->ContextRecord->Dr0 = 0;
        ep->ContextRecord->Dr7 = 0;
        ep->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return EXCEPTION_CONTINUE_SEARCH;
    if (!g_bp_page) return EXCEPTION_CONTINUE_SEARCH;   /* 从未挂过断点 */
    ULONG_PTR kind = ep->ExceptionRecord->ExceptionInformation[0];
    ULONG_PTR addr = ep->ExceptionRecord->ExceptionInformation[1];
    if (kind != 1) return EXCEPTION_CONTINUE_SEARCH;                 /* 只看写 */
    if (addr < (ULONG_PTR)g_bp_page || addr >= (ULONG_PTR)g_bp_page + 0x1000)
        return EXCEPTION_CONTINUE_SEARCH;

    /* 关键：只要页是我们在盯，就无条件放行这次写。
       绝不能因为 armed==0 就 SEARCH —— 那会让异常冒到游戏里直接崩进程。 */
    InterlockedExchange(&g_bp_armed, 0);
    DWORD old;
    VirtualProtect(g_bp_page, 0x1000, g_bp_oldprot, &old);

    InterlockedIncrement(&g_bp_total);
    if ((uint64_t)addr == g_bp_watch) {
        LONG n = InterlockedIncrement(&g_bp_hits);
        if (n <= 16) {
            g_bp_rips[n - 1] = (uint64_t)ep->ContextRecord->Rip;
            g_bp_addrs[n - 1] = (uint64_t)addr;
        }
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD WINAPI bp_watchdog(LPVOID p)
{
    (void)p;
    /* 页内每帧都有别的字段被写（时间戳等），每次都会解除只读。
       必须几乎零延迟地重上锁，否则目标写入正好落在可写窗口里被漏掉。
       用 Sleep(0) 让出时间片后立刻重锁，把只读占空比拉到接近 100%。 */
    ULONGLONG t0 = GetTickCount64();
    while (g_bp_active && g_bp_hits < 8 && (GetTickCount64() - t0) < 400) {
        if (!g_bp_armed && g_bp_page) {
            DWORD old;
            if (g_bp_active && VirtualProtect(g_bp_page, 0x1000, PAGE_READONLY, &old)) {
                InterlockedExchange(&g_bp_armed, 1);
            }
        }
        Sleep(0);
    }
    DWORD old;
    if (g_bp_page) VirtualProtect(g_bp_page, 0x1000, g_bp_oldprot, &old);
    InterlockedExchange(&g_bp_armed, 0);
    return 0;
}

static void mod_info(void)
{
    HMODULE h = GetModuleHandleA(NULL);
    g_mod_base = (uint64_t)(uintptr_t)h;
    char *p = (char *)h;
    if (p && p[0] == 'M' && p[1] == 'Z') {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)h;
        IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((char *)h + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) g_mod_size = nt->OptionalHeader.SizeOfImage;
    }
}

/* ================= 硬件写断点（DR0）=================
 * 页保护断点会被"页内其他字段每帧被写"打乱（实测噪声页 0/6，安静页 6/6），
 * 这里改用调试寄存器：精确到 4 字节，只在我们关心的地址上触发。
 * 需要给进程内所有线程设置 DR0/DR7，用完必须清除，否则线程会一直单步。
 */
#include <tlhelp32.h>
#include <intrin.h>

static volatile LONG g_hw_exec = 0;      /* 0=写断点(4字节)  1=执行断点 */

static void hw_apply(HANDLE th, int enable, uint64_t addr)
{
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(th, &ctx)) return;
    if (enable) {
        ctx.Dr0 = addr;
        /* L0=1；RW0: 00=执行 01=写；LEN0: 00=1字节 11=4字节 */
        ctx.Dr7 = g_hw_exec ? 0x00000001 : 0x000D0001;
        ctx.Dr6 = 0;
    } else {
        ctx.Dr0 = 0;
        ctx.Dr7 = 0;
        ctx.Dr6 = 0;
    }
    SetThreadContext(th, &ctx);
}

static void hw_set_all(int enable, uint64_t addr)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId();
    DWORD self = GetCurrentThreadId();          /* 绝不能挂起自己：SuspendThread 会死锁 */
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (te.th32ThreadID == self) continue;
            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                   THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
            if (!th) continue;
            SuspendThread(th);
            hw_apply(th, enable, addr);
            ResumeThread(th);
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static DWORD WINAPI hw_rearm(LPVOID p)
{
    (void)p;
    ULONGLONG t0 = GetTickCount64();
    while (g_hw_active && g_hw_hits < 8 && (GetTickCount64() - t0) < 60000) {
        Sleep(15);
        if (g_hw_active) hw_set_all(1, g_hw_addr);
    }
    hw_set_all(0, 0);
    InterlockedExchange(&g_hw_active, 0);
    return 0;
}

/* ================= 调用点跳板 hook（捕获 rsi，不碰调试寄存器） =================
 * 把调用方那条 `call set_ammo` 换成 `jmp 跳板`；跳板先存 rsi/rcx/rdx，
 * 再自己 call 真正的 set_ammo，最后 jmp 回原返回地址。栈完全平衡。
 */
static unsigned char *g_hk_page = NULL;    /* 跳板所在页 */
static uint64_t      *g_hk_slot = NULL;    /* [0]=rsi [1]=rcx [2]=rdx [3]=命中数 */
static unsigned char *g_hk_site = NULL;
static unsigned char  g_hk_orig[8];
static volatile LONG  g_hk_active = 0;
static unsigned int  g_hk_patch = 8;

/* ================= 值冻结（进程内 1ms 循环写入） ================= */
typedef struct {
    uint64_t addr;
    uint32_t size;
    uint32_t interval;
    unsigned char data[8];
    volatile LONG on;
} lock_t;

static lock_t  g_locks[8];
static volatile LONG g_lock_run = 0;
static HANDLE  g_lock_thread = NULL;

static DWORD WINAPI lock_worker(LPVOID p)
{
    (void)p;
    while (g_lock_run) {
        for (int i = 0; i < 8; i++) {
            if (g_locks[i].on) {
                SIZE_T w = 0;
                WriteProcessMemory(GetCurrentProcess(), (LPVOID)(uintptr_t)g_locks[i].addr,
                                   g_locks[i].data, g_locks[i].size, &w);
            }
        }
        Sleep(1);
    }
    return 0;
}

/* ================= 进程内飞行（帧级，1kHz） =================
 * 外部 5-46Hz 写 C+0x60 全部输给 pmove：每帧末引擎都会把 origin 写回。
 * 把循环搬进进程后可以 1ms 级重写，并在飞行期间把竖直速度清零，
 * 使 pmove 每帧读到的输入恒为我们的目标高度。
 *
 * 布局（实测）：g_entities[0].+0x178 -> client 块 C；
 *   C+0x58 原点三元组（x/y/z），C+0x64 速度三元组。
 *   pm_type 推测在 C+0x48（ps 起始 0x44，commandTime 在 +0x44），mode=1 时使用。
 *
 * 热键在进程内读取（UIPI 只拦外部注入，不拦本进程 GetAsyncKeyState）。
 */
#define G_ENT_RVA    0xF7C0E88ULL
#define O_G_PTR178   0x178
#define O_G_HEALTH   0x1E0
#define C_CMDTIME    0x44
#define C_PMTYPE     0x48
#define C_ORIG       0x58
#define C_ORIG_Z     (C_ORIG + 8)
#define C_VEL_Z      (C_ORIG + 0x14)
#define FLY_RANGE    3000.0f
#define FLY_BASE_SPD 160.0f

typedef struct {
    volatile LONG on;
    volatile LONG run;
    volatile LONG mode;        /* 0=钉高度  1=noclip(pm_type=1) */
    volatile LONG scale10;     /* 20..100 即 x2..x10 */
    volatile LONG vk_up, vk_down, vk_toggle, vk_speed;
    volatile LONG ticks;
    volatile LONG hp;
    volatile LONG err;         /* 0=ok 1=无玩家 2=死亡 */
    volatile float z, tz, bz;
    volatile LONG nudge;       /* 0=空闲 1=请求 2=已处理 */
    volatile float nudge_dz;
    volatile unsigned long long client;
} fly_state;

static fly_state g_fly;
static HANDLE g_fly_thread = NULL;

typedef UINT (WINAPI *pfn_tbp_t)(UINT);
static pfn_tbp_t g_tbp = NULL;

static void fly_hires(int on)
{
    if (!g_tbp) {
        HMODULE h = LoadLibraryA("winmm.dll");
        if (h) g_tbp = (pfn_tbp_t)(void *)GetProcAddress(h, "timeBeginPeriod");
    }
    if (g_tbp) g_tbp(on ? 1 : 0);
}

static void fly_restore_pmtype(uint64_t c, int *active, LONG *orig)
{
    if (*active && c) {
        LONG cur = *(LONG *)(uintptr_t)(c + C_PMTYPE);
        if (cur == 1 && *orig >= 0) {
            SIZE_T w = 0;
            WriteProcessMemory(GetCurrentProcess(), (LPVOID)(uintptr_t)(c + C_PMTYPE),
                               orig, 4, &w);
        }
    }
    *active = 0;
}

static DWORD WINAPI fly_worker(LPVOID p)
{
    (void)p;
    uint64_t base = (uint64_t)(uintptr_t)GetModuleHandleA(NULL);
    float base_z = 0.0f, target_z = 0.0f;
    int have = 0, prev_tog = 0, prev_spd = 0, noclip_active = 0;
    LONG pmt_orig = -1;
    uint64_t cached_c = 0;
    ULONGLONG last_t = GetTickCount64(), last_resolve = 0;

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    int hires = 0;

    while (g_fly.run) {
        ULONGLONG now = GetTickCount64();

        /* 开关关闭时也解析玩家：FLY_GET 必须能反映真实状态（早先只在开启后解析，
           导致外部等待器永远看不到玩家）。 */
        if (now - last_resolve >= (g_fly.on ? 200 : 500) || !cached_c) {
            last_resolve = now;
            uint64_t g = *(uint64_t *)(uintptr_t)(base + G_ENT_RVA);
            uint64_t c = 0;
            int hp = 0;
            if (g) {
                c = *(uint64_t *)(uintptr_t)(g + O_G_PTR178);
                hp = *(int *)(uintptr_t)(g + O_G_HEALTH);
            }
            if (c < 0x10000ULL || c > 0x7FFFFFFFFFFFULL) c = 0;
            if (c != cached_c) {
                fly_restore_pmtype(cached_c, &noclip_active, &pmt_orig);
                cached_c = c;
                have = 0;
                g_fly.client = c;
            }
            g_fly.hp = hp;
            if (!c) g_fly.err = 1;
            else if (hp <= 0) {
                g_fly.err = 2;
                if (g_fly.on) InterlockedExchange(&g_fly.on, 0);
            } else g_fly.err = 0;
        }

        LONG scale = g_fly.scale10;
        if (scale < 20) scale = 20;
        if (scale > 100) scale = 100;

        int tog = (GetAsyncKeyState((int)g_fly.vk_toggle) & 0x8000) != 0;
        int spd = (GetAsyncKeyState((int)g_fly.vk_speed) & 0x8000) != 0;
        if (tog && !prev_tog) {
            LONG nv = g_fly.on ? 0 : 1;
            InterlockedExchange(&g_fly.on, nv);
            have = 0;
            logf_("fly 开关 -> %d", nv);
        }
        prev_tog = tog;
        if (spd && !prev_spd) {
            LONG s = (scale >= 100) ? 20 : scale + 20;
            g_fly.scale10 = s;
            logf_("fly 速度 x%.0f", s / 10.0);
        }
        prev_spd = spd;

        if (!g_fly.on) {
            if (noclip_active) fly_restore_pmtype(cached_c, &noclip_active, &pmt_orig);
            if (hires) { fly_hires(0); hires = 0; }
            have = 0;
            Sleep(20);
            continue;
        }
        if (!hires) { fly_hires(1); hires = 1; }
        if (!cached_c) { Sleep(20); continue; }

        float st[6] = {0, 0, 0, 0, 0, 0};
        SIZE_T rd = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(uintptr_t)(cached_c + C_ORIG),
                               st, 24, &rd) || rd != 24) { Sleep(5); continue; }
        float z = st[2], vx = st[3], vy = st[4];
        if (!(z > -1.0e7f && z < 1.0e7f)) { Sleep(5); continue; }

        int up = (GetAsyncKeyState((int)g_fly.vk_up) & 0x8000) != 0;
        int dn = (GetAsyncKeyState((int)g_fly.vk_down) & 0x8000) != 0;

        if (!have) { base_z = target_z = z; have = 1; last_t = now; }

        float dt = (float)(now - last_t) / 1000.0f;
        last_t = now;
        if (dt < 0.0f) dt = 0.0f;
        if (dt > 0.05f) dt = 0.05f;

        float speed = FLY_BASE_SPD * (float)scale / 10.0f;
        if (up) target_z += speed * dt;
        else if (dn) target_z -= speed * dt;

        if (g_fly.nudge == 1) {
            target_z += g_fly.nudge_dz;
            g_fly.nudge = 2;
        }
        if (target_z > base_z + FLY_RANGE) target_z = base_z + FLY_RANGE;
        if (target_z < base_z - FLY_RANGE) target_z = base_z - FLY_RANGE;

        /* 水平加速：有输入方向时把引擎自己的水平速度放大到 160×倍率，
           额外位移是前馈量（只依赖引擎速度，不依赖我们写过的值），不会形成放大反馈环。 */
        float dx = 0.0f, dy = 0.0f;
        float sp2 = vx * vx + vy * vy;
        if (sp2 > 400.0f) {                       /* 速度 > 20 u/s 说明有移动输入 */
            float cur = sqrtf(sp2);
            float want = FLY_BASE_SPD * (float)scale / 10.0f;
            float k = (want / cur - 1.0f) * dt;
            dx = vx * k;
            dy = vy * k;
            if (dx > 8.0f) dx = 8.0f; else if (dx < -8.0f) dx = -8.0f;
            if (dy > 8.0f) dy = 8.0f; else if (dy < -8.0f) dy = -8.0f;
        }

        SIZE_T wr = 0;
        if (g_fly.mode == 1) {
            if (!noclip_active) {
                if (pmt_orig < 0) pmt_orig = *(LONG *)(uintptr_t)(cached_c + C_PMTYPE);
                LONG v = 1;
                WriteProcessMemory(GetCurrentProcess(), (LPVOID)(uintptr_t)(cached_c + C_PMTYPE),
                                   &v, 4, &wr);
                noclip_active = 1;
            } else if ((g_fly.ticks & 0x7F) == 0) {
                LONG cur = *(LONG *)(uintptr_t)(cached_c + C_PMTYPE);
                if (cur != 1) {
                    LONG v = 1;
                    WriteProcessMemory(GetCurrentProcess(), (LPVOID)(uintptr_t)(cached_c + C_PMTYPE),
                                       &v, 4, &wr);
                }
            }
        }
        float vz0 = 0.0f;
        if (dx != 0.0f || dy != 0.0f) {
            float nx = st[0] + dx;
            float ny = st[1] + dy;
            if (dx != 0.0f)
                WriteProcessMemory(GetCurrentProcess(), (LPVOID)(uintptr_t)(cached_c + C_ORIG),
                                   &nx, 4, &wr);
            if (dy != 0.0f)
                WriteProcessMemory(GetCurrentProcess(), (LPVOID)(uintptr_t)(cached_c + C_ORIG + 4),
                                   &ny, 4, &wr);
        }
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)(uintptr_t)(cached_c + C_VEL_Z),
                           &vz0, 4, &wr);
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)(uintptr_t)(cached_c + C_ORIG_Z),
                           &target_z, 4, &wr);

        g_fly.z = z;
        g_fly.bz = base_z;
        g_fly.tz = target_z;
        InterlockedIncrement(&g_fly.ticks);

        Sleep(1);
    }

    fly_restore_pmtype(cached_c, &noclip_active, &pmt_orig);
    fly_hires(0);
    return 0;
}

static void fly_ensure(void)
{
    if (!g_fly.run) {
        InterlockedExchange(&g_fly.run, 1);
        g_fly_thread = CreateThread(NULL, 0, fly_worker, NULL, 0, NULL);
    }
}

/* ================= 准星吸附（进程内 SendInput 相对鼠标 + 闭环自校准） =================
 * 相机姿态：模块静态 base+0xF224F5C  eye(3)@+0, look(3)@+12（每帧更新）
 * 目标：g_entities[slot]  origin@+0x24  hp@+0x1E0  class@+0x180，team=class+0x24
 * 流程：按住吸附键 -> 按角度选最近目标 -> 注入相对鼠标 -> 读姿态角度变化闭环；
 *       首次使用时用 +pulse 计数脉冲标定 counts/度 与方向（灵敏度/ADS 倍率都能吸收）。
 */
#define POS_RVA     0xF224F5CULL
#define ENT_STRIDE  0x7D0
#define ENT_COUNT   2000
#define O_E_ORIG    0x24
#define O_E_HP      0x1E0
#define O_E_CLASS   0x180
#define O_E_ACTOR   0x198
#define O_ACT_HEAD  0x19C    /* actor 内世界坐标头部位置（随蹲/趴变化） */
#define O_C_TEAM    0x24
#define O_C_PITCH   0x434
#define O_C_YAW     0x438
#define O_C_ADS     0x5B0
#define AIM_MAX     64
#define AIM_D2R     0.017453292519943295f
#define AIM_R2D     57.29577951308232f

typedef struct {
    volatile LONG on;
    volatile LONG run;
    volatile LONG hold;        /* 1=按住 vk 才生效 */
    volatile LONG vk;          /* 默认 VK_RBUTTON */
    volatile LONG cone10;      /* 角度锥（度×10） */
    volatile LONG max_dist;    /* 游戏单位（英寸） */
    volatile LONG team_excl;   /* 队友 team 值，默认 7 */
    volatile float head_dz;    /* 头部相对脚底高度 */
    volatile LONG ticks;
    volatile LONG has_tgt;
    volatile LONG slot;
    volatile LONG hp;
    volatile float dist;
    volatile float err_yaw, err_pitch;
    volatile float gain_x, gain_y;   /* counts/度（带符号） */
    volatile LONG calib;
    volatile LONG err;
} aim_state;

static aim_state g_aim = { 0, 0, 1, 0x02, 80, 3000, 7, 62.0f, 0, 0, 0, 0, 0.0f,
                           0.0f, 0.0f, 0.0f, 0.0f, 0, 0 };
static HANDLE g_aim_thread = NULL;
static float g_gain_x[2], g_gain_y[2];
static int g_gain_ok[2];
static volatile LONG g_aim_interval = 12;   /* 修正指令间隔 ms */
static volatile LONG g_aim_strength = 60;   /* 力度 %（0.6 比例） */
static volatile LONG g_aim_smooth = 0;      /* 瞄准点平滑 %，0=不平滑 */
static volatile LONG g_aim_lead = 40;       /* 头部速度提前量 ms */
static volatile LONG g_chain_on = 1;        /* 连吸：目标死亡后就近换目标 */
static volatile LONG g_chain_radius = 600;  /* 连吸搜索半径（游戏单位/英寸） */

/* ===== 阵营自动识别：开局采样最近 3 个 NPC 的 team 作为友军 ===== */
static volatile LONG g_team_auto = 1;              /* 1=自动识别友军 */
static volatile LONG g_team_extra_mask = 1u << 2;  /* 额外排除位（默认 team 2 幽灵） */
static volatile LONG g_team_friendly = -1;         /* 锁定的友军 team，-1=未知 */
static volatile LONG g_team_state = 0;             /* 0空闲 1采样中 2已锁定 3失败 */
static volatile LONG g_team_samples = 0;
static volatile LONG g_team_ticks = 0;
static volatile LONG g_team_resample = 0;
static volatile LONG g_team_run = 0;
static HANDLE g_team_thread = NULL;

static int team_skip(uint32_t team, LONG manual_excl)
{
    if (team >= 32u) return 1;
    if ((LONG)team == manual_excl) return 1;
    if ((g_team_extra_mask >> team) & 1u) return 1;
    if (g_team_auto && g_team_friendly >= 0 && (LONG)team == g_team_friendly) return 1;
    return 0;
}

typedef struct {
    int slot;
    uint32_t team;
    int hp;
    uint64_t cls;
    uint64_t actor;
    float x, y, z;
    float hx, hy, hz;
    float vx, vy, vz;
    float shx, shy, shz;
    ULONGLONG ht;
    int has_head;
} aim_tgt;

static float aim_wrap180(float a)
{
    while (a > 180.0f) a -= 360.0f;
    while (a < -180.0f) a += 360.0f;
    return a;
}

static void aim_send(int dx, int dy)
{
    INPUT in;
    memset(&in, 0, sizeof(in));
    in.type = INPUT_MOUSE;
    in.mi.dx = dx;
    in.mi.dy = dy;
    in.mi.dwFlags = MOUSEEVENTF_MOVE;
    SendInput(1, &in, sizeof(INPUT));
}

static void aim_button(int btn, int down)
{
    INPUT in;
    memset(&in, 0, sizeof(in));
    in.type = INPUT_MOUSE;
    if (btn == 2)
        in.mi.dwFlags = down ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
    else
        in.mi.dwFlags = down ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
    SendInput(1, &in, sizeof(INPUT));
}

static int aim_foreground_ok(void)
{
    HWND fg = GetForegroundWindow();
    DWORD pid = 0;
    if (!fg) return 0;
    GetWindowThreadProcessId(fg, &pid);
    return pid == GetCurrentProcessId();
}

static DWORD WINAPI aim_worker(LPVOID p)
{
    (void)p;
    uint64_t base = (uint64_t)(uintptr_t)GetModuleHandleA(NULL);
    HANDLE self = GetCurrentProcess();
    unsigned char *tbl = (unsigned char *)VirtualAlloc(NULL, (SIZE_T)ENT_COUNT * ENT_STRIDE,
                                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    aim_tgt tg[AIM_MAX];
    int ntg = 0;
    int cal = 0;
    int cal_ads = 0;
    int ads_prev = -1;
    int pulse = 24;
    float yaw0 = 0.0f, pitch0 = 0.0f, yaw1 = 0.0f, pitch1 = 0.0f;
    ULONGLONG cal_t = 0, last_full = 0, last_pos = 0, ads_t = 0, last_cmd = 0;
    int f8_prev = 0;
    int chain_slot = -1;
    ULONGLONG chain_t = 0, last_seen = 0;
    float last_tx = 0.0f, last_ty = 0.0f, last_tz = 0.0f;
    SIZE_T rd = 0;

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);
    while (g_aim.run) {
        Sleep(2);
        if (!g_aim.on) { cal = 0; continue; }

        uint64_t g = *(uint64_t *)(uintptr_t)(base + G_ENT_RVA);
        if (!g || !tbl) { Sleep(10); continue; }
        int php = *(int *)(uintptr_t)(g + O_G_HEALTH);
        if (php <= 0) {
            cal = 0;
            g_aim.has_tgt = 0;
            Sleep(50);
            continue;
        }
        if (g_aim.hold && !(GetAsyncKeyState((int)g_aim.vk) & 0x8000)) {
            cal = 0;
            g_aim.has_tgt = 0;
            chain_slot = -1;
            last_seen = 0;
            continue;
        }
        if (!aim_foreground_ok()) { cal = 0; continue; }
        int f8 = (GetAsyncKeyState(0x77) & 0x8000) ? 1 : 0;
        if (f8 && !f8_prev) {
            g_gain_ok[0] = 0;
            g_gain_ok[1] = 0;
            cal = 0;
            logf_("aim 手动重标定（F8）");
        }
        f8_prev = f8;

        float *cam = (float *)(uintptr_t)(base + POS_RVA);
        float ex = cam[0], ey = cam[1], ez = cam[2];
        uint64_t cblk = 0;
        SIZE_T crd = 0;
        if (!ReadProcessMemory(self, (LPCVOID)(uintptr_t)(g + O_G_PTR178),
                               &cblk, 8, &crd) || crd != 8)
            cblk = 0;
        float yaw = 0.0f, pitch = 0.0f;
        int ads_state = 0, got = 0;
        if (cblk) {
            float cp = 0.0f, cyaw = 0.0f, cads = 0.0f;
            SIZE_T r1 = 0, r2 = 0, r3 = 0;
            ReadProcessMemory(self, (LPCVOID)(uintptr_t)(cblk + O_C_PITCH), &cp, 4, &r1);
            ReadProcessMemory(self, (LPCVOID)(uintptr_t)(cblk + O_C_YAW), &cyaw, 4, &r2);
            ReadProcessMemory(self, (LPCVOID)(uintptr_t)(cblk + O_C_ADS), &cads, 4, &r3);
            if (r1 == 4 && r2 == 4 && fabsf(cyaw) < 3600.0f && fabsf(cp) < 200.0f) {
                yaw = aim_wrap180(cyaw);
                pitch = cp;
                got = 1;
            }
            if (r3 == 4) ads_state = (cads > 0.5f) ? 1 : 0;
        }
        if (!got) {
            float fx = cam[3] - ex, fy = cam[4] - ey, fz = cam[5] - ez;
            float fl = sqrtf(fx * fx + fy * fy + fz * fz);
            if (!(fl > 1.0e-3f)) continue;
            yaw = atan2f(fy, fx) * AIM_R2D;
            pitch = asinf(-fz / fl) * AIM_R2D;
        } else {
            /* 连射后坐力只体现在渲染相机：输入角 + 超出呼吸幅度的偏移 */
            float fx = cam[3] - ex, fy = cam[4] - ey, fz = cam[5] - ez;
            float fl = sqrtf(fx * fx + fy * fy + fz * fz);
            if (fl > 1.0e-3f) {
                float dpy = aim_wrap180(atan2f(fy, fx) * AIM_R2D - yaw);
                float dpp = asinf(-fz / fl) * AIM_R2D - pitch;
                if (dpp > 0.8f) pitch += dpp - 0.8f;
                else if (dpp < -0.8f) pitch += dpp + 0.8f;
                if (dpy > 0.8f) yaw += dpy - 0.8f;
                else if (dpy < -0.8f) yaw += dpy + 0.8f;
            }
        }

        ULONGLONG now = GetTickCount64();
        float maxd = (float)g_aim.max_dist;
        if (ads_state != ads_prev) { ads_prev = ads_state; ads_t = now; }

        if (now - last_full >= 400 || ntg == 0) {
            last_full = now;
            if (ReadProcessMemory(self, (LPCVOID)(uintptr_t)g, tbl,
                                  (SIZE_T)ENT_COUNT * ENT_STRIDE, &rd) &&
                rd == (SIZE_T)ENT_COUNT * ENT_STRIDE) {
                ntg = 0;
                for (int i = 1; i < ENT_COUNT && ntg < AIM_MAX; i++) {
                    unsigned char *e = tbl + (SIZE_T)i * ENT_STRIDE;
                    int thp = *(int *)(e + O_E_HP);
                    uint64_t cls = *(uint64_t *)(e + O_E_CLASS);
                    float tx = *(float *)(e + O_E_ORIG);
                    float ty = *(float *)(e + O_E_ORIG + 4);
                    float tz = *(float *)(e + O_E_ORIG + 8);
                    if (thp <= 0 || thp > 10000) continue;
                    if (cls < base + 0x1000 || cls >= base + 0x20000000ULL) continue;
                    if (!(fabsf(tx) <= 1.0e6f) || !(fabsf(ty) <= 1.0e6f) ||
                        !(fabsf(tz) <= 1.0e6f)) continue;
                    float ddx = tx - ex, ddy = ty - ey, ddz = tz - ez;
                    float d = sqrtf(ddx * ddx + ddy * ddy + ddz * ddz);
                    if (d < 3.0f || d > maxd) continue;
                    uint32_t team = 0xFFFFFFFFu;
                    SIZE_T cr = 0;
                    if (!ReadProcessMemory(self, (LPCVOID)(uintptr_t)(cls + O_C_TEAM),
                                           &team, 4, &cr) || cr != 4) continue;
                    if (team_skip(team, g_aim.team_excl)) continue;
                    tg[ntg].slot = i;
                    tg[ntg].team = team;
                    tg[ntg].hp = thp;
                    tg[ntg].cls = cls;
                    tg[ntg].x = tx; tg[ntg].y = ty; tg[ntg].z = tz;
                    tg[ntg].has_head = 0;
                    tg[ntg].vx = tg[ntg].vy = tg[ntg].vz = 0.0f;
                    tg[ntg].shx = tx; tg[ntg].shy = ty; tg[ntg].shz = tz + g_aim.head_dz;
                    tg[ntg].ht = 0;
                    tg[ntg].actor = *(uint64_t *)(e + O_E_ACTOR);
                    if (tg[ntg].actor) {
                        float hb[3];
                        SIZE_T hr = 0;
                        if (ReadProcessMemory(self,
                                (LPCVOID)(uintptr_t)(tg[ntg].actor + O_ACT_HEAD),
                                hb, 12, &hr) && hr == 12 &&
                            fabsf(hb[0] - tx) < 100.0f && fabsf(hb[1] - ty) < 100.0f &&
                            (hb[2] - tz) > -20.0f && (hb[2] - tz) < 130.0f) {
                            tg[ntg].hx = hb[0]; tg[ntg].hy = hb[1]; tg[ntg].hz = hb[2];
                            tg[ntg].shx = hb[0]; tg[ntg].shy = hb[1]; tg[ntg].shz = hb[2];
                            tg[ntg].has_head = 1;
                        }
                    }
                    ntg++;
                }
            }
        }

        if (now - last_pos >= 8) {
            last_pos = now;
            int n2 = 0;
            for (int i = 0; i < ntg; i++) {
                unsigned char tmp[0x1E8];
                if (!ReadProcessMemory(self,
                        (LPCVOID)(uintptr_t)(g + (SIZE_T)tg[i].slot * ENT_STRIDE),
                        tmp, sizeof(tmp), &rd) || rd != sizeof(tmp)) continue;
                int thp = *(int *)(tmp + O_E_HP);
                uint64_t cls = *(uint64_t *)(tmp + O_E_CLASS);
                if (thp <= 0 || thp > 10000) continue;
                if (cls != tg[i].cls) { last_full = 0; continue; }
                tg[i].hp = thp;
                tg[i].x = *(float *)(tmp + O_E_ORIG);
                tg[i].y = *(float *)(tmp + O_E_ORIG + 4);
                tg[i].z = *(float *)(tmp + O_E_ORIG + 8);
                if (tg[i].actor) {
                    float hb[3];
                    SIZE_T hr = 0;
                    if (ReadProcessMemory(self,
                            (LPCVOID)(uintptr_t)(tg[i].actor + O_ACT_HEAD),
                            hb, 12, &hr) && hr == 12 &&
                        fabsf(hb[0] - tg[i].x) < 100.0f && fabsf(hb[1] - tg[i].y) < 100.0f &&
                        (hb[2] - tg[i].z) > -20.0f && (hb[2] - tg[i].z) < 130.0f) {
                        if (tg[i].has_head && tg[i].ht && now > tg[i].ht &&
                            now - tg[i].ht < 250) {
                            float dt = (float)(now - tg[i].ht) / 1000.0f;
                            float nvx = (hb[0] - tg[i].hx) / dt;
                            float nvy = (hb[1] - tg[i].hy) / dt;
                            float nvz = (hb[2] - tg[i].hz) / dt;
                            if (nvx > 3000.0f) nvx = 3000.0f;
                            else if (nvx < -3000.0f) nvx = -3000.0f;
                            if (nvy > 3000.0f) nvy = 3000.0f;
                            else if (nvy < -3000.0f) nvy = -3000.0f;
                            if (nvz > 3000.0f) nvz = 3000.0f;
                            else if (nvz < -3000.0f) nvz = -3000.0f;
                            tg[i].vx = 0.6f * tg[i].vx + 0.4f * nvx;
                            tg[i].vy = 0.6f * tg[i].vy + 0.4f * nvy;
                            tg[i].vz = 0.6f * tg[i].vz + 0.4f * nvz;
                        } else {
                            tg[i].vx = tg[i].vy = tg[i].vz = 0.0f;
                        }
                        float sa = 1.0f - (float)g_aim_smooth * 0.01f;
                        if (sa < 0.1f) sa = 0.1f;
                        if (!tg[i].has_head) {
                            tg[i].shx = hb[0]; tg[i].shy = hb[1]; tg[i].shz = hb[2];
                        } else {
                            tg[i].shx += sa * (hb[0] - tg[i].shx);
                            tg[i].shy += sa * (hb[1] - tg[i].shy);
                            tg[i].shz += sa * (hb[2] - tg[i].shz);
                        }
                        tg[i].hx = hb[0]; tg[i].hy = hb[1]; tg[i].hz = hb[2];
                        tg[i].has_head = 1;
                        tg[i].ht = now;
                    } else {
                        tg[i].has_head = 0;
                    }
                } else {
                    tg[i].has_head = 0;
                }
                tg[n2++] = tg[i];
            }
            ntg = n2;
        }

        float head = g_aim.head_dz;
        float cone = (float)g_aim.cone10 / 10.0f;
        int bi = -1;
        float bs = 1.0e9f, bdy = 0.0f, bdp = 0.0f, bd = 0.0f;
        float lead_s = (float)g_aim_lead * 0.001f;

        /* 连吸：当前目标消失（死亡/出表）后，按它最后位置找最近的活敌 */
        int cur_present = 0;
        if (g_aim.slot >= 0) {
            for (int i = 0; i < ntg; i++) {
                if (tg[i].slot == g_aim.slot) {
                    cur_present = 1;
                    last_tx = tg[i].x; last_ty = tg[i].y; last_tz = tg[i].z;
                    last_seen = now;
                    break;
                }
            }
        }
        if (g_chain_on && !cur_present && last_seen && now - last_seen < 3000) {
            float bestd = (float)g_chain_radius * (float)g_chain_radius;
            int bj = -1;
            for (int i = 0; i < ntg; i++) {
                float dx = tg[i].x - last_tx, dy = tg[i].y - last_ty, dz = tg[i].z - last_tz;
                float d2 = dx * dx + dy * dy + dz * dz;
                if (d2 > 1.0f && d2 < bestd) { bestd = d2; bj = i; }
            }
            if (bj >= 0) { chain_slot = tg[bj].slot; chain_t = now; }
        }
        int chain_idx = -1;
        if (g_chain_on && chain_slot >= 0 && now - chain_t <= 1500) {
            for (int i = 0; i < ntg; i++)
                if (tg[i].slot == chain_slot) { chain_idx = i; break; }
            if (chain_idx < 0) chain_slot = -1;
        } else if (chain_slot >= 0) {
            chain_slot = -1;
        }

        for (int i = 0; i < ntg; i++) {
            float tx = tg[i].has_head ? (tg[i].shx + tg[i].vx * lead_s) : tg[i].x;
            float ty = tg[i].has_head ? (tg[i].shy + tg[i].vy * lead_s) : tg[i].y;
            float tz = tg[i].has_head ? (tg[i].shz + tg[i].vz * lead_s) : (tg[i].z + head);
            float dx = tx - ex, dy = ty - ey;
            float dh = sqrtf(dx * dx + dy * dy);
            if (dh < 1.0f) continue;
            float tyaw = atan2f(dy, dx) * AIM_R2D;
            /* 姿态 pitch = asin(-fz)：正=向下（实测：鼠标下移->pitch 增大->画面内容上移）。
               目标仰角取反后再和姿态 pitch 比较，符号才一致。 */
            float tpitch = -atan2f(tz - ez, dh) * AIM_R2D;
            float dyaw = aim_wrap180(tyaw - yaw);
            float dp = tpitch - pitch;
            float sc = sqrtf(dyaw * dyaw + dp * dp);
            if (i == chain_idx) {
                bi = i; bdy = dyaw; bdp = dp; bd = dh;
                if (sc <= cone) chain_slot = -1;
                break;
            }
            if (tg[i].slot == g_aim.slot) sc -= 0.7f;
            if (sc <= cone && sc < bs) {
                bs = sc; bi = i; bdy = dyaw; bdp = dp; bd = dh;
            }
        }
        int snap_req = (bi >= 0 && tg[bi].slot != g_aim.slot) ? 1 : 0;
        g_aim.has_tgt = (bi >= 0) ? 1 : 0;
        if (bi >= 0) {
            g_aim.slot = tg[bi].slot;
            g_aim.hp = tg[bi].hp;
            g_aim.dist = bd;
            g_aim.err_yaw = bdy;
            g_aim.err_pitch = bdp;
        }

        if (cal >= 1 && cal <= 5 && ads_state != cal_ads) cal = 0;
        if (cal == 0) {
            if (g_gain_ok[ads_state]) {
                g_aim.gain_x = g_gain_x[ads_state];
                g_aim.gain_y = g_gain_y[ads_state];
                g_aim.calib = 1;
                cal_ads = ads_state;
                cal = 6;
            } else if (now - ads_t < 250) {
                /* 等 ADS 标志稳定，避免把腰射增益标定到开镜 */
            } else {
                cal = 1;
                cal_ads = ads_state;
                pulse = 16;
                yaw0 = yaw;
                pitch0 = pitch;
                cal_t = now;
            }
        } else if (cal == 1) {
            /* 静默 100ms 后才发脉冲：玩家在动/后坐时标定必偏 */
            if (now - cal_t >= 100) {
                if (fabsf(aim_wrap180(yaw - yaw0)) > 0.05f || fabsf(pitch - pitch0) > 0.05f) {
                    yaw0 = yaw; pitch0 = pitch; cal_t = now;
                } else {
                    aim_send(pulse, 0);
                    cal = 2;
                    cal_t = now;
                }
            }
        } else if (cal == 2) {
            if (now - cal_t >= 60) {
                yaw1 = aim_wrap180(yaw - yaw0);
                aim_send(-pulse, 0);
                cal = 3;
                cal_t = now;
            }
        } else if (cal == 3) {
            if (now - cal_t >= 60) {
                float d2 = aim_wrap180(yaw - yaw0) - yaw1;
                float ret = yaw1 + d2;
                if (fabsf(yaw1) < 0.05f || fabsf(yaw1) > 6.0f ||
                    fabsf(ret) > 0.15f + 0.35f * fabsf(yaw1)) {
                    logf_("aim 标定失败(yaw d1=%.3f ret=%.3f)", yaw1, ret);
                    cal = 0;
                    Sleep(400);
                } else {
                    g_aim.gain_x = (float)pulse / yaw1;
                    aim_send(0, pulse);
                    cal = 4;
                    cal_t = now;
                }
            }
        } else if (cal == 4) {
            if (now - cal_t >= 60) {
                pitch1 = pitch - pitch0;
                aim_send(0, -pulse);
                cal = 5;
                cal_t = now;
            }
        } else if (cal == 5) {
            if (now - cal_t >= 60) {
                float d2 = (pitch - pitch0) - pitch1;
                float ret = pitch1 + d2;
                float gy = (float)pulse / pitch1;
                if (fabsf(pitch1) < 0.05f || fabsf(pitch1) > 6.0f ||
                    fabsf(ret) > 0.15f + 0.35f * fabsf(pitch1) ||
                    fabsf(gy) < 1.5f || fabsf(gy) > 400.0f) {
                    logf_("aim 标定失败(pitch d1=%.3f ret=%.3f gy=%.2f)", pitch1, ret, gy);
                    cal = 0;
                    Sleep(400);
                } else {
                    g_aim.gain_y = gy;
                    g_gain_x[cal_ads] = g_aim.gain_x;
                    g_gain_y[cal_ads] = gy;
                    g_gain_ok[cal_ads] = 1;
                    g_aim.calib = 1;
                    cal = 6;
                    logf_("aim 标定完成 ads=%d gain_x=%.3f gain_y=%.3f counts/度",
                          cal_ads, g_aim.gain_x, gy);
                }
            }
        } else if (cal == 6) {
            if (ads_state != cal_ads) {
                if (g_gain_ok[ads_state]) {
                    g_aim.gain_x = g_gain_x[ads_state];
                    g_aim.gain_y = g_gain_y[ads_state];
                    cal_ads = ads_state;
                } else {
                    cal = 0;
                }
            } else if (bi >= 0 && (snap_req ||
                       now - last_cmd >= (ULONGLONG)(g_aim_interval > 3 ? g_aim_interval : 4))) {
                float factor = snap_req ? 1.0f : (float)g_aim_strength * 0.01f;
                int cap;
                if (snap_req) {
                    cap = 400;                 /* 换敌瞬间全量甩枪 */
                } else {
                    cap = 12 + (int)(((int)g_aim_strength - 50) / 5);
                    if (cap < 4) cap = 4;
                    if (cap > 40) cap = 40;
                }
                int cx = 0, cy = 0;
                if (fabsf(bdy) > 0.12f && g_aim.gain_x != 0.0f) {
                    cx = (int)(bdy * g_aim.gain_x * factor);
                    if (cx > cap) cx = cap; else if (cx < -cap) cx = -cap;
                    if (cx == 0) cx = (bdy > 0.0f) ? 1 : -1;
                }
                if (fabsf(bdp) > 0.12f && g_aim.gain_y != 0.0f) {
                    cy = (int)(bdp * g_aim.gain_y * factor);
                    if (cy > cap) cy = cap; else if (cy < -cap) cy = -cap;
                    if (cy == 0) cy = (bdp > 0.0f) ? 1 : -1;
                }
                if (cx || cy) {
                    aim_send(cx, cy);
                    last_cmd = now;
                }
            }
        }
        InterlockedIncrement(&g_aim.ticks);
    }
    return 0;
}

static void team_ensure(void);

static void aim_ensure(void)
{
    if (!g_aim.run) {
        InterlockedExchange(&g_aim.run, 1);
        g_aim_thread = CreateThread(NULL, 0, aim_worker, NULL, 0, NULL);
    }
    team_ensure();
}

/* ================= 吸敌人：把敌对 NPC 持续钉在镜头前方 =================
 * 位置镜像（同一实体内）：
 *   +0x24  origin / +0x140 originB（z=origin.z+36）/ +0x158 origin 副本
 * 头部世界点：actor+0x19C（+0x1D8 副本），随蹲/趴/扑变化
 * 每 ~2ms 重写一次，压过 AI 每帧的移动写入；team 7 队友永不处理。
 */
#define VAC_MAX      256
#define O_E_ORIG_B   0x140
#define O_E_ORIG_C   0x158
#define O_ACT_HEAD2  0x1D8

typedef struct {
    uint64_t ent;
    uint64_t actor;
    int slot;
    int has_head;
    float hox, hoy, hoz;     /* 头部相对脚底偏移（扫描时） */
    float lx, ly, lz;
    float lhx, lhy, lhz;
    int lw, lhw;
} vac_tgt;

static volatile LONG  g_vac_on = 0;
static volatile LONG  g_vac_run = 0;
static volatile LONG  g_vac_ticks = 0;
static volatile LONG  g_vac_n = 0;
static volatile LONG  g_vac_writes = 0;
static volatile float g_vac_drift = 0.0f;
static volatile float g_vac_headerr = 0.0f;
static volatile LONG  g_vac_dist = 400;    /* cm，镜头前方距离 */
static volatile LONG  g_vac_up = 0;        /* cm，额外上抬 */
static volatile LONG  g_vac_ring = 0;      /* cm，环绕半径，0=同一点 */
static volatile LONG  g_vac_team = 7;      /* 排除的阵营（队友） */
static volatile LONG  g_vac_team_only = 0; /* 0=除队友外全吸；>0=只吸该阵营 */
static volatile LONG  g_vac_flags = 7;     /* bit0 头部跟随 bit1 +0x140 bit2 +0x158 */
static HANDLE g_vac_thread = NULL;
static vac_tgt g_vac_tg[VAC_MAX];

static int mem_span_ok(const void *p, size_t n, int wr)
{
    MEMORY_BASIC_INFORMATION mi;
    if (!VirtualQuery(p, &mi, sizeof(mi))) return 0;
    if (mi.State != MEM_COMMIT) return 0;
    if (mi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    if (wr && !(mi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                              PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return 0;
    return (const unsigned char *)p + n <=
           (const unsigned char *)mi.BaseAddress + mi.RegionSize;
}

static int vac_scan(uint64_t base, uint64_t g)
{
    int n = 0;
    /* 自动阵营未锁定时不吸，避免把还没识别出来的友军拉走 */
    if (g_team_auto && g_team_friendly < 0) return 0;
    uint64_t lo = base + 0x1000, hi = base + 0x20000000ULL;
    for (int i = 1; i < ENT_COUNT && n < VAC_MAX; i++) {
        uint64_t ent = g + (uint64_t)i * ENT_STRIDE;
        int hp = *(int *)(uintptr_t)(ent + O_E_HP);
        if (hp <= 0 || hp > 10000) continue;
        uint64_t cls = *(uint64_t *)(uintptr_t)(ent + O_E_CLASS);
        if (cls < lo || cls >= hi) continue;
        if (!mem_span_ok((const void *)(uintptr_t)(cls + O_C_TEAM), 4, 0)) continue;
        uint32_t team = *(uint32_t *)(uintptr_t)(cls + O_C_TEAM);
        if (team_skip(team, g_vac_team)) continue;
        if (g_vac_team_only && (LONG)team != g_vac_team_only) continue;
        float ox = *(float *)(uintptr_t)(ent + O_E_ORIG);
        float oy = *(float *)(uintptr_t)(ent + O_E_ORIG + 4);
        float oz = *(float *)(uintptr_t)(ent + O_E_ORIG + 8);
        if (!(fabsf(ox) < 1.0e6f && fabsf(oy) < 1.0e6f && fabsf(oz) < 1.0e6f))
            continue;
        uint64_t actor = *(uint64_t *)(uintptr_t)(ent + O_E_ACTOR);
        int hh = 0;
        float hox = 0, hoy = 0, hoz = 0;
        if (actor && mem_span_ok((const void *)(uintptr_t)(actor + O_ACT_HEAD),
                                 O_ACT_HEAD2 - O_ACT_HEAD + 12, 1)) {
            float hx = *(float *)(uintptr_t)(actor + O_ACT_HEAD);
            float hy = *(float *)(uintptr_t)(actor + O_ACT_HEAD + 4);
            float hz = *(float *)(uintptr_t)(actor + O_ACT_HEAD + 8);
            float dx = hx - ox, dy = hy - oy, dz = hz - oz;
            if (fabsf(dx) < 150.0f && fabsf(dy) < 150.0f && dz > -30.0f && dz < 150.0f) {
                hh = 1;
                hox = dx; hoy = dy; hoz = dz;
            }
        }
        g_vac_tg[n].ent = ent;
        g_vac_tg[n].actor = actor;
        g_vac_tg[n].slot = i;
        g_vac_tg[n].has_head = hh;
        g_vac_tg[n].hox = hox; g_vac_tg[n].hoy = hoy; g_vac_tg[n].hoz = hoz;
        g_vac_tg[n].lw = 0; g_vac_tg[n].lhw = 0;
        n++;
    }
    return n;
}

static DWORD WINAPI vac_worker(LPVOID p)
{
    (void)p;
    uint64_t base = (uint64_t)(uintptr_t)GetModuleHandleA(NULL);
    int ntg = 0, hires = 0;
    ULONGLONG last_full = 0;
    while (g_vac_run) {
        Sleep(2);
        if (!g_vac_on) {
            g_vac_n = 0;
            if (hires) { fly_hires(0); hires = 0; }
            continue;
        }
        if (!hires) { fly_hires(1); hires = 1; }
        uint64_t g = *(uint64_t *)(uintptr_t)(base + G_ENT_RVA);
        if (!g) { g_vac_n = 0; Sleep(20); continue; }
        if (*(int *)(uintptr_t)(g + O_G_HEALTH) <= 0) { g_vac_n = 0; Sleep(20); continue; }
        ULONGLONG now = GetTickCount64();
        if (!last_full || now - last_full >= 400) {
            ntg = vac_scan(base, g);
            last_full = now;
            g_vac_n = ntg;
        }
        if (ntg <= 0) { Sleep(10); continue; }
        float *cam = (float *)(uintptr_t)(base + POS_RVA);
        float fx = cam[3] - cam[0], fy = cam[4] - cam[1], fz = cam[5] - cam[2];
        float fl = sqrtf(fx * fx + fy * fy + fz * fz);
        if (!(fl > 1.0e-3f)) continue;
        fx /= fl; fy /= fl; fz /= fl;
        float du = (float)g_vac_dist * 0.3937007874f;
        float uu = (float)g_vac_up * 0.3937007874f;
        float px = cam[0] + fx * du;
        float py = cam[1] + fy * du;
        float pz = cam[2] + fz * du + uu;
        float rl = sqrtf(fx * fx + fy * fy);
        float rx, ry, ex = 0, ey = 0, ez = 1;
        if (rl > 1.0e-4f) {
            rx = -fy / rl; ry = fx / rl;
            ex = -fz * rx; ey = -fz * ry; ez = rl;   /* cross(f, r) 归一化 */
        } else {
            rx = 1.0f; ry = 0.0f;
            ex = 0.0f; ey = 1.0f; ez = 0.0f;
        }
        float ru = (float)g_vac_ring * 0.3937007874f;
        float mx_drift = 0.0f, mx_head = 0.0f;
        int wrote = 0;
        for (int i = 0; i < ntg; i++) {
            vac_tgt *t = &g_vac_tg[i];
            uint64_t ent = t->ent;
            if (*(int *)(uintptr_t)(ent + O_E_HP) <= 0) continue;
            float tx = px, ty = py, tz = pz;
            if (ru > 0.01f) {
                float ang = 6.283185307f * (float)i / (float)ntg;
                float c = cosf(ang) * ru, s = sinf(ang) * ru;
                tx += rx * c + ex * s;
                ty += ry * c + ey * s;
                tz += ez * s;
            }
            float *eo = (float *)(uintptr_t)(ent + O_E_ORIG);
            if (t->lw && i < 16) {
                float dx = eo[0] - t->lx, dy = eo[1] - t->ly, dz = eo[2] - t->lz;
                float d = sqrtf(dx * dx + dy * dy + dz * dz);
                if (d > mx_drift) mx_drift = d;
            }
            eo[0] = tx; eo[1] = ty; eo[2] = tz;
            if (g_vac_flags & 2) {
                *(float *)(uintptr_t)(ent + O_E_ORIG_B) = tx;
                *(float *)(uintptr_t)(ent + O_E_ORIG_B + 4) = ty;
                *(float *)(uintptr_t)(ent + O_E_ORIG_B + 8) = tz + 36.0f;
            }
            if (g_vac_flags & 4) {
                *(float *)(uintptr_t)(ent + O_E_ORIG_C) = tx;
                *(float *)(uintptr_t)(ent + O_E_ORIG_C + 4) = ty;
                *(float *)(uintptr_t)(ent + O_E_ORIG_C + 8) = tz;
            }
            if ((g_vac_flags & 1) && t->has_head && t->actor) {
                float *hp = (float *)(uintptr_t)(t->actor + O_ACT_HEAD);
                float hx2 = tx + t->hox, hy2 = ty + t->hoy, hz2 = tz + t->hoz;
                if (i == 0 && t->lhw) {
                    float dx = hp[0] - t->lhx, dy = hp[1] - t->lhy, dz = hp[2] - t->lhz;
                    mx_head = sqrtf(dx * dx + dy * dy + dz * dz);
                }
                hp[0] = hx2; hp[1] = hy2; hp[2] = hz2;
                float *hp2 = (float *)(uintptr_t)(t->actor + O_ACT_HEAD2);
                hp2[0] = hx2; hp2[1] = hy2; hp2[2] = hz2;
                t->lhx = hx2; t->lhy = hy2; t->lhz = hz2; t->lhw = 1;
            }
            t->lx = tx; t->ly = ty; t->lz = tz; t->lw = 1;
            wrote++;
        }
        g_vac_drift = mx_drift;
        g_vac_headerr = mx_head;
        g_vac_writes = wrote;
        InterlockedIncrement(&g_vac_ticks);
    }
    return 0;
}

static void vac_ensure(void)
{
    if (!g_vac_run) {
        InterlockedExchange(&g_vac_run, 1);
        g_vac_thread = CreateThread(NULL, 0, vac_worker, NULL, 0, NULL);
    }
    team_ensure();
}

/* ===== 阵营识别 worker：关卡切换后采样最近 3 个活体 NPC 的 team ===== */
static DWORD WINAPI team_worker(LPVOID p)
{
    (void)p;
    uint64_t base = (uint64_t)(uintptr_t)GetModuleHandleA(NULL);
    uint64_t last_g = 0;
    float lx = 0.0f, ly = 0.0f, lz = 0.0f;
    int last_hp = -1;
    int phase = 0;                    /* 0 空闲 1 采样中 */
    ULONGLONG deadline = 0, sample_start = 0;
    LONG votes[32];
    int streak = 0;
    uint32_t last_valid = 0;
    memset(votes, 0, sizeof(votes));
    while (g_team_run) {
        Sleep(300);
        InterlockedIncrement(&g_team_ticks);
        uint64_t g = *(uint64_t *)(uintptr_t)(base + G_ENT_RVA);
        if (!g) { last_g = 0; phase = 0; g_team_state = 0; continue; }
        int hp = *(int *)(uintptr_t)(g + O_G_HEALTH);
        float px = *(float *)(uintptr_t)(g + O_E_ORIG);
        float py = *(float *)(uintptr_t)(g + O_E_ORIG + 4);
        float pz = *(float *)(uintptr_t)(g + O_E_ORIG + 8);
        int level_new = 0;
        if (g != last_g) level_new = 1;
        if (last_hp <= 0 && hp > 0) level_new = 1;
        if (last_g && fabsf(px - lx) + fabsf(py - ly) + fabsf(pz - lz) > 4000.0f)
            level_new = 1;
        last_g = g; last_hp = hp;
        lx = px; ly = py; lz = pz;
        if (g_team_resample) {
            InterlockedExchange(&g_team_resample, 0);
            level_new = 1;
        }
        if (level_new) {
            phase = 0;
            if (g_team_auto) {
                /* 开局先等 3 秒让队友就位，再采样 8 秒；避免把远处敌人当成友军 */
                phase = 1;
                sample_start = GetTickCount64() + 3000;
                deadline = sample_start + 8000;
                memset(votes, 0, sizeof(votes));
                streak = 0;
                last_valid = 0;
                g_team_samples = 0;
                g_team_friendly = -1;
                g_team_state = 1;
            }
            continue;
        }
        if (!phase) continue;
        if (hp <= 0) continue;
        if (GetTickCount64() < sample_start) continue;
        /* 最近的 3 个活体 NPC（不套阵营过滤，否则找不到友军） */
        int bs[3] = { -1, -1, -1 };
        float bd[3] = { 1.0e30f, 1.0e30f, 1.0e30f };
        uint32_t bt[3] = { 0, 0, 0 };
        uint64_t lo = base + 0x1000, hi = base + 0x20000000ULL;
        for (int i = 1; i < ENT_COUNT; i++) {
            uint64_t ent = g + (uint64_t)i * ENT_STRIDE;
            int ehp = *(int *)(uintptr_t)(ent + O_E_HP);
            if (ehp <= 0 || ehp > 10000) continue;
            uint64_t cls = *(uint64_t *)(uintptr_t)(ent + O_E_CLASS);
            if (cls < lo || cls >= hi) continue;
            if (!mem_span_ok((const void *)(uintptr_t)(cls + O_C_TEAM), 4, 0)) continue;
            uint32_t team = *(uint32_t *)(uintptr_t)(cls + O_C_TEAM);
            if (team >= 32u) continue;
            if ((g_team_extra_mask >> team) & 1u) continue;   /* 幽灵/弃用阵营不参与采样 */
            float x = *(float *)(uintptr_t)(ent + O_E_ORIG);
            float y = *(float *)(uintptr_t)(ent + O_E_ORIG + 4);
            float z = *(float *)(uintptr_t)(ent + O_E_ORIG + 8);
            if (!(fabsf(x) < 1.0e6f && fabsf(y) < 1.0e6f && fabsf(z) < 1.0e6f))
                continue;
            float dx = x - px, dy = y - py, dz = z - pz;
            float d2 = dx * dx + dy * dy + dz * dz;
            if (d2 >= bd[2]) continue;
            if (d2 < bd[0]) {
                bd[2] = bd[1]; bs[2] = bs[1]; bt[2] = bt[1];
                bd[1] = bd[0]; bs[1] = bs[0]; bt[1] = bt[0];
                bd[0] = d2; bs[0] = i; bt[0] = team;
            } else if (d2 < bd[1]) {
                bd[2] = bd[1]; bs[2] = bs[1]; bt[2] = bt[1];
                bd[1] = d2; bs[1] = i; bt[1] = team;
            } else {
                bd[2] = d2; bs[2] = i; bt[2] = team;
            }
        }
        /* 三人同队且第三近的也在 25m 内才算有效样本（队友总跟在身边，远处的是敌人） */
        if (bs[2] >= 0 && bt[0] == bt[1] && bt[1] == bt[2] && bd[2] <= 970000.0f) {
            votes[bt[0] & 31]++;
            g_team_samples = g_team_samples + 1;
            streak = (bt[0] == last_valid) ? streak + 1 : 1;
            last_valid = bt[0];
            if (g_team_friendly < 0 && streak >= 2) {   /* 连续两次稳定即先行锁定 */
                g_team_friendly = (LONG)bt[0];
                g_team_state = 2;
                logf_("team 识别锁定 友军=%d（连续 %d 次）", bt[0], streak);
            }
        } else {
            streak = 0;
            last_valid = 0;
        }
        if (GetTickCount64() >= deadline || g_team_samples >= 6) {
            int best = 0, bt2 = -1;
            for (int i = 0; i < 32; i++)
                if (votes[i] > best) { best = votes[i]; bt2 = i; }
            if (bt2 >= 0 && best >= 2 && (LONG)best * 2 >= g_team_samples) {
                g_team_friendly = bt2;
                g_team_state = 2;
                logf_("team 自动识别 友军=%d 票=%d/%d", bt2, best, (int)g_team_samples);
            } else {
                g_team_friendly = -1;
                g_team_state = 3;
                logf_("team 自动识别失败 有效样本=%d", (int)g_team_samples);
            }
            phase = 0;
        }
    }
    return 0;
}

static void team_ensure(void)
{
    if (!g_team_run) {
        InterlockedExchange(&g_team_run, 1);
        g_team_thread = CreateThread(NULL, 0, team_worker, NULL, 0, NULL);
    }
}

static unsigned char g_snap[SNAP_CAP];
static uint64_t      g_snap_addr = 0;
static uint32_t      g_snap_size = 0;

static double raw_to_num(uint64_t raw, uint32_t dsize)
{
    switch (dsize) {
    case 4:  { union { uint32_t u; float f; } c;    c.u = (uint32_t)raw; return (double)c.f; }
    case 8:  { union { uint64_t u; double d; } c;   c.u = raw;           return c.d; }
    case 2:  { int16_t v; memcpy(&v, &raw, 2);      return (double)v; }
    default: { int8_t  v; memcpy(&v, &raw, 1);      return (double)v; }
    }
}

static int64_t raw_to_i64(uint64_t raw, uint32_t dsize)
{
    switch (dsize) {
    case 4:  return (int64_t)(int32_t)(uint32_t)raw;
    case 8:  return (int64_t)raw;
    case 2:  { int16_t v; memcpy(&v, &raw, 2); return (int64_t)v; }
    default: { int8_t  v; memcpy(&v, &raw, 1); return (int64_t)v; }
    }
}

static int is_float_dtype(uint32_t dsize) { return dsize == 4 || dsize == 8; }

static void scan_begin(uint32_t dsize, uint32_t mode, double v1, double v2, int writable_only)
{
    MEMORY_BASIC_INFORMATION mbi;
    unsigned long long addr = 0;
    const SIZE_T BUF = 4u << 20;
    unsigned char *buf = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, BUF);
    if (!buf) return;

    g_dtype = dsize;
    g_count = 0;
    g_capped = 0;

    uint64_t want = 0;
    memcpy(&want, &v1, 8);              /* 精度模式：v1 传的是原始位 */

    while (addr < 0x7FFFFFFF0000ULL) {
        SIZE_T got = VirtualQueryEx(GetCurrentProcess(), (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi));
        if (!got) break;
        if (mbi.State == MEM_COMMIT && mbi.RegionSize &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            int is_w = (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            if (!writable_only || is_w) {
                unsigned long long a = (unsigned long long)(uintptr_t)mbi.BaseAddress;
                unsigned long long end = a + mbi.RegionSize;
                while (a < end && !g_capped) {
                    SIZE_T n = (SIZE_T)((end - a) > BUF ? BUF : (end - a));
                    SIZE_T read = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(uintptr_t)a, buf, n, &read) && read >= dsize) {
                        SIZE_T usable = read - (read % dsize);
                        for (SIZE_T off = 0; off + dsize <= usable; off += dsize) {
                            uint64_t raw = 0;
                            memcpy(&raw, buf + off, dsize);
                            int hit;
                            if (mode == 0) {
                                uint64_t mask = (dsize >= 8) ? ~0ULL : ((1ULL << (dsize * 8)) - 1);
                                hit = ((raw & mask) == (want & mask));
                            } else if (is_float_dtype(dsize)) {
                                double d = raw_to_num(raw, dsize);
                                hit = (d >= v1 && d <= v2);
                            } else {
                                int64_t iv = raw_to_i64(raw, dsize);
                                hit = ((double)iv >= v1 && (double)iv <= v2);
                            }
                            if (hit) {
                                if (g_count >= SCAN_CAP) { g_capped = 1; break; }
                                g_addrs[g_count] = (uint64_t)(a + off);
                                g_vals[g_count] = raw;
                                g_count++;
                            }
                        }
                    }
                    a += n;
                }
            }
        }
        addr = (unsigned long long)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    HeapFree(GetProcessHeap(), 0, buf);
    logf_("scan_begin dsize=%u mode=%u -> %u%s", dsize, mode, g_count, g_capped ? " (capped)" : "");
}

static void scan_filter(uint32_t mode, double v1, double v2)
{
    uint32_t keep = 0;
    for (uint32_t i = 0; i < g_count; i++) {
        uint64_t a = g_addrs[i];
        uint64_t raw = 0;
        SIZE_T read = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(uintptr_t)a, &raw, g_dtype, &read) ||
            read != g_dtype) {
            continue;
        }
        uint64_t prev = g_vals[i];
        int ok = 0;
        switch (mode) {
        case 0: ok = (raw != prev); break;                       /* 变化 */
        case 1: ok = (raw == prev); break;                       /* 未变 */
        case 2:
            ok = is_float_dtype(g_dtype)
                     ? raw_to_num(raw, g_dtype) > raw_to_num(prev, g_dtype)
                     : raw_to_i64(raw, g_dtype) > raw_to_i64(prev, g_dtype);
            break;
        case 3:
            ok = is_float_dtype(g_dtype)
                     ? raw_to_num(raw, g_dtype) < raw_to_num(prev, g_dtype)
                     : raw_to_i64(raw, g_dtype) < raw_to_i64(prev, g_dtype);
            break;
        case 4: {
            uint64_t want = 0;
            memcpy(&want, &v1, 8);
            uint64_t mask = (g_dtype >= 8) ? ~0ULL : ((1ULL << (g_dtype * 8)) - 1);
            ok = ((raw & mask) == (want & mask));
            break;
        }
        default:
            if (is_float_dtype(g_dtype)) {
                double d = raw_to_num(raw, g_dtype);
                ok = (d >= v1 && d <= v2);
            } else {
                int64_t iv = raw_to_i64(raw, g_dtype);
                ok = ((double)iv >= v1 && (double)iv <= v2);
            }
        }
        if (ok) {
            g_addrs[keep] = a;
            g_vals[keep] = raw;
            keep++;
        }
    }
    g_count = keep;
    logf_("scan_filter mode=%u -> %u", mode, g_count);
}

/* ---------------- 网络 ---------------- */
static int recv_all(SOCKET s, char *buf, int len)
{
    int got = 0;
    while (got < len) {
        int r = recv(s, buf + got, len - got, 0);
        if (r <= 0) return 0;
        got += r;
    }
    return 1;
}

static int send_all(SOCKET s, const char *buf, int len)
{
    int sent = 0;
    while (sent < len) {
        int r = send(s, buf + sent, len - sent, 0);
        if (r <= 0) return 0;
        sent += r;
    }
    return 1;
}

static void handle_client(SOCKET c, char *buf)
{
    for (;;) {
        unsigned char op;
        if (!recv_all(c, (char *)&op, 1)) break;

        if (op == 1) {                                   /* READ */
            unsigned long long addr; unsigned int len;
            if (!recv_all(c, (char *)&addr, 8)) break;
            if (!recv_all(c, (char *)&len, 4)) break;
            if (len > MAX_XFER) len = MAX_XFER;
            SIZE_T done = 0;
            BOOL ok = ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(uintptr_t)addr, buf + 5, len, &done);
            if (!ok) done = 0;
            buf[0] = ok ? 1 : 0;
            memcpy(buf + 1, &done, 4);
            if (!send_all(c, buf, 5 + (int)done)) break;
        } else if (op == 2) {                            /* WRITE */
            unsigned long long addr; unsigned int len;
            if (!recv_all(c, (char *)&addr, 8)) break;
            if (!recv_all(c, (char *)&len, 4)) break;
            if (len > MAX_XFER) break;
            if (!recv_all(c, buf, (int)len)) break;
            SIZE_T done = 0;
            BOOL ok = WriteProcessMemory(GetCurrentProcess(), (LPVOID)(uintptr_t)addr, buf, len, &done);
            buf[0] = ok ? 1 : 0;
            memcpy(buf + 1, &done, 4);
            if (!send_all(c, buf, 5)) break;
        } else if (op == 3) {                            /* INFO */
            HMODULE h = GetModuleHandleA(NULL);
            unsigned long long base = (unsigned long long)(uintptr_t)h;
            unsigned long long size = 0;
            char *p = (char *)h;
            if (p && p[0] == 'M' && p[1] == 'Z') {
                IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)h;
                IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((char *)h + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE) size = nt->OptionalHeader.SizeOfImage;
            }
            char name[MAX_PATH] = {0};
            GetModuleFileNameA(NULL, name, MAX_PATH);
            char *bn = strrchr(name, '\\'); bn = bn ? bn + 1 : name;
            unsigned int nlen = (unsigned int)strlen(bn);
            buf[0] = 1;
            memcpy(buf + 1, &base, 8);
            memcpy(buf + 9, &size, 8);
            memcpy(buf + 17, &nlen, 4);
            memcpy(buf + 21, bn, nlen);
            if (!send_all(c, buf, 21 + (int)nlen)) break;
        } else if (op == 4) {                            /* REGIONS */
            unsigned long long addr = 0;
            if (!recv_all(c, (char *)&addr, 8)) break;
            unsigned int count = 0;
            char *w = buf + 13;
            unsigned long long next = 0;
            MEMORY_BASIC_INFORMATION mbi;
            while (addr < 0x7FFFFFFF0000ULL) {
                SIZE_T got = VirtualQueryEx(GetCurrentProcess(), (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi));
                if (!got) break;
                if (mbi.State == MEM_COMMIT && mbi.RegionSize) {
                    if (13 + (count + 1) * 24 > MAX_XFER) { next = addr; break; }
                    unsigned long long b = (unsigned long long)(uintptr_t)mbi.BaseAddress;
                    unsigned long long sz = (unsigned long long)mbi.RegionSize;
                    unsigned int pr = (unsigned int)mbi.Protect;
                    unsigned int ty = (unsigned int)mbi.Type;
                    memcpy(w, &b, 8); memcpy(w + 8, &sz, 8);
                    memcpy(w + 16, &pr, 4); memcpy(w + 20, &ty, 4);
                    w += 24; count++;
                }
                addr = (unsigned long long)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            }
            buf[0] = 1;
            memcpy(buf + 1, &count, 4);
            memcpy(buf + 5, &next, 8);
            if (!send_all(c, buf, 13 + (int)count * 24)) break;
        } else if (op == 5) {                            /* PING */
            unsigned int pid = GetCurrentProcessId();
            buf[0] = 1;
            memcpy(buf + 1, &pid, 4);
            if (!send_all(c, buf, 5)) break;
        } else if (op == 6) {                            /* SCAN_BEGIN */
            unsigned int dsize, mode, writable;
            double v1, v2;
            if (!recv_all(c, (char *)&dsize, 4)) break;
            if (!recv_all(c, (char *)&mode, 4)) break;
            if (!recv_all(c, (char *)&v1, 8)) break;
            if (!recv_all(c, (char *)&v2, 8)) break;
            if (!recv_all(c, (char *)&writable, 4)) break;
            if (dsize != 1 && dsize != 2 && dsize != 4 && dsize != 8) dsize = 4;
            EnterCriticalSection(&g_scan_cs);
            if (!g_addrs) {
                g_addrs = (uint64_t *)VirtualAlloc(NULL, (SIZE_T)SCAN_CAP * 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                g_vals  = (uint64_t *)VirtualAlloc(NULL, (SIZE_T)SCAN_CAP * 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            }
            if (g_addrs && g_vals) {
                scan_begin(dsize, mode, v1, v2, writable ? 1 : 0);
            } else {
                g_count = 0;
                g_capped = 1;
            }
            unsigned int cnt = g_count;
            LeaveCriticalSection(&g_scan_cs);
            buf[0] = 1;
            memcpy(buf + 1, &cnt, 4);
            buf[5] = (char)g_capped;
            if (!send_all(c, buf, 6)) break;
        } else if (op == 7) {                            /* SCAN_FILTER */
            unsigned int mode;
            double v1, v2;
            if (!recv_all(c, (char *)&mode, 4)) break;
            if (!recv_all(c, (char *)&v1, 8)) break;
            if (!recv_all(c, (char *)&v2, 8)) break;
            EnterCriticalSection(&g_scan_cs);
            if (g_addrs && g_vals) scan_filter(mode, v1, v2);
            unsigned int cnt = g_count;
            LeaveCriticalSection(&g_scan_cs);
            buf[0] = 1;
            memcpy(buf + 1, &cnt, 4);
            if (!send_all(c, buf, 5)) break;
        } else if (op == 8) {                            /* SCAN_GET */
            unsigned int start, want;
            if (!recv_all(c, (char *)&start, 4)) break;
            if (!recv_all(c, (char *)&want, 4)) break;
            unsigned int n = 0;
            char *w = buf + 5;
            EnterCriticalSection(&g_scan_cs);
            if (start < g_count) {
                unsigned int cap = (MAX_XFER - 16) / 16;
                n = want < cap ? want : cap;
                if (start + n > g_count) n = g_count - start;
                for (unsigned int i = 0; i < n; i++) {
                    memcpy(w, &g_addrs[start + i], 8);
                    memcpy(w + 8, &g_vals[start + i], 8);
                    w += 16;
                }
            }
            LeaveCriticalSection(&g_scan_cs);
            buf[0] = 1;
            memcpy(buf + 1, &n, 4);
            if (!send_all(c, buf, 5 + (int)n * 16)) break;
        } else if (op == 9) {                            /* SCAN_CLEAR */
            EnterCriticalSection(&g_scan_cs);
            g_count = 0; g_capped = 0;
            LeaveCriticalSection(&g_scan_cs);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 10) {                           /* SNAP */
            unsigned long long addr; unsigned int size;
            if (!recv_all(c, (char *)&addr, 8)) break;
            if (!recv_all(c, (char *)&size, 4)) break;
            if (size > SNAP_CAP) size = SNAP_CAP;
            SIZE_T read = 0;
            BOOL ok = ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(uintptr_t)addr, g_snap, size, &read);
            g_snap_addr = addr;
            g_snap_size = ok ? (uint32_t)read : 0;
            buf[0] = ok ? 1 : 0;
            memcpy(buf + 1, &g_snap_size, 4);
            if (!send_all(c, buf, 5)) break;
        } else if (op == 11) {                           /* DIFF */
            unsigned int min_delta;
            if (!recv_all(c, (char *)&min_delta, 4)) break;
            unsigned int n = 0;
            char *w = buf + 5;
            if (g_snap_size >= 4) {
                unsigned char *cur = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, g_snap_size);
                if (cur) {
                    SIZE_T read = 0;
                    if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(uintptr_t)g_snap_addr,
                                          cur, g_snap_size, &read) && read >= 4) {
                        uint32_t limit = (g_snap_size < read) ? g_snap_size : (uint32_t)read;
                        for (uint32_t off = 0; off + 4 <= limit && n < 8000; off += 4) {
                            int32_t a, b;
                            memcpy(&a, g_snap + off, 4);
                            memcpy(&b, cur + off, 4);
                            if (a == b) continue;
                            int64_t d = (int64_t)b - (int64_t)a;
                            if (min_delta && d > -(int64_t)min_delta && d < (int64_t)min_delta) continue;
                            unsigned int o = off;
                            int64_t av = a, bv = b;
                            memcpy(w, &o, 4); memcpy(w + 4, &av, 8); memcpy(w + 12, &bv, 8);
                            w += 20; n++;
                        }
                    }
                    HeapFree(GetProcessHeap(), 0, cur);
                }
            }
            buf[0] = 1;
            memcpy(buf + 1, &n, 4);
            if (!send_all(c, buf, 5 + (int)n * 20)) break;
        } else if (op == 13) {                           /* HASH_BEGIN：全内存页哈希 */
            unsigned int writable;
            if (!recv_all(c, (char *)&writable, 4)) break;
            EnterCriticalSection(&g_scan_cs);
            if (!g_ph_addr) {
                g_ph_addr = (uint64_t *)VirtualAlloc(NULL, (SIZE_T)HASH_CAP * 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                g_ph_hash = (uint64_t *)VirtualAlloc(NULL, (SIZE_T)HASH_CAP * 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            }
            if (g_ph_addr && g_ph_hash)
                g_ph_count = walk_pages(writable ? 1 : 0, cb_store, HASH_CAP);
            else
                g_ph_count = 0;
            unsigned int cnt = g_ph_count;
            LeaveCriticalSection(&g_scan_cs);
            logf_("hash_begin pages=%u", cnt);
            buf[0] = 1;
            memcpy(buf + 1, &cnt, 4);
            if (!send_all(c, buf, 5)) break;
        } else if (op == 14) {                           /* HASH_DIFF：返回变化的页 */
            unsigned int n = 0;
            char *w = buf + 5;
            EnterCriticalSection(&g_scan_cs);
            if (g_ph_addr && g_ph_hash && g_ph_count) {
                MEMORY_BASIC_INFORMATION mbi;
                unsigned long long addr = 0;
                unsigned char pagebuf[PAGE_SZ];
                uint32_t idx = 0;
                while (addr < 0x7FFFFFFF0000ULL && idx < g_ph_count) {
                    SIZE_T got = VirtualQueryEx(GetCurrentProcess(), (LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi));
                    if (!got) break;
                    int readable = mbi.State == MEM_COMMIT && mbi.RegionSize &&
                                   (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                                   PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) &&
                                   !(mbi.Protect & PAGE_GUARD);
                    if (readable) {
                        unsigned long long a = (unsigned long long)(uintptr_t)mbi.BaseAddress;
                        unsigned long long end = a + mbi.RegionSize;
                        while (a < end && idx < g_ph_count) {
                            SIZE_T want = (SIZE_T)((end - a) >= PAGE_SZ ? PAGE_SZ : (end - a));
                            SIZE_T read = 0;
                            if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(uintptr_t)a, pagebuf, want, &read) && read) {
                                /* 两趟之间可能有新分配导致下标漂移，必须按地址查找 */
                                uint32_t lo = 0, hi = g_ph_count;
                                int found = -1;
                                while (lo < hi) {
                                    uint32_t mid = lo + (hi - lo) / 2;
                                    if (g_ph_addr[mid] == (uint64_t)a) { found = (int)mid; break; }
                                    if (g_ph_addr[mid] < (uint64_t)a) lo = mid + 1; else hi = mid;
                                }
                                if (found >= 0) {
                                    uint64_t h = fnv1a(pagebuf, read);
                                    if (h != g_ph_hash[found] && n < 8000) {
                                        uint64_t pa = (uint64_t)a;
                                        memcpy(w, &pa, 8);
                                        w += 8;
                                        n++;
                                    }
                                }
                                idx++;
                            }
                            a += want;
                        }
                    }
                    addr = (unsigned long long)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
                }
            }
            LeaveCriticalSection(&g_scan_cs);
            logf_("hash_diff changed=%u", n);
            buf[0] = 1;
            memcpy(buf + 1, &n, 4);
            if (!send_all(c, buf, 5 + (int)n * 8)) break;
        } else if (op == 15) {                           /* BP_ARM: 监视某地址的写入 */
            unsigned long long watch;
            if (!recv_all(c, (char *)&watch, 8)) break;
            if (!g_veh) {
                g_veh = AddVectoredExceptionHandler(1, bp_handler);
                mod_info();
            }
            g_bp_watch = watch;
            DWORD old;
            unsigned char *page = (unsigned char *)(uintptr_t)(watch & ~0xFFFULL);
            int ok = VirtualProtect(page, 0x1000, PAGE_READONLY, &old);
            if (ok) {
                g_bp_page = page;
                g_bp_oldprot = old;
                g_bp_hits = 0;
                g_bp_total = 0;
                InterlockedExchange(&g_bp_active, 1);
                InterlockedExchange(&g_bp_armed, 1);
                HANDLE t = CreateThread(NULL, 0, bp_watchdog, NULL, 0, NULL);
                if (t) CloseHandle(t);
                logf_("bp_arm 0x%llx", watch);
            }
            buf[0] = ok ? 1 : 0;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 16) {                           /* BP_GET: 取 RIP 列表 */
            unsigned int n = 0;
            char *w = buf + 5;
            EnterCriticalSection(&g_scan_cs);
            LONG hits = g_bp_hits;
            if (hits > 16) hits = 16;
            for (LONG i = 0; i < hits; i++) {
                uint64_t rip = g_bp_rips[i], rva = 0;
                if (rip >= g_mod_base && rip < g_mod_base + g_mod_size) rva = rip - g_mod_base;
                uint64_t fa = g_bp_addrs[i];
                memcpy(w, &rip, 8); memcpy(w + 8, &rva, 8); memcpy(w + 16, &fa, 8);
                w += 24; n++;
            }
            LeaveCriticalSection(&g_scan_cs);
            buf[0] = 1;
            memcpy(buf + 1, &n, 4);
            if (!send_all(c, buf, 5 + (int)n * 24)) break;
        } else if (op == 17) {                           /* BP_DISARM */
            /* 顺序很重要：先停看门狗，再等它退出，最后恢复可写。
               页指针一律保留 —— 万一有竞态残留只读，异常处理器还能兜底放行。 */
            InterlockedExchange(&g_bp_active, 0);
            InterlockedExchange(&g_bp_armed, 0);
            Sleep(3);
            if (g_bp_page) {
                DWORD old;
                VirtualProtect(g_bp_page, 0x1000, g_bp_oldprot, &old);
            }
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 18) {                           /* BP_HW_SET: 硬件写断点 */
            unsigned long long addr;
            if (!recv_all(c, (char *)&addr, 8)) break;
            if (!g_veh) {
                g_veh = AddVectoredExceptionHandler(1, bp_handler);
                mod_info();
            }
            g_hw_addr = addr;
            g_hw_hits = 0;
            InterlockedExchange(&g_hw_ever, 1);
            InterlockedExchange(&g_hw_active, 1);
            hw_set_all(1, addr);
            HANDLE t = CreateThread(NULL, 0, hw_rearm, NULL, 0, NULL);
            if (t) CloseHandle(t);
            logf_("hw_bp 0x%llx", addr);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 19) {                           /* BP_HW_GET */
            unsigned int n = 0;
            char *w = buf + 5;
            EnterCriticalSection(&g_scan_cs);
            LONG hits = g_hw_hits;
            if (hits > 16) hits = 16;
            for (LONG i = 0; i < hits; i++) {
                uint64_t rip = g_hw_rips[i], rva = g_hw_rvas[i];
                uint32_t tid = g_hw_tids[i];
                uint64_t rsp = g_hw_rsp[i];
                uint64_t g0 = g_hw_regs[i][0], g1 = g_hw_regs[i][1];
                uint64_t g2 = g_hw_regs[i][2], g3 = g_hw_regs[i][3];
                memcpy(w, &rip, 8); memcpy(w + 8, &rva, 8);
                memcpy(w + 16, &tid, 4); memcpy(w + 20, &rsp, 8);
                memcpy(w + 28, &g0, 8); memcpy(w + 36, &g1, 8);
                memcpy(w + 44, &g2, 8); memcpy(w + 52, &g3, 8);
                w += 60; n++;
            }
            LeaveCriticalSection(&g_scan_cs);
            buf[0] = 1;
            memcpy(buf + 1, &n, 4);
            if (!send_all(c, buf, 5 + (int)n * 60)) break;
        } else if (op == 24) {                           /* HOOK_CALL: site, fn, ret, filter */
            unsigned long long site, fn, ret;
            unsigned int filter;
            if (!recv_all(c, (char *)&site, 8)) break;
            if (!recv_all(c, (char *)&fn, 8)) break;
            if (!recv_all(c, (char *)&ret, 8)) break;
            if (!recv_all(c, (char *)&filter, 4)) break;
            int ok = 0;
            if (!g_hk_page) {
                unsigned long long hint = site & ~0xFFFFULL;
                for (unsigned long long dlt = 0x10000; dlt < 0x30000000ULL && !g_hk_page; dlt += 0x10000) {
                    g_hk_page = (unsigned char *)VirtualAlloc((LPVOID)(uintptr_t)(hint + dlt), 0x1000,
                                                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (!g_hk_page)
                        g_hk_page = (unsigned char *)VirtualAlloc((LPVOID)(uintptr_t)(hint - dlt), 0x1000,
                                                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                }
                if (g_hk_page) g_hk_slot = (uint64_t *)(g_hk_page + 0x800);
            }
            if (g_hk_page && g_hk_slot) {
                unsigned char *s2 = g_hk_page;
                uint64_t *sl = g_hk_slot;
                int o = 0;
                /* 只在 ecx 低 16 位 == filter 时记录，避免被其他索引的调用覆盖 */
                s2[o++] = 0x89; s2[o++] = 0xC8;                       /* mov eax, ecx */
                s2[o++] = 0x25; s2[o++] = 0xFF; s2[o++] = 0xFF; s2[o++] = 0x00; s2[o++] = 0x00;
                s2[o++] = 0x3D; memcpy(s2 + o, &filter, 4); o += 4;   /* cmp eax, filter */
                s2[o++] = 0x75; s2[o++] = 0x1C;                       /* jne skip(28) */
                unsigned char regs[3] = { 0x35, 0x0D, 0x15 };         /* rsi, rcx, rdx */
                for (int k = 0; k < 3; k++) {
                    s2[o++] = 0x48; s2[o++] = 0x89; s2[o++] = regs[k];
                    int32_t d = (int32_t)((uint64_t)(sl + k) - (uint64_t)(s2 + o + 4));
                    memcpy(s2 + o, &d, 4); o += 4;
                }
                /* inc qword [slot+3] */
                s2[o++] = 0x48; s2[o++] = 0xFF; s2[o++] = 0x05;
                int32_t d4 = (int32_t)((uint64_t)(sl + 3) - (uint64_t)(s2 + o + 4));
                memcpy(s2 + o, &d4, 4); o += 4;
                /* call fn */
                s2[o++] = 0xE8;
                int32_t rel = (int32_t)(fn - (uint64_t)(s2 + o + 4));
                memcpy(s2 + o, &rel, 4); o += 4;
                /* mov rax, ret ; jmp rax */
                s2[o++] = 0x48; s2[o++] = 0xB8;
                memcpy(s2 + o, &ret, 8); o += 8;
                s2[o++] = 0xFF; s2[o++] = 0xE0;

                g_hk_site = (unsigned char *)(uintptr_t)site;
                memcpy(g_hk_orig, g_hk_site, 5);
                DWORD old;
                if (VirtualProtect(g_hk_site, 5, PAGE_EXECUTE_READWRITE, &old)) {
                    g_hk_site[0] = 0xE9;
                    int32_t r2 = (int32_t)((uint64_t)s2 - ((uint64_t)g_hk_site + 5));
                    memcpy(g_hk_site + 1, &r2, 4);
                    VirtualProtect(g_hk_site, 5, old, &old);
                    InterlockedExchange(&g_hk_active, 1);
                    ok = 1;
                    logf_("hook_call site=0x%llx stub=0x%llx filter=%u", site,
                          (unsigned long long)(uintptr_t)s2, filter);
                }
            }
            buf[0] = (char)ok;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 30) {                           /* LOCK_ADD: addr, size, raw, interval */
            unsigned long long addr, raw;
            unsigned int sz, iv;
            if (!recv_all(c, (char *)&addr, 8)) break;
            if (!recv_all(c, (char *)&sz, 4)) break;
            if (!recv_all(c, (char *)&raw, 8)) break;
            if (!recv_all(c, (char *)&iv, 4)) break;
            int ok = 0;
            if (sz > 8) sz = 8;
            if (iv < 1) iv = 1;
            for (int i = 0; i < 8; i++) {
                if (!g_locks[i].on) {
                    g_locks[i].addr = addr;
                    g_locks[i].size = sz;
                    g_locks[i].interval = iv;
                    memcpy(g_locks[i].data, &raw, 8);
                    InterlockedExchange(&g_locks[i].on, 1);
                    ok = 1;
                    break;
                }
            }
            if (ok && !g_lock_run) {
                InterlockedExchange(&g_lock_run, 1);
                g_lock_thread = CreateThread(NULL, 0, lock_worker, NULL, 0, NULL);
            }
            logf_("lock_add 0x%llx size=%u raw=0x%llx", addr, sz, raw);
            buf[0] = (char)ok;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 31) {                           /* LOCK_CLR */
            for (int i = 0; i < 8; i++) InterlockedExchange(&g_locks[i].on, 0);
            InterlockedExchange(&g_lock_run, 0);
            Sleep(10);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 32) {                           /* FLY_SET */
            unsigned char en, mode;
            unsigned int scale, vku, vkd, vkt, vks;
            if (!recv_all(c, (char *)&en, 1)) break;
            if (!recv_all(c, (char *)&mode, 1)) break;
            if (!recv_all(c, (char *)&scale, 4)) break;
            if (!recv_all(c, (char *)&vku, 4)) break;
            if (!recv_all(c, (char *)&vkd, 4)) break;
            if (!recv_all(c, (char *)&vkt, 4)) break;
            if (!recv_all(c, (char *)&vks, 4)) break;
            g_fly.mode = mode ? 1 : 0;
            g_fly.scale10 = (LONG)(scale < 20 ? 20 : (scale > 100 ? 100 : scale));
            g_fly.vk_up = (LONG)vku;
            g_fly.vk_down = (LONG)vkd;
            g_fly.vk_toggle = (LONG)vkt;
            g_fly.vk_speed = (LONG)vks;
            fly_ensure();
            InterlockedExchange(&g_fly.nudge, 0);
            InterlockedExchange(&g_fly.on, en ? 1 : 0);
            logf_("fly_set on=%u mode=%u scale=%u up=%u down=%u", en, mode, scale, vku, vkd);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 33) {                           /* FLY_GET */
            fly_ensure();
            float z = g_fly.z, tz = g_fly.tz, bz = g_fly.bz;
            unsigned int ticks = (unsigned int)g_fly.ticks;
            int hp = (int)g_fly.hp, err = (int)g_fly.err;
            unsigned long long cl = g_fly.client;
            unsigned int scale = (unsigned int)g_fly.scale10;
            buf[0] = 1;
            buf[1] = (char)g_fly.on;
            buf[2] = (char)g_fly.mode;
            buf[3] = (char)err;
            memcpy(buf + 4, &z, 4);
            memcpy(buf + 8, &tz, 4);
            memcpy(buf + 12, &bz, 4);
            memcpy(buf + 16, &ticks, 4);
            memcpy(buf + 20, &hp, 4);
            memcpy(buf + 24, &cl, 8);
            memcpy(buf + 32, &scale, 4);
            if (!send_all(c, buf, 36)) break;
        } else if (op == 34) {                           /* FLY_CLR */
            InterlockedExchange(&g_fly.on, 0);
            Sleep(15);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 35) {                           /* FLY_NUDGE: f32 dz */
            float dz;
            if (!recv_all(c, (char *)&dz, 4)) break;
            fly_ensure();
            g_fly.nudge_dz = dz;
            InterlockedExchange(&g_fly.nudge, 1);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 36) {                           /* AIM_SET */
            unsigned char en, hold;
            unsigned int vk, cone10, maxd, team;
            float hdz;
            if (!recv_all(c, (char *)&en, 1)) break;
            if (!recv_all(c, (char *)&hold, 1)) break;
            if (!recv_all(c, (char *)&vk, 4)) break;
            if (!recv_all(c, (char *)&cone10, 4)) break;
            if (!recv_all(c, (char *)&maxd, 4)) break;
            if (!recv_all(c, (char *)&team, 4)) break;
            if (!recv_all(c, (char *)&hdz, 4)) break;
            g_aim.hold = hold ? 1 : 0;
            g_aim.vk = (LONG)vk;
            if (cone10 < 5) cone10 = 5;
            if (cone10 > 900) cone10 = 900;
            g_aim.cone10 = (LONG)cone10;
            if (maxd < 100) maxd = 100;
            g_aim.max_dist = (LONG)maxd;
            g_aim.team_excl = (LONG)team;
            if (hdz < 0.0f) hdz = 0.0f;
            if (hdz > 120.0f) hdz = 120.0f;
            g_aim.head_dz = hdz;
            aim_ensure();
            if (!en) g_aim.calib = 0;
            InterlockedExchange(&g_aim.on, en ? 1 : 0);
            logf_("aim_set on=%u hold=%u vk=%u cone=%.1f maxd=%u team=%u hdz=%.1f",
                  en, hold, vk, cone10 / 10.0, maxd, team, hdz);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 37) {                           /* AIM_GET */
            aim_ensure();
            int slot = (int)g_aim.slot, hp = (int)g_aim.hp;
            float d = g_aim.dist, eyv = g_aim.err_yaw, epv = g_aim.err_pitch;
            float gx = g_aim.gain_x, gy = g_aim.gain_y;
            int ticks = (int)g_aim.ticks, err = (int)g_aim.err;
            buf[0] = 1;
            buf[1] = (char)g_aim.on;
            buf[2] = (char)g_aim.calib;
            buf[3] = (char)g_aim.has_tgt;
            memcpy(buf + 4, &slot, 4);
            memcpy(buf + 8, &hp, 4);
            memcpy(buf + 12, &d, 4);
            memcpy(buf + 16, &eyv, 4);
            memcpy(buf + 20, &epv, 4);
            memcpy(buf + 24, &gx, 4);
            memcpy(buf + 28, &gy, 4);
            memcpy(buf + 32, &ticks, 4);
            memcpy(buf + 36, &err, 4);
            if (!send_all(c, buf, 40)) break;
        } else if (op == 38) {                           /* AIM_CLR */
            InterlockedExchange(&g_aim.on, 0);
            g_aim.calib = 0;
            Sleep(15);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 39) {                           /* AIM_MOUSE: i32 dx, i32 dy 调试注入 */
            int dx, dy;
            if (!recv_all(c, (char *)&dx, 4)) break;
            if (!recv_all(c, (char *)&dy, 4)) break;
            if (dx < -400) dx = -400;
            if (dx > 400) dx = 400;
            if (dy < -400) dy = -400;
            if (dy > 400) dy = 400;
            if (aim_foreground_ok() && (dx || dy)) aim_send(dx, dy);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 40) {                           /* AIM_BTN: u8 btn(1左/2右), u8 down */
            unsigned char bb[2];
            if (!recv_all(c, (char *)bb, 2)) break;
            if (aim_foreground_ok()) aim_button(bb[0], bb[1]);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 41) {                           /* AIM_CFG: 4×u32 间隔/力度/平滑/提前量 */
            unsigned int iv, st, sm, ld;
            if (!recv_all(c, (char *)&iv, 4)) break;
            if (!recv_all(c, (char *)&st, 4)) break;
            if (!recv_all(c, (char *)&sm, 4)) break;
            if (!recv_all(c, (char *)&ld, 4)) break;
            if (iv < 4) iv = 4;
            if (iv > 100) iv = 100;
            if (st < 10) st = 10;
            if (st > 100) st = 100;
            if (sm > 90) sm = 90;
            if (ld > 200) ld = 200;
            g_aim_interval = (LONG)iv;
            g_aim_strength = (LONG)st;
            g_aim_smooth = (LONG)sm;
            g_aim_lead = (LONG)ld;
            logf_("aim_cfg interval=%u strength=%u smooth=%u lead=%u", iv, st, sm, ld);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 42) {                           /* AIM_CHAIN: u32 on, u32 radius */
            unsigned int on, rad;
            if (!recv_all(c, (char *)&on, 4)) break;
            if (!recv_all(c, (char *)&rad, 4)) break;
            if (rad < 50) rad = 50;
            if (rad > 5000) rad = 5000;
            g_chain_on = on ? 1 : 0;
            g_chain_radius = (LONG)rad;
            logf_("aim_chain on=%u radius=%u", on, rad);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 43) {                           /* VAC_SET: 7×u32 */
            unsigned int vals[7];
            int ok = 1;
            for (int i = 0; i < 7; i++)
                if (!recv_all(c, (char *)&vals[i], 4)) { ok = 0; break; }
            if (!ok) break;
            unsigned int on = vals[0], dist = vals[1], up = vals[2], ring = vals[3];
            unsigned int team = vals[4], only = vals[5], flags = vals[6];
            if (dist < 50) dist = 50;
            if (dist > 2000) dist = 2000;
            if (up > 500) up = 500;
            if ((int)up < -200) up = (unsigned int)-200;
            if (ring > 500) ring = 500;
            if (team >= 32) team = 32;
            if (only >= 32) only = 0;
            if (flags > 7) flags = 7;
            g_vac_dist = (LONG)dist;
            g_vac_up = (int)up;
            g_vac_ring = (LONG)ring;
            g_vac_team = (LONG)team;
            g_vac_team_only = (LONG)only;
            g_vac_flags = (LONG)flags;
            vac_ensure();
            InterlockedExchange(&g_vac_on, on ? 1 : 0);
            logf_("vac_set on=%u dist=%ucm up=%dcm ring=%ucm excl=%u only=%u flags=%u",
                  on, dist, (int)up, ring, team, only, flags);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 44) {                           /* VAC_GET */
            vac_ensure();
            int ticks = (int)g_vac_ticks, n = (int)g_vac_n, wr = (int)g_vac_writes;
            float dr = g_vac_drift, he = g_vac_headerr;
            unsigned int dist = (unsigned int)g_vac_dist, flags = (unsigned int)g_vac_flags;
            buf[0] = 1;
            buf[1] = (char)g_vac_on;
            memcpy(buf + 4, &ticks, 4);
            memcpy(buf + 8, &n, 4);
            memcpy(buf + 12, &wr, 4);
            memcpy(buf + 16, &dr, 4);
            memcpy(buf + 20, &he, 4);
            memcpy(buf + 24, &dist, 4);
            memcpy(buf + 28, &flags, 4);
            if (!send_all(c, buf, 32)) break;
        } else if (op == 45) {                           /* TEAM_CFG: auto, extra_mask, manual, resample */
            unsigned int tv[4];
            int ok = 1;
            for (int i = 0; i < 4; i++)
                if (!recv_all(c, (char *)&tv[i], 4)) { ok = 0; break; }
            if (!ok) break;
            g_team_auto = tv[0] ? 1 : 0;
            g_team_extra_mask = (LONG)tv[1];
            if (tv[2] >= 1 && tv[2] < 32) {
                g_team_friendly = (LONG)tv[2];
                g_team_state = 2;
            } else if (tv[2] == 0 && !g_team_auto) {
                g_team_state = 0;
            }
            if (tv[3]) InterlockedExchange(&g_team_resample, 1);
            team_ensure();
            logf_("team_cfg auto=%u mask=%#x manual=%u resample=%u",
                  tv[0], tv[1], tv[2], tv[3]);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 46) {                           /* TEAM_GET */
            team_ensure();
            int ft = (int)g_team_friendly;
            unsigned int mask = (unsigned int)g_team_extra_mask;
            int samples = (int)g_team_samples, ticks = (int)g_team_ticks;
            buf[0] = 1;
            buf[1] = (char)g_team_auto;
            buf[2] = (char)g_team_state;
            memcpy(buf + 4, &ft, 4);
            memcpy(buf + 8, &mask, 4);
            memcpy(buf + 12, &samples, 4);
            memcpy(buf + 16, &ticks, 4);
            if (!send_all(c, buf, 20)) break;
        } else if (op == 27) {                           /* HOOK_ENTER: fn, patch_len, filter */
            unsigned long long fn;
            unsigned int patch_len, filter;
            if (!recv_all(c, (char *)&fn, 8)) break;
            if (!recv_all(c, (char *)&patch_len, 4)) break;
            if (!recv_all(c, (char *)&filter, 4)) break;
            int ok = 0;
            if (patch_len < 5 || patch_len > 12) patch_len = 7;
            if (!g_hk_page) {
                unsigned long long hint = fn & ~0xFFFFULL;
                for (unsigned long long dlt = 0x10000; dlt < 0x30000000ULL && !g_hk_page; dlt += 0x10000) {
                    g_hk_page = (unsigned char *)VirtualAlloc((LPVOID)(uintptr_t)(hint + dlt), 0x1000,
                                                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (!g_hk_page)
                        g_hk_page = (unsigned char *)VirtualAlloc((LPVOID)(uintptr_t)(hint - dlt), 0x1000,
                                                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                }
                if (g_hk_page) g_hk_slot = (uint64_t *)(g_hk_page + 0x800);
            }
            if (g_hk_page && g_hk_slot) {
                unsigned char *s2 = g_hk_page;
                uint64_t *sl = g_hk_slot;
                int o = 0;
                if (filter != 0xFFFFFFFFu) {
                    /* 按 ecx 低16位过滤 */
                    s2[o++] = 0x89; s2[o++] = 0xC8;
                    s2[o++] = 0x25; s2[o++] = 0xFF; s2[o++] = 0xFF; s2[o++] = 0x00; s2[o++] = 0x00;
                    s2[o++] = 0x3D; memcpy(s2 + o, &filter, 4); o += 4;
                    s2[o++] = 0x75; s2[o++] = 0x1C;   /* 跳过 3 个 store + inc = 28 字节 */
                }
                for (int k = 0; k < 3; k++) {
                    unsigned char rr[3] = { 0x35, 0x0D, 0x15 };   /* rsi, rcx, rdx */
                    s2[o++] = 0x48; s2[o++] = 0x89; s2[o++] = rr[k];
                    int32_t d = (int32_t)((uint64_t)(sl + k) - (uint64_t)(s2 + o + 4));
                    memcpy(s2 + o, &d, 4); o += 4;
                }
                s2[o++] = 0x48; s2[o++] = 0xFF; s2[o++] = 0x05;   /* inc qword [slot+3] */
                int32_t d4 = (int32_t)((uint64_t)(sl + 3) - (uint64_t)(s2 + o + 4));
                memcpy(s2 + o, &d4, 4); o += 4;
                /* 原样搬运被覆盖的前 patch_len 字节（必须是完整指令） */
                memcpy(s2 + o, (void *)(uintptr_t)fn, patch_len); o += patch_len;
                s2[o++] = 0x48; s2[o++] = 0xB8;                   /* mov rax, fn+patch_len */
                uint64_t resume = fn + patch_len;
                memcpy(s2 + o, &resume, 8); o += 8;
                s2[o++] = 0xFF; s2[o++] = 0xE0;                   /* jmp rax */

                g_hk_site = (unsigned char *)(uintptr_t)fn;
                memcpy(g_hk_orig, g_hk_site, patch_len);
                g_hk_patch = patch_len;
                DWORD old;
                if (VirtualProtect(g_hk_site, patch_len, PAGE_EXECUTE_READWRITE, &old)) {
                    g_hk_site[0] = 0xE9;
                    int32_t r2 = (int32_t)((uint64_t)s2 - ((uint64_t)g_hk_site + 5));
                    memcpy(g_hk_site + 1, &r2, 4);
                    for (unsigned int z = 5; z < patch_len; z++) g_hk_site[z] = 0x90;
                    VirtualProtect(g_hk_site, patch_len, old, &old);
                    InterlockedExchange(&g_hk_active, 1);
                    ok = 1;
                    logf_("hook_enter fn=0x%llx len=%u filter=%u", fn, patch_len, filter);
                }
            }
            buf[0] = (char)ok;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 25) {                           /* HOOK_GET: rsi, rcx, rdx */
            char *w = buf + 1;
            EnterCriticalSection(&g_scan_cs);
            for (int k = 0; k < 4; k++) {
                uint64_t v = g_hk_slot ? g_hk_slot[k] : 0;
                memcpy(w, &v, 8); w += 8;
            }
            LeaveCriticalSection(&g_scan_cs);
            buf[0] = 1;
            if (!send_all(c, buf, 33)) break;
        } else if (op == 26) {                           /* HOOK_CLR */
            if (g_hk_site) {
                DWORD old;
                unsigned int len = g_hk_patch ? g_hk_patch : 8;
                if (VirtualProtect(g_hk_site, len, PAGE_EXECUTE_READWRITE, &old)) {
                    memcpy(g_hk_site, g_hk_orig, len);
                    VirtualProtect(g_hk_site, len, old, &old);
                }
            }
            InterlockedExchange(&g_hk_active, 0);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 28) {                           /* ENV: PEB + ImageBase */
            char *w = buf + 1;
            uint64_t peb = (uint64_t)__readgsqword(0x60);
            uint64_t ib = (uint64_t)(uintptr_t)GetModuleHandleA(NULL);
            memcpy(w, &peb, 8); memcpy(w + 8, &ib, 8);
            buf[0] = 1;
            if (!send_all(c, buf, 17)) break;
        } else if (op == 22) {                           /* BP_SW_SET: INT3 软件断点 */
            unsigned long long addr;
            if (!recv_all(c, (char *)&addr, 8)) break;
            if (!g_veh) {
                g_veh = AddVectoredExceptionHandler(1, bp_handler);
                mod_info();
            }
            int ok = 0;
            unsigned char *p2 = (unsigned char *)(uintptr_t)addr;
            DWORD old;
            if (VirtualProtect(p2, 1, PAGE_EXECUTE_READWRITE, &old)) {
                g_sw_addr = p2;
                g_sw_oldprot = old;
                g_sw_orig = *p2;
                g_hw_hits = 0;
                InterlockedExchange(&g_sw_pending, 0);
                InterlockedExchange(&g_sw_active, 1);   /* 必须先激活再写 0xCC */
                *p2 = 0xCC;
                ok = 1;
                logf_("sw_bp 0x%llx orig=%02X", addr, g_sw_orig);
            }
            buf[0] = (char)ok;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 23) {                           /* BP_SW_CLR */
            InterlockedExchange(&g_sw_active, 0);
            for (int i = 0; i < 50 && g_sw_pending; i++) Sleep(1);   /* 等单步收尾 */
            Sleep(2);
            if (g_sw_addr) {
                DWORD old;
                *g_sw_addr = g_sw_orig;
                VirtualProtect(g_sw_addr, 1, g_sw_oldprot, &old);
            }
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 21) {                           /* BP_HW_EXEC: 执行断点 */
            unsigned long long addr;
            if (!recv_all(c, (char *)&addr, 8)) break;
            if (!g_veh) {
                g_veh = AddVectoredExceptionHandler(1, bp_handler);
                mod_info();
            }
            g_hw_addr = addr;
            g_hw_hits = 0;
            InterlockedExchange(&g_hw_exec, 1);
            InterlockedExchange(&g_hw_active, 1);
            hw_set_all(1, addr);
            HANDLE t = CreateThread(NULL, 0, hw_rearm, NULL, 0, NULL);
            if (t) CloseHandle(t);
            logf_("hw_exec 0x%llx", addr);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 20) {                           /* BP_HW_CLR */
            hw_set_all(0, 0);                            /* 先清 DR，再关 active */
            Sleep(5);
            InterlockedExchange(&g_hw_active, 0);
            InterlockedExchange(&g_hw_exec, 0);
            buf[0] = 1;
            if (!send_all(c, buf, 1)) break;
        } else if (op == 12) {                           /* SCAN_WRITE: 给所有候选写同一个值 */
            unsigned int dsize;
            uint64_t raw;
            if (!recv_all(c, (char *)&dsize, 4)) break;
            if (!recv_all(c, (char *)&raw, 8)) break;
            if (dsize != 1 && dsize != 2 && dsize != 4 && dsize != 8) dsize = 4;
            unsigned int written = 0;
            EnterCriticalSection(&g_scan_cs);
            for (uint32_t i = 0; i < g_count; i++) {
                SIZE_T w = 0;
                if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)(uintptr_t)g_addrs[i], &raw, dsize, &w) && w == dsize)
                    written++;
            }
            LeaveCriticalSection(&g_scan_cs);
            buf[0] = 1;
            memcpy(buf + 1, &written, 4);
            if (!send_all(c, buf, 5)) break;
        } else {
            break;
        }
    }
}

typedef struct { SOCKET s; } client_ctx;

static DWORD WINAPI client_thread(LPVOID p)
{
    client_ctx *ctx = (client_ctx *)p;
    SOCKET c = ctx->s;
    HeapFree(GetProcessHeap(), 0, ctx);

    /* 每个连接独立缓冲区：共享 static 缓冲会被并发客户端互相污染，
       一旦某个客户端卡住，别的连接会收到错位的回复（表现为"连接超时"） */
    char *buf = (char *)HeapAlloc(GetProcessHeap(), 0, MAX_XFER + 64);
    if (buf) {
        /* 30 s 收包超时：客户端异常消失时让线程自己退出，不再永久占坑 */
        DWORD tv = 30000;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
        logf_("客户端接入");
        handle_client(c, buf);
        HeapFree(GetProcessHeap(), 0, buf);
    }
    closesocket(c);
    logf_("客户端断开");
    return 0;
}

/* 端口可被环境变量覆盖：便于同机多个进程实例并存调试 */
static int agent_port(void)
{
    char b[16];
    DWORD n = GetEnvironmentVariableA("CODTOOL_AGENT_PORT", b, sizeof(b));
    if (n > 0 && n < sizeof(b)) {
        int p = atoi(b);
        if (p > 0 && p < 65536) return p;
    }
    return AGENT_PORT;
}

static DWORD WINAPI server_thread(LPVOID param)
{
    (void)param;
    int port = agent_port();
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { logf_("WSAStartup 失败"); return 0; }

    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) { logf_("socket 失败 %d", WSAGetLastError()); return 0; }

    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((u_short)port);
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        logf_("bind %d 失败（端口被占用？）", port);
        closesocket(srv);
        return 0;
    }
    if (listen(srv, 8) != 0) { logf_("listen 失败"); closesocket(srv); return 0; }
    logf_("agent v2 监听 127.0.0.1:%d pid=%u", port, GetCurrentProcessId());

    for (;;) {
        SOCKET c = accept(srv, NULL, NULL);
        if (c == INVALID_SOCKET) { Sleep(100); continue; }
        client_ctx *ctx = (client_ctx *)HeapAlloc(GetProcessHeap(), 0, sizeof(client_ctx));
        if (!ctx) { closesocket(c); continue; }
        ctx->s = c;
        HANDLE t = CreateThread(NULL, 0, client_thread, ctx, 0, NULL);
        if (t) CloseHandle(t);
        else { closesocket(c); HeapFree(GetProcessHeap(), 0, ctx); }
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        InitializeCriticalSection(&g_log_cs);
        InitializeCriticalSection(&g_scan_cs);
        proxy_resolve();
        HANDLE t = CreateThread(NULL, 0, server_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
        logf_("proxy v2 已载入, 导出 %d 个", g_tbl_count);
    }
    return TRUE;
}
