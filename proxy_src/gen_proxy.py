"""生成代理 DLL 的配套文件：stubs.S / table.c / exports.def。

每个导出都是一个 6 字节跳板：
        jmp *p_Name(%rip)
指针槽在 DllMain 里被填成 steam_api64_GSE.dll 的真实地址。
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_names(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        names = [ln.strip() for ln in f if ln.strip()]
    bad = [n for n in names if not all(c.isalnum() or c == "_" for c in n)]
    if bad:
        raise SystemExit(f"非法标识符: {bad[:5]}")
    if len(set(names)) != len(names):
        raise SystemExit("导出名有重复")
    return names


def gen(names: list[str], out_dir: str, target: str = "steam_api64_GSE.dll"):
    # 1) stubs.S
    s = [".text"]
    for n in names:
        s.append(f".globl {n}")
        s.append(f".p2align 4")
        s.append(f"{n}:")
        s.append(f"\tjmp *p_{n}(%rip)")
    s.append(".data")
    for n in names:
        s.append(f".globl p_{n}")
        s.append(f".p2align 3")
        s.append(f"p_{n}: .quad 0")
    s.append('.section .rdata,"dr"')
    s.append(".globl g_target_name")
    s.append("g_target_name:")
    s.append(f'    .asciz "{target}"')
    open(os.path.join(out_dir, "stubs.S"), "w", encoding="utf-8").write("\n".join(s) + "\n")

    # 2) table.c
    c = ["/* 自动生成，勿手改 */",
         "#include <windows.h>",
         "typedef struct { const char *name; void **slot; } proxy_entry;",
         "extern void proxy_null_stub(void);",
         "extern const char g_target_name[];"]
    for n in names:
        c.append(f"extern void *p_{n};")
    c.append("proxy_entry g_tbl[] = {")
    for n in names:
        c.append(f'    {{"{n}", &p_{n}}},')
    c.append("};")
    c.append("int g_tbl_count = (int)(sizeof(g_tbl)/sizeof(g_tbl[0]));")
    c.append("""
void proxy_resolve(void)
{
    HMODULE h = LoadLibraryA(g_target_name);
    int ok = 0;
    for (int i = 0; i < g_tbl_count; i++) {
        FARPROC f = h ? GetProcAddress(h, g_tbl[i].name) : NULL;
        if (f) { *g_tbl[i].slot = (void *)f; ok++; }
        else   { *g_tbl[i].slot = (void *)&proxy_null_stub; }
    }
    if (!h) {
        /* 目标 DLL 不在，全部落空桩，但仍然让进程活着 */
        for (int i = 0; i < g_tbl_count; i++)
            *g_tbl[i].slot = (void *)&proxy_null_stub;
    }
}
""")
    open(os.path.join(out_dir, "table.c"), "w", encoding="utf-8").write("\n".join(c))

    # 3) exports.def
    d = ["LIBRARY steam_api64", "EXPORTS"]
    d += [f"    {n}" for n in names]
    open(os.path.join(out_dir, "exports.def"), "w", encoding="utf-8").write("\n".join(d) + "\n")

    return len(names)


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "exports.txt")
    target = sys.argv[2] if len(sys.argv) > 2 else "steam_api64_real.dll"
    names = load_names(src)
    n = gen(names, HERE, target=target)
    print(f"生成 {n} 个导出跳板 -> stubs.S / table.c / exports.def  (转发目标 {target})")
