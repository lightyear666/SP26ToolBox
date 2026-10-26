"""god6：按"目标地址"判定，而不是按"受害者指针"。

前五处跳板都靠 `cmp 受害者寄存器, [g_entities]` 来认玩家，全部无效。本版换判据：
在写入点比较**即将写入的地址**是不是 `g_entities[0]+0x1E0` —— 这正是哨兵试验证实的权威血量地址，
与"代码以为自己在处理哪个实体"无关。

补丁点 0x14712800D（`sub_147126A10` 内）：
    原作  89 84 24 94 00 00 00      mov [rsp+94h], eax      ; eax = 旧血量-伤害（伤害量）
    之后  0x147128026 sub eax,[rsp+94h] -> 0x14712802D mov [rsi+1E0h], eax
所以把"落到玩家血量上的那份伤害量"置 0，就等价于玩家不吃伤害；AI 走同一条路径时
判据不成立，原值照写，行为不变。

跳板（39 字节，洞 slot0）：
    48 8B 05 rel32          mov  rax, cs:[g_entities]
    48 05 E0 01 00 00       add  rax, 1E0h
    48 8D 96 E0 01 00 00    lea  rdx, [rsi+1E0h]
    48 39 C2                cmp  rdx, rax
    75 02                   jne  +2
    31 C0                   xor  eax, eax          ; 玩家：伤害置 0
    89 84 24 94 00 00 00    mov  [rsp+94h], eax    ; 原存储（两条路共用）
    E9 rel32                jmp  0x147128014

写前落档、写后回读，不一致自动回滚。只写合法指令字节。

用法：
  python sp26_god6.py on       打补丁
  python sp26_god6.py off      还原
  python sp26_god6.py status   只看字节
"""
import struct
import sys
import traceback

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

import sp26_patch as P

NAME = 'god6'
SITE_RVA = 0x712800D
ORIG = bytes.fromhex('89842494000000')   # 7 字节
RESUME_RVA = 0x7128014
CAVE_RVA = P.CAVE_RVA                     # 0xCA3455C
STATE = P.STATE


def build(base):
    site = base + SITE_RVA
    cave = base + CAVE_RVA
    out = bytearray()
    out += b'\x48\x8B\x05' + struct.pack('<i', (base + P.GENT_RVA) - (cave + 7))
    out += b'\x48\x05\xE0\x01\x00\x00'
    out += b'\x48\x8D\x96\xE0\x01\x00\x00'
    out += b'\x48\x39\xC2'
    out += b'\x75\x02'
    out += b'\x31\xC0'
    out += ORIG
    out += P.jmp_rel32(cave + len(out), base + RESUME_RVA)
    patch = P.jmp_rel32(site, cave) + b'\x90' * (len(ORIG) - 5)
    return site, cave, patch, bytes(out)


def cmd_on():
    agent, base, pid = P.connect()
    st = P.prune_stale(P.load_state(), base, 'god6')
    site, cave, patch, code = build(base)
    cur = agent.read(site, len(ORIG))
    if cur == patch:
        print('god6 已生效，跳过')
        agent.close()
        return 0
    if cur != ORIG:
        print(f'!! 站点 0x{site:X} 当前={cur.hex()} 非原始字节，先 off')
        agent.close()
        return 2
    if agent.read(cave, len(code)) != bytes([0xCC]) * len(code):
        print(f'!! 洞 0x{cave:X} 已被占用')
        agent.close()
        return 2
    ok = P.apply(agent, NAME, [(cave, code), (site, patch)], st, base)
    agent.close()
    return 0 if ok else 2


def cmd_off():
    agent, base, pid = P.connect()
    st = P.load_state()
    if NAME not in st:
        print('无 god6 存档')
        agent.close()
        return 0
    for addr, oh in st[NAME]:
        o = bytes.fromhex(oh)
        agent.write(addr, o)
        back = agent.read(addr, len(o))
        print(f'  还原 0x{addr:X} <- {o.hex()} 回读 {"一致" if back == o else "不一致!!"}')
    st.pop(NAME)
    P.save_state(st)
    agent.close()
    return 0


def cmd_status():
    agent, base, pid = P.connect()
    site, cave, patch, code = build(base)
    cur = agent.read(site, len(ORIG))
    cd = agent.read(cave, len(code))
    tag = '已生效' if cur == patch and cd == code else ('原始' if cur == ORIG else '其他:' + cur.hex())
    print(f'god6 站点 0x{site:X} {cur.hex()}  {tag}')
    print(f'     洞 0x{cave:X} {cd.hex()}')
    print(f'     期望洞 {code.hex()}')
    print(f'     存档 {sorted(k for k in P.load_state() if k != "_base")}')
    agent.close()
    return 0


if __name__ == '__main__':
    try:
        c = sys.argv[1] if len(sys.argv) > 1 else 'status'
        sys.exit({'on': cmd_on, 'off': cmd_off, 'status': cmd_status}[c]())
    except Exception:
        traceback.print_exc()
        sys.exit(2)
