"""SP26 代码补丁器（只写合法指令字节，不打任何断点、不动调试寄存器）。

god1/god2/god3/god4：四处真实扣血写入，全部改成"受害者 == g_entities[0]（本地玩家）时跳过扣血"
  god1  0x147005E86  sub [rsi+1E0h], edx     （该函数前面就解引用 [rsi+178h]，只有玩家能走到）
  god2  0x14AD7F011  sub [r15+1E0h], r13d   （原版在这里查 [gclient+0x3E21] 免伤标志，但本 build gclient 数组为 0）
  god3  0x147DF30E9  sub [rdi+1E0h], r12d   （sub_147DF3090，带存活/死亡分支的主路径）
  god4  0x14702A7FB  mov [rdi+1E0h], ecx    （读旧血量→寄存器中减伤害→回写；前三处实测漏掉的玩家伤害路径）
ammo：无限弹药（已验收，勿改）

代码洞：0x14CA3455C 起 164 字节 0xCC 对齐填充（不属任何函数、不可达），按 32 字节切片使用。

用法：
  python sp26_patch.py check          只读校验所有站点/代码洞/保护属性
  python sp26_patch.py status         各补丁是否生效
  python sp26_patch.py on god         打三处免伤跳板（已打的自动跳过）
  python sp26_patch.py on ammo        打弹药补丁
  python sp26_patch.py off god2       精确回滚一处
  python sp26_patch.py off all        全部回滚
"""
import json
import struct
import sys
import traceback

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

import ammo_probe

GENT_RVA = 0xF7C0E88                 # g_entities 基址全局；槽0 = 本地玩家
CAVE_RVA = 0xCA3455C                 # .text 内 164B 0xCC 填充，不属任何函数
CAVE_TOTAL = 164

# cmp 前缀按受害者寄存器编码：48 3B 3D=rdi  48 3B 35=rsi  49 3B 3D=r15
# 历史否证记录（勿再启用，代码保留在 GOD 之外）：
#   god1 0x7005E86 sub [rsi+1E0],edx / god2 0xAD7F011 sub [r15+1E0],r13d
#   god3 0x7DF30E9 sub [rdi+1E0],r12d / god4 0x702A7FB mov [rdi+1E0],ecx
#   god5 0x712802D mov [rsi+1E0],eax
# 五处"受害者==g_entities"条件跳板全部实测无效（玩家照旧掉血并死亡），
# 因为到达写入点时寄存器里不是玩家实体指针。定案改用按"目标地址"判定的 god6
# （见 sp26_god6.py）。这里清空，避免占用代码洞与 god6 冲突。
GOD = {}

AMMO_SCANNER_RVA = 0x12EF5B0
AMMO_ADDER_RVA = 0x33D1E30
AMMO_SCANNER_PATCH = bytes.fromhex('B8E7030000C3')
AMMO_ADDER_PATCH = bytes.fromhex('31C0C3')

STATE = 'sp26_patch_state.json'


def connect():
    agent, proc = ammo_probe.connect_readonly(ammo_probe.TOOLKIT, 49700)
    return agent, proc['module_base'], proc['pid']


def load_state():
    try:
        with open(STATE, 'r', encoding='utf-8') as f:
            st = json.load(f)
    except FileNotFoundError:
        st = {}
    if 'god' in st:                       # 旧键名迁移
        st.setdefault('god3', st.pop('god'))
        save_state(st)
    return st


def save_state(st):
    with open(STATE, 'w', encoding='utf-8') as f:
        json.dump(st, f, indent=1)


def jmp_rel32(frm, to):
    d = to - (frm + 5)
    if not -0x80000000 <= d <= 0x7FFFFFFF:
        raise ValueError('跳转超出 rel32 范围')
    return b'\xE9' + struct.pack('<i', d)


def build_god(base, cfg):
    site = base + cfg['site']
    cave = base + CAVE_RVA + cfg['slot']
    orig = bytes.fromhex(cfg['orig'])
    head = bytes.fromhex(cfg['head'])
    out = bytearray()
    out += head + struct.pack('<i', (base + GENT_RVA) - (cave + 7))   # cmp victim, cs:[g_entities]
    out += b'\x74' + bytes([len(orig)])                              # jz  -> 跳过扣血
    out += orig                                                      # 原扣血指令
    out += jmp_rel32(cave + len(out), base + cfg['resume'])           # jmp back
    patch = jmp_rel32(site, cave) + b'\x90' * (len(orig) - 5)
    return site, cave, bytes(patch), bytes(out), orig


def cmd_check():
    agent, base, pid = connect()
    g = struct.unpack('<Q', agent.read(base + GENT_RVA, 8))[0]
    print(f'PID={pid} base=0x{base:X} g_entities=0x{g:X}')
    cd = agent.read(base + CAVE_RVA, CAVE_TOTAL)
    print(f'代码洞 0x{base + CAVE_RVA:X} {CAVE_TOTAL}B 全为 CC: {cd == bytes([0xCC]) * CAVE_TOTAL}')
    for n, cfg in sorted(GOD.items()):
        site, cave, patch, caved, orig = build_god(base, cfg)
        cur = agent.read(site, len(orig))
        nxt = agent.read(base + cfg['resume'], 3)
        print(f'{n}: 站点0x{site:X}={cur.hex()} 期望{orig.hex()} '
              f'{"OK" if cur == orig else "已改/不符"}  返回点={nxt.hex()} 跳板{len(caved)}B')
        print(f'      站点补丁 {patch.hex()}  洞 {caved.hex()}')
    print(f'ammo scanner 0x{base + AMMO_SCANNER_RVA:X} = {agent.read(base + AMMO_SCANNER_RVA, 6).hex()}')
    print(f'ammo adder   0x{base + AMMO_ADDER_RVA:X} = {agent.read(base + AMMO_ADDER_RVA, 3).hex()}')
    agent.close()


def cmd_status():
    agent, base, pid = connect()
    for n, cfg in sorted(GOD.items()):
        site, cave, patch, caved, orig = build_god(base, cfg)
        cur = agent.read(site, len(patch))
        cd = agent.read(cave, len(caved))
        print(f'{n}: {"已生效" if cur == patch and cd == caved else "未生效"} 站点={cur.hex()} 洞={cd.hex()}')
    s1 = agent.read(base + AMMO_SCANNER_RVA, 6)
    s2 = agent.read(base + AMMO_ADDER_RVA, 3)
    print(f'ammo : {"已生效" if s1 == AMMO_SCANNER_PATCH and s2 == AMMO_ADDER_PATCH else "未生效"} '
          f'{s1.hex()} {s2.hex()}')
    st = load_state()
    print(f'存档 : {sorted(k for k in st if k != "_base")} 基址={st.get("_base")} 当前=0x{base:X}'
          + ('  <== 存档属于旧进程，会被自动丢弃' if st.get('_base') not in (None, hex(base)) else ''))
    agent.close()


def apply(agent, name, writes, st, base):
    """writes=[(addr,new)]；先存档原始字节再逐段写，任一步失败即整体回滚。

    存档必须带上当时的镜像基址：ASLR 下旧进程的绝对地址在新进程里是**任意地址**，
    拿它回滚等于往随机位置写字。
    """
    segs = []
    for addr, new in writes:
        orig = agent.read(addr, len(new))
        if orig is None or len(orig) != len(new):
            print(f'!! 0x{addr:X} 读不到原始字节，放弃')
            for a, o in segs:
                agent.write(a, o)
            return False
        segs.append((addr, orig))
    st[name] = [[s[0], s[1].hex()] for s in segs]
    st['_base'] = hex(base)
    save_state(st)
    for (addr, new), (_, orig) in zip(writes, segs):
        if not agent.write(addr, new):
            print(f'!! 0x{addr:X} 写入失败，回滚')
            for a, o in segs:
                agent.write(a, o)
            st.pop(name, None)
            save_state(st)
            return False
        back = agent.read(addr, len(new))
        if back != new:
            print(f'!! 0x{addr:X} 回读不一致（{back.hex()} != {new.hex()}），回滚')
            for a, o in segs:
                agent.write(a, o)
            st.pop(name, None)
            save_state(st)
            return False
        print(f'  0x{addr:X} <- {new.hex()} 回读一致')
    print(f'{name} 已生效')
    return True


def prune_stale(st, base, tag):
    """存档基址与当前进程不符（或压根没记基址）→ 旧进程已死，存档里的绝对地址在新进程里
    是任意地址，必须丢弃；拿它回滚等于往随机位置写字。"""
    archived = [k for k in st if k != '_base']
    if archived and st.get('_base') != hex(base):
        print(f'!! 存档基址 {st.get("_base")} != 当前 0x{base:X}（游戏重启过或存档过旧），'
              f'丢弃 {archived}，绝不拿旧地址回写')
        for k in archived:
            st.pop(k)
        st.pop('_base', None)
        save_state(st)
    return st


def cmd_on(what):
    agent, base, pid = connect()
    st = prune_stale(load_state(), base, 'on')
    if what == 'ammo':
        if (agent.read(base + AMMO_SCANNER_RVA, 6) == AMMO_SCANNER_PATCH
                and agent.read(base + AMMO_ADDER_RVA, 3) == AMMO_ADDER_PATCH):
            print('ammo 已生效')
            agent.close()
            return 0
        rc = 0 if apply(agent, 'ammo', [
            (base + AMMO_SCANNER_RVA, AMMO_SCANNER_PATCH),
            (base + AMMO_ADDER_RVA, AMMO_ADDER_PATCH)], st, base) else 2
        agent.close()
        return rc
    for n, cfg in sorted(GOD.items()):
        site, cave, patch, caved, orig = build_god(base, cfg)
        cur = agent.read(site, len(orig))
        if cur == patch[:len(orig)]:
            print(f'{n} 已生效，跳过')
            continue
        if cur != orig:
            print(f'!! {n} 站点当前={cur.hex()} 既不是原始也不是补丁，先 off all')
            continue
        if agent.read(cave, len(caved)) != bytes([0xCC]) * len(caved):
            print(f'!! {n} 代码洞 0x{cave:X} 已被占用：{agent.read(cave, len(caved)).hex()}')
            continue
        if n in st:
            print(f'!! {n} 有残留存档，先 off {n}')
            continue
        # 先写不可达的洞，再改站点
        apply(agent, n, [(cave, caved), (site, patch)], st, base)
    agent.close()
    return 0


def cmd_off(which):
    agent, base, pid = connect()
    st = prune_stale(load_state(), base, 'off')
    for n in (sorted(k for k in st if k != '_base') if which == 'all' else [which]):
        if n not in st:
            print(f'{n}: 无存档，跳过')
            continue
        for addr, oh in st[n]:
            o = bytes.fromhex(oh)
            agent.write(addr, o)
            back = agent.read(addr, len(o))
            print(f'  还原 0x{addr:X} <- {o.hex()} 回读 {"一致" if back == o else "不一致!!"}')
        st.pop(n)
        save_state(st)
    agent.close()
    return 0


if __name__ == '__main__':
    try:
        c = sys.argv[1] if len(sys.argv) > 1 else 'check'
        if c == 'check':
            sys.exit(cmd_check())
        if c == 'status':
            sys.exit(cmd_status())
        if c == 'on':
            sys.exit(cmd_on(sys.argv[2]))
        if c == 'off':
            sys.exit(cmd_off(sys.argv[2] if len(sys.argv) > 2 else 'all'))
        if c == 'god':
            sys.exit(cmd_on('god'))
        if c == 'ammo':
            sys.exit(cmd_on('ammo'))
        print(__doc__)
    except Exception:
        traceback.print_exc()
        sys.exit(2)
