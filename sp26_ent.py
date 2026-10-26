"""枚举 g_entities 数组：gentity = [img+0xF7C0E88] + 2000 * entNum（由 sub_146DC5740 证实）。

只读。用于拿到玩家/敌人的 3D 坐标与血量等属性。
用法：
    python sp26_ent.py list [最大槽数]     列出所有看起来在用的实体
    python sp26_ent.py watch [秒数]        持续打印玩家与最近敌人坐标
"""
import math
import os
import struct
import sys
import time
import traceback

sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ammo_probe

ENT_ARRAY_RVA = 0xF7C0E88
ENT_COUNT_RVA = 0xF6FB300
STRIDE = 0x7D0
HEAD = 0x1E8            # 读到 maxHealth 之后
O_NUM = 0x00
O_F10 = 0x10
O_FLAG12 = 0x12
O_F18 = 0x18
O_ORIG_A = 0x24         # 三组互相镜像的 xyz 副本
O_ORIG_B = 0x140
O_ORIG_C = 0x158
O_PTR178 = 0x178
O_PTR180 = 0x180
O_HEALTH = 0x1E0
O_MAXHP = 0x1E4


def connect():
    agent, proc = ammo_probe.connect_readonly(ammo_probe.TOOLKIT, 49700)
    b = proc['module_base']
    base = struct.unpack('<Q', agent.read(b + ENT_ARRAY_RVA, 8))[0]
    cnt = struct.unpack('<i', agent.read(b + ENT_COUNT_RVA, 4))[0]
    return agent, b, base, cnt


def xyz(d, off):
    try:
        x, y, z = struct.unpack_from('<fff', d, off)
    except struct.error:
        return None
    for v in (x, y, z):
        if math.isnan(v) or math.isinf(v) or abs(v) > 1e7:
            return None
    return (x, y, z)


def parse(idx, d):
    """返回 (记录 dict 或 None)。None 表示该槽不像有效实体。"""
    if not d or len(d) < HEAD:
        return None
    hp = struct.unpack_from('<i', d, O_HEALTH)[0]
    mx = struct.unpack_from('<i', d, O_MAXHP)[0]
    o_a = xyz(d, O_ORIG_A)
    o_b = xyz(d, O_ORIG_B)
    if not (-20000 <= hp <= 200000) or o_a is None or o_b is None:
        return None
    if hp == 0 and o_a == (0.0, 0.0, 0.0) and o_b == (0.0, 0.0, 0.0):
        return None
    return {
        'idx': idx, 'hp': hp, 'max': mx,
        'num': struct.unpack_from('<i', d, O_NUM)[0],
        'f10': struct.unpack_from('<I', d, O_F10)[0],
        'b12': d[O_FLAG12],
        'f18': struct.unpack_from('<i', d, O_F18)[0],
        'p178': struct.unpack_from('<Q', d, O_PTR178)[0],
        'p180': struct.unpack_from('<Q', d, O_PTR180)[0],
        'a': o_a, 'b': o_b, 'c': xyz(d, O_ORIG_C),
    }


def read_slots(agent, base, n):
    """一次性读大块再本地切分，减少往返。"""
    out = []
    step = 128
    done = 0
    while done < n:
        k = min(step, n - done)
        blob = agent.read(base + done * STRIDE, k * STRIDE)
        if not blob:
            break
        for j in range(k):
            r = parse(done + j, blob[j * STRIDE:(j + 1) * STRIDE])
            if r:
                out.append(r)
        done += k
    return out


def dist(p, q):
    return math.sqrt(sum((a - b) ** 2 for a, b in zip(p, q)))


def fmt(r):
    return ('  槽%4d hp=%6d max=%6d num=%5d f10=0x%08X b12=0x%02X f18=%3d '
            'orig=(%9.2f,%9.2f,%9.2f) b=(%9.2f,%9.2f,%9.2f) p178=0x%X p180=0x%X'
            % (r['idx'], r['hp'], r['max'], r['num'], r['f10'], r['b12'], r['f18'],
               r['a'][0], r['a'][1], r['a'][2],
               r['b'][0], r['b'][1], r['b'][2], r['p178'], r['p180']))


def cmd_list(n):
    agent, b, base, cnt = connect()
    print(f'base=0x{b:X} g_entities=0x{base:X} 计数全局={cnt}')
    rows = read_slots(agent, base, n)
    print(f'扫描 {n} 槽，命中 {len(rows)} 个疑似实体')
    pl = rows[0] if rows and rows[0]['idx'] == 0 else None
    for r in rows:
        tag = ''
        if pl and r['idx'] != 0:
            tag = '  距玩家 %.1f' % dist(pl['b'], r['b'])
        print(fmt(r) + tag)
    agent.close()


def cmd_watch(dur, n=2048):
    agent, b, base, cnt = connect()
    t0 = time.time()
    while time.time() - t0 < dur:
        rows = read_slots(agent, base, n)
        pl = next((r for r in rows if r['idx'] == 0), None)
        if pl is None:
            print('!! 玩家槽读不到')
            time.sleep(0.5)
            continue
        near = [r for r in rows if r['idx'] != 0 and 0 < r['hp'] <= 1000 and r['p180']]
        near.sort(key=lambda r: dist(pl['b'], r['b']))
        print('[%5.1fs] 玩家 hp=%d pos=(%.1f,%.1f,%.1f) 活体actor=%d'
              % (time.time() - t0, pl['hp'], pl['b'][0], pl['b'][1], pl['b'][2], len(near)))
        for r in near[:8]:
            print('    槽%-4d hp=%5d 距=%7.1f pos=(%.1f,%.1f,%.1f) 类=0x%X'
                  % (r['idx'], r['hp'], dist(pl['b'], r['b']),
                     r['b'][0], r['b'][1], r['b'][2], r['p180'] - b))
        time.sleep(0.5)
    agent.close()


def cmd_hp(n):
    """只列血量>0 的实体（AI/载具候选）。"""
    agent, b, base, cnt = connect()
    print(f'base=0x{b:X} g_entities=0x{base:X} 计数全局={cnt}')
    rows = [r for r in read_slots(agent, base, n) if r['hp'] > 0]
    pl = next((r for r in rows if r['idx'] == 0), None)
    print(f'血量>0 的实体 {len(rows)} 个（扫描 {n} 槽）')
    for r in sorted(rows, key=lambda r: r['hp'], reverse=True):
        tag = ''
        if pl and r['idx'] != 0:
            tag = '  距玩家 %.1f' % dist(pl['b'], r['b'])
        print(fmt(r) + tag)
    agent.close()


def cmd_live(rounds, gap, n):
    """两轮采样比较 origin：会动的槽就是活着的 actor（AI/可动物体）。"""
    agent, b, base, cnt = connect()
    pl = None
    for k in range(rounds):
        t0 = time.time()
        a = {r['idx']: r for r in read_slots(agent, base, n)}
        time.sleep(max(0.0, gap - (time.time() - t0)))
        c = {r['idx']: r for r in read_slots(agent, base, n)}
        if pl is None:
            pl = c.get(0)
            print(f'玩家 槽0 hp={pl["hp"]} pos=({pl["b"][0]:.1f},{pl["b"][1]:.1f},{pl["b"][2]:.1f})')
        moved = []
        for i, r in c.items():
            q = a.get(i)
            if q is None:
                continue
            d = dist(q['b'], r['b'])
            if d > 1.0:
                moved.append((d, i, r))
        moved.sort(key=lambda t: -t[0])
        print(f'--- 第{k}轮 位移>1 的槽 {len(moved)} 个 ---')
        for d, i, r in moved[:25]:
            print('  槽%-5d 位移%8.1f hp=%6d pos=(%9.2f,%9.2f,%9.2f) 距玩家%8.1f'
                  % (i, d, r['hp'], r['b'][0], r['b'][1], r['b'][2],
                     dist(pl['b'], r['b']) if pl else -1))
    agent.close()


if __name__ == '__main__':
    try:
        mode = sys.argv[1] if len(sys.argv) > 1 else 'list'
        if mode == 'list':
            sys.exit(cmd_list(int(sys.argv[2]) if len(sys.argv) > 2 else 512))
        if mode == 'hp':
            sys.exit(cmd_hp(int(sys.argv[2]) if len(sys.argv) > 2 else 2048))
        if mode == 'live':
            sys.exit(cmd_live(int(sys.argv[2]) if len(sys.argv) > 2 else 3,
                              float(sys.argv[3]) if len(sys.argv) > 3 else 2.0,
                              int(sys.argv[4]) if len(sys.argv) > 4 else 2048))
        sys.exit(cmd_watch(float(sys.argv[2]) if len(sys.argv) > 2 else 20.0))
    except Exception:
        traceback.print_exc()
        sys.exit(2)
