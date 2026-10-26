from __future__ import annotations

import json
import math
import struct
import time
from pathlib import Path

RVA_G = 0xF7C0E88
RVA_SERVER_MAP = 0xF84BB90
RVA_PAGES = 0xE950CA0
STRIDE = 0x7D0
O_TYPE = 0x8
O_ORIGINS = (0x24, 0x140, 0x158)
O_HANDLE = 0x118
O_STATE = 0x178
O_EQUIP = 0x810
O_CURRENT = 0xCB4
O_AMMO = 0x1220
AMMO_STRIDE = 0x58
AMMO_COUNT = 18
O_WCACHE = 0xDA8
WCACHE_STRIDE = 0x48
WCACHE_COUNT = 16
REF_ARRAY = 4208
NONE_INDEX = 0x3FFFFF

DISPLAY_NAMES = {
    'rex_ar_kilo437': 'AXION',
}


class SpawnError(RuntimeError):
    pass


class Spawner:
    def __init__(self, read, write, module_base):
        self.read = read
        self.write = write
        self.module_base = module_base

    def _u16(self, addr):
        raw = self.read(addr, 2)
        return struct.unpack('<H', raw)[0] if raw and len(raw) == 2 else None

    def _i32(self, addr):
        raw = self.read(addr, 4)
        return struct.unpack('<i', raw)[0] if raw and len(raw) == 4 else None

    def _u64(self, addr):
        raw = self.read(addr, 8)
        return struct.unpack('<Q', raw)[0] if raw and len(raw) == 8 else None

    def _f32x3(self, addr):
        raw = self.read(addr, 12)
        return struct.unpack('<3f', raw) if raw and len(raw) == 12 else None

    def resolve(self):
        base = self.module_base
        if not base:
            raise SpawnError('缺少模块基址')
        g = self._u64(base + RVA_G)
        smap = self._u64(base + RVA_SERVER_MAP)
        if not g or not smap:
            raise SpawnError('实体/武器 map 未就绪')
        pool = self._u64(smap + 8)
        return base, g, smap, pool

    def page_name(self, base, page):
        cache = getattr(self, '_pages', None)
        if cache is None:
            cache = self._pages = {}
        if page in cache:
            return cache[page]
        name = '?'
        raw = self.read(base + RVA_PAGES + page * 8, 8)
        if raw and len(raw) == 8:
            ptr = struct.unpack('<Q', raw)[0]
            if 0x10000 <= ptr < 0x800000000000:
                np = self.read(ptr + 0x548, 8)
                if np and len(np) == 8:
                    nptr = struct.unpack('<Q', np)[0]
                    text = self.read(nptr, 64) if 0x10000 <= nptr < 0x800000000000 else None
                    if text:
                        end = text.find(b'\0')
                        if end > 0:
                            name = ''.join(chr(c) for c in text[:end] if 32 <= c < 127) or '?'
        cache[page] = name
        return name

    def decode_key(self, base, key):
        packed = struct.unpack_from('<I', key, 0x08)[0]
        page = (packed >> 10) & 0x7FF
        return {'page': page, 'name': self.page_name(base, page),
                'variant': struct.unpack_from('<I', key, 0x10)[0],
                'attachments': struct.unpack_from('<Q', key, 0x18)[0]}

    def refs(self, smap, handle):
        if self._i32(smap + 112) != 0:
            raw = self.read(smap + 116 + handle * 4, 4)
            return struct.unpack('<I', raw)[0] if raw and len(raw) == 4 else 0
        raw = self.read(smap + REF_ARRAY + handle * 2, 2)
        return struct.unpack('<H', raw)[0] if raw and len(raw) == 2 else 0

    def set_refs(self, smap, handle, value):
        if self._i32(smap + 112) != 0:
            return self.write(smap + 116 + handle * 4, struct.pack('<I', value))
        return self.write(smap + REF_ARRAY + handle * 2, struct.pack('<H', value))

    def entry_key(self, pool, handle):
        raw = self.read(pool + handle * 0x40, 0x40)
        if not raw or len(raw) != 0x40 or struct.unpack_from('<H', raw)[0] != handle:
            return None
        return raw[8:64]

    def armory(self):
        base, g, smap, pool = self.resolve()
        workers = self._i32(smap + 112) or 0
        rows = []
        blob = self.read(pool, 0x40 * 256)
        if workers:
            refs_blob = self.read(smap + 116, 4 * 256)
        else:
            refs_blob = self.read(smap + REF_ARRAY, 2 * 256)
        for handle in range(256):
            if blob and len(blob) == 0x40 * 256:
                entry = blob[handle * 0x40:(handle + 1) * 0x40]
                if struct.unpack_from('<H', entry)[0] != handle:
                    continue
                key = entry[8:64]
            else:
                key = self.entry_key(pool, handle)
                if key is None:
                    continue
            if workers:
                refs = struct.unpack_from('<I', refs_blob, handle * 4)[0] if refs_blob else 0
            else:
                refs = struct.unpack_from('<H', refs_blob, handle * 2)[0] if refs_blob else 0
            if refs <= 0:
                continue
            info = self.decode_key(base, key)
            rows.append({'handle': handle, 'refs': refs, 'key': key, **info,
                         'label': DISPLAY_NAMES.get(info['name'], info['name'])})
        rows.sort(key=lambda r: (r['name'], r['variant'], r['attachments']))
        return rows

    def player(self, g):
        ps = self._u64(g + O_STATE)
        if not ps:
            raise SpawnError('玩家状态未就绪')
        raw = self.read(ps + O_EQUIP, 30)
        equip = struct.unpack('<15H', raw) if raw and len(raw) == 30 else ()
        current = self._u16(ps + O_CURRENT)
        pos = self._f32x3(g + O_ORIGINS[0])
        return ps, equip, current, pos

    def slot_of(self, equip, handle):
        for i, h in enumerate(equip):
            if h == handle:
                return i
        return -1

    def current_slot(self, equip, current):
        idx = self.slot_of(equip, current)
        if idx >= 0:
            return idx
        for i, h in enumerate(equip):
            if not h:
                return i
        return 0

    def _type3_entities(self, base, g, near=None):
        out = []
        px, py, pz = (near or (0.0, 0.0, 0.0))
        size = 2048 * STRIDE
        blob = self.read(g, size)
        if blob and len(blob) == size:
            for idx in range(1, 2048):
                off = idx * STRIDE
                if struct.unpack_from('<H', blob, off + O_TYPE)[0] != 3:
                    continue
                handle = struct.unpack_from('<H', blob, off + O_HANDLE)[0]
                x, y, z = struct.unpack_from('<3f', blob, off + O_ORIGINS[0])
                dist = math.sqrt((x - px) ** 2 + (y - py) ** 2 + (z - pz) ** 2)
                out.append({'idx': idx, 'handle': handle, 'pos': (x, y, z), 'dist': dist})
            return out
        for idx in range(1, 2048):
            raw = self.read(g + idx * STRIDE, 0x120)
            if not raw or len(raw) < 0x120:
                continue
            if struct.unpack_from('<H', raw, O_TYPE)[0] != 3:
                continue
            handle = struct.unpack_from('<H', raw, O_HANDLE)[0]
            x, y, z = struct.unpack_from('<3f', raw, O_ORIGINS[0])
            dist = math.sqrt((x - px) ** 2 + (y - py) ** 2 + (z - pz) ** 2)
            out.append({'idx': idx, 'handle': handle, 'pos': (x, y, z), 'dist': dist})
        return out

    def pick_donor(self, base, g, target, near_pos):
        items = self._type3_entities(base, g, near_pos)
        if not items:
            raise SpawnError('没有可用的 type-3 供体')
        near = [e for e in items if e['dist'] < 200 and e['handle'] != target]
        if near:
            near.sort(key=lambda e: e['dist'])
            return near[0], items
        far = [e for e in items if e['handle'] != target]
        far.sort(key=lambda e: -e['dist'])
        if not far:
            raise SpawnError('没有空闲供体')
        return far[0], items

    def seed_ammo(self, ps, slot, key, mag, reserve):
        addr = ps + O_AMMO + slot * AMMO_STRIDE
        block = bytearray(AMMO_STRIDE)
        block[:56] = key
        struct.pack_into('<i', block, 0x40, 1)
        struct.pack_into('<i', block, 0x50, max(0, mag - 1))
        self.write(addr, bytes(block))
        return self.set_reserve(ps, key, reserve)

    def set_reserve(self, ps, key, reserve):
        packed = struct.unpack_from('<I', key, 0x08)[0]
        variant = struct.unpack_from('<I', key, 0x10)[0]
        att = struct.unpack_from('<Q', key, 0x18)[0]
        empty = None
        for i in range(WCACHE_COUNT):
            addr = ps + O_WCACHE + i * WCACHE_STRIDE
            raw = self.read(addr, WCACHE_STRIDE)
            if not raw or len(raw) != WCACHE_STRIDE:
                continue
            pk = struct.unpack_from('<I', raw, 0x00)[0]
            var = struct.unpack_from('<I', raw, 0x08)[0]
            at = struct.unpack_from('<Q', raw, 0x10)[0]
            if pk == packed and var == variant and at == att:
                self.write(addr + 0x38, struct.pack('<i', reserve))
                return 'matched'
            if empty is None and not any(raw):
                empty = addr
        if empty is not None:
            block = bytearray(WCACHE_STRIDE)
            struct.pack_into('<I', block, 0x00, packed)
            struct.pack_into('<I', block, 0x08, variant)
            struct.pack_into('<Q', block, 0x10, att)
            struct.pack_into('<i', block, 0x38, reserve)
            self.write(empty, bytes(block))
            return 'created'
        return 'missing'

    def spawn(self, handle, mag=30, reserve=210, timeout=30.0, donor_idx=None,
              place=None, cancel_event=None, progress=None):
        base, g, smap, pool = self.resolve()
        key = self.entry_key(pool, handle)
        if key is None:
            raise SpawnError(f'handle {handle} 不在武器 map 中')
        refs = self.refs(smap, handle)
        if refs <= 0:
            raise SpawnError(f'handle {handle} 无有效引用')
        ps, equip, current, pos = self.player(g)
        target_slot = self.current_slot(equip, current)
        if donor_idx is None:
            donor, _ = self.pick_donor(base, g, handle, pos)
        else:
            donor = {'idx': donor_idx, 'handle': self._u16(g + donor_idx * STRIDE + O_HANDLE),
                     'pos': self._f32x3(g + donor_idx * STRIDE + O_ORIGINS[0]), 'dist': 0.0}
        if donor['handle'] == handle:
            raise SpawnError('供体已经是目标武器，请换一把再试')
        ty = self._u16(g + donor['idx'] * STRIDE + O_TYPE)
        if ty != 3:
            raise SpawnError(f'供体实体类型异常：{ty}')
        donor_addr = g + donor['idx'] * STRIDE
        old_handle = self._u16(donor_addr + O_HANDLE)
        old_pos = self._f32x3(donor_addr + O_ORIGINS[0])
        if progress:
            progress(f"供体 idx={donor['idx']} h{old_handle} -> h{handle}，目标槽 {target_slot}")
        self.set_refs(smap, handle, refs + 1)
        self.write(donor_addr + O_HANDLE, struct.pack('<H', handle))
        at = place or (pos[0], pos[1], pos[2] + 0.5)
        for off in O_ORIGINS:
            self.write(donor_addr + off, struct.pack('<3f', *at))
        picked = False
        try:
            deadline = time.time() + timeout
            while time.time() < deadline:
                if cancel_event is not None and cancel_event.is_set():
                    break
                raw = self.read(ps + O_EQUIP, 30)
                if raw and len(raw) == 30:
                    eq = struct.unpack('<15H', raw)
                    if handle in eq:
                        picked = True
                        target_slot = eq.index(handle)
                        break
                time.sleep(0.25)
        finally:
            if not picked:
                self.write(donor_addr + O_HANDLE, struct.pack('<H', old_handle))
                if old_pos:
                    for off in O_ORIGINS:
                        self.write(donor_addr + off, struct.pack('<3f', *old_pos))
                self.set_refs(smap, handle, refs)
        if not picked:
            raise SpawnError('未检测到拾取，已还原供体')
        self.seed_ammo(ps, target_slot, key, mag, reserve)
        if progress:
            progress(f"已装备到槽 {target_slot}，弹药 {mag}/{reserve}")
        return {'handle': handle, 'slot': target_slot, 'name': self.decode_key(base, key)['name'],
                'mag': mag, 'reserve': reserve, 'donor': donor['idx']}

    def direct_equip(self, handle, mag=30, reserve=210, slot=None, progress=None):
        """无 type-3 供体时，绕过拾取直接把武器写入玩家当前槽。"""
        base, g, smap, pool = self.resolve()
        key = self.entry_key(pool, handle)
        if key is None:
            raise SpawnError(f'handle {handle} 不在武器 map 中')
        refs = self.refs(smap, handle)
        if refs <= 0:
            raise SpawnError(f'handle {handle} 无有效引用')
        ps, equip, current, pos = self.player(g)
        if slot is None:
            slot = self.current_slot(equip, current)
        if not (0 <= slot < 15):
            raise SpawnError(f'装备槽 {slot} 无效')
        try:
            backup = {
                'time': time.strftime('%F %T'), 'handle': handle, 'slot': slot,
                'ent_handle': self._u16(g + O_HANDLE),
                'equip': list(equip), 'current': current,
                'ammo': self.read(ps + O_AMMO, AMMO_COUNT * AMMO_STRIDE).hex(),
                'wcache': self.read(ps + O_WCACHE, WCACHE_COUNT * WCACHE_STRIDE).hex(),
                'refs': refs,
            }
            Path('sp26_direct_equip_backup.json').write_text(
                json.dumps(backup, indent=1), encoding='utf-8')
        except Exception:
            pass
        added = handle not in equip
        if added:
            self.set_refs(smap, handle, refs + 1)
        self.write(g + O_HANDLE, struct.pack('<H', handle))
        eqb = bytearray(30)
        struct.pack_into('<15H', eqb, 0, *equip)
        struct.pack_into('<H', eqb, slot * 2, handle)
        self.write(ps + O_EQUIP, bytes(eqb))
        self.write(ps + O_CURRENT, struct.pack('<H', handle))
        ammo_state = self.seed_ammo(ps, slot, key, mag, reserve)
        time.sleep(0.15)
        eq2 = struct.unpack('<15H', self.read(ps + O_EQUIP, 30))
        cur2 = self._u16(ps + O_CURRENT)
        verified = handle in eq2 and cur2 == handle
        name = self.decode_key(base, key)['name']
        if progress:
            progress(f"直接装备 {name} h{handle} 槽{slot} {mag}/{reserve} 校验={verified}")
        return {'handle': handle, 'slot': slot, 'name': name, 'mag': mag,
                'reserve': reserve, 'mode': 'direct', 'verified': verified,
                'ammo_state': ammo_state, 'refs_added': int(added)}

    def weapon_pages(self):
        base = self.module_base
        live = {r['page'] for r in self.armory()}
        out = []
        for page in range(0, 128):
            ptr = self._u64(base + RVA_PAGES + page * 8)
            if not ptr or not (0x10000 <= ptr < 0x800000000000):
                continue
            name = self.page_name(base, page)
            if not name.startswith('rex_') or 'fists' in name or name.startswith('rex_la_'):
                continue
            out.append({'page': page, 'name': name,
                        'label': DISPLAY_NAMES.get(name, name), 'live': page in live})
        return out

    def find_carrier(self, pool, cpool, smap):
        for h in range(20, 255):
            se = self.read(pool + h * 0x40, 0x40)
            ce = self.read(cpool + h * 0x40, 0x40)
            if se and len(se) == 0x40 and struct.unpack_from('<H', se)[0] == h:
                continue
            if ce and len(ce) == 0x40 and struct.unpack_from('<H', ce)[0] == h:
                continue
            if self.refs(smap, h):
                continue
            return h
        return None

    def synthetic_spawn(self, page, template, mag=30, reserve=150, timeout=30.0, progress=None):
        base, g, smap, pool = self.resolve()
        ammo_patch = (self.read(base + 0x12EF5B0, 6) == bytes.fromhex('B8E7030000C3')
                      or self.read(base + 0x33D1E30, 3) == bytes.fromhex('31C0C3'))
        if ammo_patch:
            raise SpawnError('无限弹药补丁开启中：合成刷枪已禁用，请先关闭 F5 再试')
        cmap = self._u64(base + 0xF224B78)
        cpool = self._u64(cmap + 8)
        src_key = self.entry_key(pool, template)
        if not src_key:
            raise SpawnError(f'模板 handle {template} 无效')
        packed = struct.unpack_from('<I', src_key, 0x08)[0]
        src_page = (packed >> 10) & 0x7FF
        src_name = self.page_name(base, src_page)
        dst_name = self.page_name(base, page)
        if dst_name.startswith('rex_la_'):
            raise SpawnError('发射器页暂不支持合成注册：缺少有效变体模板，等待关卡内真实实例')
        same_family = src_name.split('_')[:2] == dst_name.split('_')[:2]
        low = (packed & 0x3FF) if same_family else 9
        variant = struct.unpack_from('<I', src_key, 0x10)[0] if same_family else 0
        key = bytearray(56)
        struct.pack_into('<I', key, 0x08, (page << 10) | low)
        struct.pack_into('<I', key, 0x10, variant)
        key = bytes(key)
        carrier = self.find_carrier(pool, cpool, smap)
        if carrier is None:
            raise SpawnError('没有空闲 carrier handle')
        ps, equip, current, pos = self.player(g)
        donor, _ = self.pick_donor(base, g, carrier, pos)
        donor_addr = g + donor['idx'] * STRIDE
        old_handle = self._u16(donor_addr + O_HANDLE)
        old_pos = self._f32x3(donor_addr + O_ORIGINS[0])
        block = bytearray(0x40)
        struct.pack_into('<H', block, 0, carrier)
        block[8:64] = key
        self.write(pool + carrier * 0x40, bytes(block))
        self.write(cpool + carrier * 0x40, bytes(block))
        self.set_refs(smap, carrier, 1)
        self.write(donor_addr + O_HANDLE, struct.pack('<H', carrier))
        at = (pos[0], pos[1], pos[2] + 0.5)
        for off in O_ORIGINS:
            self.write(donor_addr + off, struct.pack('<3f', *at))
        if progress:
            progress(f"合成 page {page} carrier h{carrier}，请拾取")
        new_handle = None
        deadline = time.time() + timeout
        try:
            while time.time() < deadline:
                raw = self.read(ps + O_EQUIP, 30)
                if raw and len(raw) == 30:
                    for h in struct.unpack('<15H', raw):
                        if h and h not in equip:
                            k = self.entry_key(pool, h)
                            if k and ((struct.unpack_from('<I', k, 0x08)[0] >> 10) & 0x7FF) == page:
                                new_handle = h
                                break
                    if new_handle is not None:
                        break
                time.sleep(0.25)
        finally:
            if new_handle is None:
                self.write(donor_addr + O_HANDLE, struct.pack('<H', old_handle))
                if old_pos:
                    for off in O_ORIGINS:
                        self.write(donor_addr + off, struct.pack('<3f', *old_pos))
                self.write(pool + carrier * 0x40, bytes(0x40))
                self.write(cpool + carrier * 0x40, bytes(0x40))
                self.set_refs(smap, carrier, 0)
        if new_handle is None:
            raise SpawnError('未检测到拾取，已还原')
        raw = self.read(ps + O_EQUIP, 30)
        eq = struct.unpack('<15H', raw) if raw and len(raw) == 30 else ()
        slot = eq.index(new_handle) if new_handle in eq else self.current_slot(eq, self._u16(ps + O_CURRENT))
        key2 = self.entry_key(pool, new_handle)
        ammo_state = self.seed_ammo(ps, slot, key2, mag, reserve)
        carrier_cleared = False
        if progress:
            progress(f"已注册 page {page} h{new_handle} 槽{slot} 弹药{mag}/{reserve} "
                     f"reserve={ammo_state} carrier h{carrier} 保留为武器句柄")
        return {'handle': new_handle, 'slot': slot, 'page': page,
                'name': self.decode_key(base, key2)['name'], 'mag': mag,
                'reserve': reserve, 'reserve_state': ammo_state,
                'carrier': carrier, 'carrier_cleared': carrier_cleared}

    def synthetic_direct_equip(self, page, template, mag=30, reserve=210, progress=None):
        """未注册页：合成 key 注册到空 carrier，再直接装备（跳过拾取）。"""
        base, g, smap, pool = self.resolve()
        ammo_patch = (self.read(base + 0x12EF5B0, 6) == bytes.fromhex('B8E7030000C3')
                      or self.read(base + 0x33D1E30, 3) == bytes.fromhex('31C0C3'))
        if ammo_patch:
            raise SpawnError('无限弹药补丁开启中：合成刷枪已禁用，请先关闭 F5 再试')
        cmap = self._u64(base + 0xF224B78)
        cpool = self._u64(cmap + 8) if cmap else 0
        if not cpool:
            raise SpawnError('client 武器 map 未就绪')
        src_key = self.entry_key(pool, template)
        if not src_key:
            raise SpawnError(f'模板 handle {template} 无效')
        packed = struct.unpack_from('<I', src_key, 0x08)[0]
        src_page = (packed >> 10) & 0x7FF
        src_name = self.page_name(base, src_page)
        dst_name = self.page_name(base, page)
        if dst_name.startswith('rex_la_'):
            raise SpawnError('发射器页暂不支持合成注册：缺少有效变体模板')
        same_family = src_name.split('_')[:2] == dst_name.split('_')[:2]
        low = (packed & 0x3FF) if same_family else 9
        variant = struct.unpack_from('<I', src_key, 0x10)[0] if same_family else 0
        key = bytearray(56)
        struct.pack_into('<I', key, 0x08, (page << 10) | low)
        struct.pack_into('<I', key, 0x10, variant)
        key = bytes(key)
        carrier = self.find_carrier(pool, cpool, smap)
        if carrier is None:
            raise SpawnError('没有空闲 carrier handle')
        block = bytearray(0x40)
        struct.pack_into('<H', block, 0, carrier)
        block[8:64] = key
        self.write(pool + carrier * 0x40, bytes(block))
        self.write(cpool + carrier * 0x40, bytes(block))
        self.set_refs(smap, carrier, 1)
        if progress:
            progress(f"合成 page {page} carrier h{carrier}，直接装备")
        try:
            res = self.direct_equip(carrier, mag=mag, reserve=reserve, progress=progress)
        except Exception:
            self.write(pool + carrier * 0x40, bytes(0x40))
            self.write(cpool + carrier * 0x40, bytes(0x40))
            self.set_refs(smap, carrier, 0)
            raise
        res.update({'page': page, 'carrier': carrier,
                    'name': self.decode_key(base, key)['name']})
        return res


def main():
    import argparse
    from pathlib import Path
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import ammo_probe

    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=49700)
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--handle', type=int)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--mag', type=int, default=30)
    parser.add_argument('--reserve', type=int, default=210)
    parser.add_argument('--donor', type=int)
    parser.add_argument('--timeout', type=float, default=30.0)
    parser.add_argument('--page', type=int)
    parser.add_argument('--template', type=int)
    args = parser.parse_args()

    agent, info = ammo_probe.connect_readonly(ammo_probe.TOOLKIT, args.port)
    try:
        sp = Spawner(agent.read, agent.write, info['module_base'])
        if args.page is not None:
            base = info['module_base']
            template = args.template or args.handle
            if template is None:
                rows = sp.armory()
                if not rows:
                    raise SpawnError('没有可用模板武器')
                pname = sp.page_name(base, args.page)
                prefix = '_'.join(pname.split('_')[:2]) if pname != '?' else 'rex'
                cands = [r for r in rows if r['name'].startswith(prefix)]
                if not cands and '_me_' in pname:
                    cands = [r for r in rows if '_me_' in r['name']]
                if not cands:
                    cands = [r for r in rows if r['name'].startswith('rex_')
                             and not r['name'].startswith('rex_me_')]
                template = (cands or rows)[0]['handle']
            try:
                result = sp.synthetic_spawn(args.page, template, mag=args.mag,
                                            reserve=args.reserve, timeout=args.timeout,
                                            progress=lambda m: print(m, flush=True))
            except SpawnError as exc:
                print(f'失败：{exc}')
                return 2
            print('synthetic ok', result)
            return 0
        if args.list or args.handle is None:
            for row in sp.armory():
                print(f"h{row['handle']:>3} refs={row['refs']:>2} "
                      f"{row['label']}#{row['page']} v{row['variant']} "
                      f"att={row['attachments']:016X}")
        if args.handle is not None:
            base, g, smap, pool = sp.resolve()
            key = sp.entry_key(pool, args.handle)
            if key is None:
                raise SpawnError('目标 handle 无效')
            ps, equip, current, pos = sp.player(g)
            print(f"player pos={pos} current={current} equip={equip}")
            if args.dry_run:
                donor, items = sp.pick_donor(base, g, args.handle, pos)
                print(f"dry-run donor idx={donor['idx']} h{donor['handle']} "
                      f"dist={donor['dist']:.0f} pos={donor['pos']}")
                print(f"target h{args.handle} {sp.decode_key(base, key)}")
            else:
                try:
                    result = sp.spawn(args.handle, mag=args.mag, reserve=args.reserve,
                                      timeout=args.timeout, donor_idx=args.donor,
                                      progress=lambda m: print(m, flush=True))
                except SpawnError as exc:
                    print(f'失败：{exc}')
                    return 2
                print('spawn ok', result)
    finally:
        agent.close()


if __name__ == '__main__':
    main()
