from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import mmap
from pathlib import Path
import socket
import struct
import sys
import time

EXE = Path('sp26-cod.exe')
TOOLKIT = Path(__file__).resolve().parent
SCANNER_RVA = 0x3373D80
SCANNER_HEAD = bytes.fromhex('4157415656')
IMAGE_SIZE = 0x15948000
SLOT_START = 0x1220
SLOT_STRIDE = 0x58
SLOT_COUNT = 18
SPAN = 0x2800
MASK64 = (1 << 64) - 1
PHASES = ('primary', 'reload', 'secondary')
LABELS = {
    'primary': '主武器开火相关递减候选',
    'secondary': '副武器开火相关递减候选',
    'reload_decrease': '换弹相关递减候选（备弹待验证）',
    'reload_increase': '换弹相关递增候选（弹匣待验证）',
}


def pointer_key(module_base: int, peb: int) -> int:
    return ((module_base + 0x4B7BA3E5) & MASK64) ^ peb


def slot_field(offset: int):
    relative = offset - SLOT_START
    if 0 <= relative < SLOT_COUNT * SLOT_STRIDE:
        slot, field = divmod(relative, SLOT_STRIDE)
        return {'slot': slot, 'field': field, 'dword_index': field // 4}
    return None


def words(data: bytes):
    if len(data) != SPAN:
        raise ValueError(f'快照须为 0x{SPAN:X} 字节，实际为 0x{len(data):X}')
    return struct.unpack(f'<{SPAN // 4}i', data)


def analyse(session: dict):
    if session.get('schema') != 1 or session.get('span') != SPAN:
        raise ValueError('不支持的会话格式或快照长度')
    if not isinstance(session.get('container'), int) or session['container'] <= 0:
        raise ValueError('会话缺少有效容器地址')
    idle = [words(bytes.fromhex(data)) for data in session['idle']]
    if len(idle) < 2:
        raise ValueError('至少需要两份静置快照')
    noisy = {
        i for a, b in zip(idle, idle[1:])
        for i, (old, new) in enumerate(zip(a, b)) if old != new
    }
    grouped = {phase: [] for phase in PHASES}
    for event in session['events']:
        if event['phase'] not in grouped:
            raise ValueError('未知采样动作')
        grouped[event['phase']].append((
            words(bytes.fromhex(event['before'])),
            words(bytes.fromhex(event['after'])),
        ))
    result = {'candidate_only': True, 'container': session['container'],
              'idle_noisy_fields': len(noisy), 'groups': {}}
    for phase, events in grouped.items():
        kinds = ('reload_decrease', 'reload_increase') if phase == 'reload' else (phase,)
        for kind in kinds:
            rows = []
            if len(events) >= 2:
                for index in range(SPAN // 4):
                    if index in noisy:
                        continue
                    changes = [(before[index], after[index]) for before, after in events]
                    deltas = [new - old for old, new in changes]
                    matches = (all(delta < 0 for delta in deltas) if kind == 'reload_decrease'
                               else all(delta > 0 for delta in deltas) if kind == 'reload_increase'
                               else all(delta == -1 for delta in deltas))
                    if matches:
                        offset = index * 4
                        rows.append({'offset': offset, 'address': session['container'] + offset,
                                     'slot_field': slot_field(offset), 'changes': changes,
                                     'deltas': deltas})
            rows.sort(key=lambda row: (
                0 if row['slot_field'] and row['slot_field']['dword_index'] in (16, 17, 20, 21) else 1,
                row['offset'],
            ))
            result['groups'][kind] = {'event_count': len(events), 'candidates': rows}
    return result


def print_analysis(report: dict):
    print('仅为事件相关候选；不自动冻结，不把时间戳、标志或显示副本判定成权威值。')
    print(f"静置期间排除 {report['idle_noisy_fields']} 个变化字段")
    for kind, group in report['groups'].items():
        rows = group['candidates']
        print(f"\n{LABELS[kind]}：{len(rows)} 个，动作样本 {group['event_count']} 次")
        if group['event_count'] < 2:
            print('样本不足，至少重复同一动作两次。')
        for row in rows[:20]:
            field = row['slot_field']
            location = f"k={field['slot']} v[{field['dword_index']}]" if field else '槽表外'
            print(f"  +0x{row['offset']:04X} / 0x{row['address']:X} {location} "
                  f"变化={row['changes']} delta={row['deltas']}")
        if len(rows) > 20:
            print('仅显示前 20 项；完整候选可用 analyse --out 保存。')


def save_new(path: Path, data: dict):
    with path.open('x', encoding='utf-8') as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write('\n')


def static_profile(exe: Path):
    import capstone
    from capstone.x86 import X86_OP_MEM, X86_REG_RIP

    with exe.open('rb') as handle, mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as image:
        if image[:2] != b'MZ':
            raise ValueError('不是 PE 程序')
        pe = struct.unpack_from('<I', image, 0x3C)[0]
        if image[pe:pe + 4] != b'PE\0\0':
            raise ValueError('PE 签名无效')
        machine, count = struct.unpack_from('<HH', image, pe + 4)
        optional_size = struct.unpack_from('<H', image, pe + 20)[0]
        if machine != 0x8664 or struct.unpack_from('<H', image, pe + 24)[0] != 0x20B:
            raise ValueError('要求 x64 PE32+')
        preferred_base = struct.unpack_from('<Q', image, pe + 48)[0]
        section_table = pe + 24 + optional_size
        sections = [struct.unpack_from('<8sIIII', image, section_table + i * 40)
                    for i in range(count)]

        def read_rva(rva, length):
            for name, virtual_size, start, raw_size, raw_offset in sections:
                relative = rva - start
                if 0 <= relative and relative + length <= raw_size:
                    return image[raw_offset + relative:raw_offset + relative + length]
            raise ValueError(f'RVA 0x{rva:X} 没有完整磁盘数据（可能是 BSS）')

        scanner = read_rva(SCANNER_RVA, 0x260)
        if scanner[:5] != SCANNER_HEAD:
            raise ValueError('扫描器函数头不匹配，不能套用旧布局')
        decode_blob = read_rva(0x941F840, 0x280)
        aggregator = read_rva(0x3375520, 0x400)
        disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        disassembler.detail = True
        instructions = []
        for rva, code in ((SCANNER_RVA, scanner), (0x941F840, decode_blob), (0x3375520, aggregator)):
            for instruction in disassembler.disasm(code, preferred_base + rva):
                row = {'rva': instruction.address - preferred_base,
                       'bytes': instruction.bytes.hex(), 'mnemonic': instruction.mnemonic,
                       'operands': instruction.op_str}
                targets = [instruction.address + instruction.size + operand.mem.disp - preferred_base
                           for operand in instruction.operands
                           if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP]
                if targets:
                    row['rip_target_rvas'] = targets
                instructions.append(row)
                if instruction.mnemonic == 'ret':
                    break
        indexed = {row['rva']: row for row in instructions}
        expected = {
            0x3373F77: ('add', 'rdi, 0x17f8'),
            0x3373F94: ('mov', 'ebp, dword ptr [r14 + 0x54]'),
            0x3373F98: ('add', 'ebp, dword ptr [r14 + 0x50]'),
            0x3373FAA: ('add', 'ebp, dword ptr [r14 + 0x40]'),
            0x3373FAE: ('add', 'ebp, dword ptr [r14 + 0x44]'),
            0x941F8C2: ('lea', 'r10, [r11 + 0x4b7ba3e5]'),
            0x941FA06: ('add', 'rdi, 0x234840'),
            0x337559D: ('cmp', 'rbx, 0xf'),
            0x33755AA: ('movzx', 'eax, word ptr [rsi + rbx*2 + 0x810]'),
        }
        for rva, (mnemonic, operands) in expected.items():
            row = indexed.get(rva)
            if row is None or (row['mnemonic'], row['operands']) != (mnemonic, operands):
                raise ValueError(f'RVA 0x{rva:X} 机器码证据不匹配，拒绝导出旧布局')
        return {
            'exe': str(exe.resolve()), 'sha256': hashlib.sha256(image).hexdigest(),
            'preferred_base': preferred_base, 'scanner_rva': SCANNER_RVA,
            'slot_start': SLOT_START, 'slot_stride': SLOT_STRIDE, 'slot_count': SLOT_COUNT,
            'slot_end_exclusive': SLOT_START + SLOT_COUNT * SLOT_STRIDE,
            'snapshot_span': SPAN, 'instructions': instructions,
            'pointer_key_formula': 'PEB XOR ((runtime_module_base + 0x4B7BA3E5) mod 2^64)',
            'pointer_decode_status': '仅校正机器码中的第一步密钥；完整指针解码仍未验证',
            'container_bias': {'offset': 0x234840, 'evidence_rva': 0x941FA06},
            'conditional_sum_fields': {'offsets': [0x40, 0x44], 'evidence_rvas': [0x3373FAA, 0x3373FAE]},
            'inventory_indices': {'offset': 0x810, 'element_size': 2, 'count': 15,
                                  'evidence_rvas': [0x33755AA, 0x337559D]},
            'reserve_field_status': '第二条路径按武器引用聚合并再次调用槽扫描器，不足以证明备弹字段',
        }


def _agent_client():
    try:
        return importlib.import_module('codtool.agent_client')
    except ImportError:
        pass
    for base in (TOOLKIT, Path(__file__).resolve().parent):
        if (base / 'codtool' / 'agent_client.py').is_file():
            sys.path.insert(0, str(base.resolve()))
            return importlib.import_module('codtool.agent_client')
    raise ValueError('找不到 codtool/agent_client.py（内置模块缺失）')


def connect_readonly(toolkit: Path, port: int):
    AgentProcess = _agent_client().AgentProcess
    sock = socket.create_connection(('127.0.0.1', port), timeout=10)
    agent = AgentProcess(sock, 0, '?', 0, 0)
    try:
        # connect() 会发送 SCAN_CLEAR，采样不能清除其他窗口的扫描状态。
        pid = agent.ping()
        base, size, name = agent.info()
        if name.lower() != 'sp26-cod.exe' or size != IMAGE_SIZE:
            raise ValueError(f'代理目标不匹配：{name} / 0x{size:X}')
        if agent.read(base + SCANNER_RVA, len(SCANNER_HEAD)) != SCANNER_HEAD:
            raise ValueError('运行中扫描器函数头不匹配，停止读取容器')
        return agent, {'pid': pid, 'module_base': base, 'module_size': size, 'name': name}
    except BaseException:
        agent.close()
        raise


def snapshot(agent, pid: int, container: int):
    if agent.ping() != pid:
        raise ValueError('会话进程已变化，必须重新定位容器')
    data = agent.read(container, SPAN)
    if data is None or len(data) != SPAN:
        raise ValueError('容器读取不完整；地址可能过期，不生成候选')
    return data.hex()


def capture(args):
    if args.container <= 0 or args.container > 0x7FFFFFFFFFFF or args.container % 4:
        raise ValueError('请输入本次游戏会话有效且四字节对齐的容器地址')
    if args.out.exists() or not args.out.parent.is_dir():
        raise ValueError('输出文件已存在或父目录不存在；不会覆盖旧记录')
    agent, process = connect_readonly(args.toolkit, args.port)
    session = {'schema': 1, 'span': SPAN, 'container': args.container,
               'process': process, 'idle': [], 'events': [], 'interrupted': False}
    try:
        print(f"已连接 {process['name']} PID={process['pid']}，容器 0x{args.container:X}")
        print('本工具只发送 PING / INFO / READ，不清扫描、不挂 hook、不设置断点、不冻结。')
        print('旧地址即使可读也可能已复用；最终字段仍须结合实机动作确认。')
        input('不要开枪或换弹；按回车开始静置采样，随后切回游戏保持静置约 4 秒。')
        for _ in range(20):
            session['idle'].append(snapshot(agent, process['pid'], args.container))
            time.sleep(0.2)
        instructions = {
            'primary': ('切到主武器，确保有弹可开火', '仅开一枪，不要换弹、换枪或拾取弹药'),
            'reload': ('切到主武器，先消耗几发且不要换弹', '仅换弹一次，等待动画结束，不要开枪或拾取弹药'),
            'secondary': ('切到副武器，确保有弹可开火', '仅开一枪，不要换弹、换枪或拾取弹药'),
        }
        for phase in PHASES:
            prepare, action = instructions[phase]
            for round_index in range(args.rounds):
                input(f'\n[{phase} {round_index + 1}/{args.rounds}] {prepare}，回终端按回车拍前快照。')
                before = snapshot(agent, process['pid'], args.container)
                input(f'切回游戏：{action}，然后回终端按回车拍后快照。')
                after = snapshot(agent, process['pid'], args.container)
                session['events'].append({'phase': phase, 'before': before, 'after': after})
    except (KeyboardInterrupt, EOFError):
        session['interrupted'] = True
        print('\n采样已停止，保存已完成的动作。')
    finally:
        agent.close()
        if session['idle']:
            save_new(args.out, session)
            print(f'采样记录：{args.out.resolve()}')
    print_analysis(analyse(session))


def main(argv=None):
    parser = argparse.ArgumentParser(description='SP26 离线战役只读弹药采样与静态机器码核验')
    commands = parser.add_subparsers(dest='command', required=True)
    static = commands.add_parser('static', help='只读磁盘程序，校验布局并导出机器码证据')
    static.add_argument('--exe', type=Path, default=EXE)
    static.add_argument('--out', type=Path, required=True)
    live = commands.add_parser('capture', help='已有代理的只读采样；必须提供当前容器地址')
    live.add_argument('--container', type=lambda value: int(value, 0), required=True)
    live.add_argument('--toolkit', type=Path, default=TOOLKIT)
    live.add_argument('--port', type=int, default=49700)
    live.add_argument('--rounds', type=int, choices=range(2, 6), default=2)
    live.add_argument('--out', type=Path, required=True)
    offline = commands.add_parser('analyse', help='离线分析采样记录，不连接游戏')
    offline.add_argument('session', type=Path)
    offline.add_argument('--out', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'static':
            profile = static_profile(args.exe)
            save_new(args.out, profile)
            print(f"SHA256: {profile['sha256']}")
            print(f'完整槽表终点 +0x{SLOT_START + SLOT_COUNT * SLOT_STRIDE:X}，采样范围 0x{SPAN:X}')
            print(profile['pointer_key_formula'])
            print(f'机器码证据：{args.out.resolve()}')
        elif args.command == 'capture':
            capture(args)
        else:
            with args.session.open(encoding='utf-8') as handle:
                report = analyse(json.load(handle))
            print_analysis(report)
            if args.out:
                save_new(args.out, report)
        return 0
    except (OSError, ValueError, KeyError, TypeError, ImportError, RuntimeError) as error:
        print(f'失败：{error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
