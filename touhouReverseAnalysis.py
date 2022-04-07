import binaryninja as bn
import typing as tp
from touhouReverseBnutil import llil_at, llil_begin_addr, cached_llil

T = tp.TypeVar('T')

def bindiff(bv: bn.BinaryView, path1, path2=None, skip_start=0, skip_end=0):
    text = bv.sections['.text']
    def do_skips(bits):
        bits = bits[skip_start:]
        if skip_end:
            bits = bits[:-skip_end]
        return bits
    with open(path1, 'rb') as f1:
        bytes1 = do_skips(f1.read())
    if path2 is None:
        bytes2 = bytes1
        bytes1 = bv.read(text.start, text.end - text.start)
    else:
        with open(path2, 'rb') as f2:
            bytes2 = do_skips(f2.read())
    assert len(bytes1) == len(bytes2) == text.end - text.start, (len(bytes1), len(bytes2), text.end - text.start)

    changed_addresses = [addr for (addr, (b1, b2)) in enumerate(zip(bytes1, bytes2), start=text.start) if b1 != b2]
    changed_instr_starts = set([llil_begin_addr(bv, addr) for addr in changed_addresses])
    for addr in sorted([x for x in changed_instr_starts if x is not None]):
        to_hex = lambda bits: ''.join(f'{x:02x}' for x in bits)
        instr = llil_at(bv, addr)
        slc = slice(addr - text.start, addr - text.start + bv.get_instruction_length(addr))
        print(f'{addr:#x}: {to_hex(bytes1[slc])} => {to_hex(bytes2[slc])}  (orig: {llil_at(bv, addr)})')

# ========================================================================

def export_func_meta(bv: bn.BinaryView, path):
    import json
    meta = __func_meta(bv)
    with open(path, 'w') as f:
        json.dump(meta, f)
        print(file=f)

def __func_meta(bv: bn.BinaryView):
    import base64
    section = bv.sections['.text']
    bits = bv.read(section.start, section.end - section.start)
    bits = base64.b64encode(bits).decode('ascii')

    probable_jumptable_addrs = []
    for name, symbol in bv.symbols.items():
        if symbol.address not in range(section.start, section.end):
            continue
        if name.startswith('float('):
            continue
        if bv.get_functions_containing(symbol.address):
            continue  # binja should return [] for jumptables
        probable_jumptable_addrs.append(symbol.address)

    callgraph = get_callgraph(bv)
    __add_static_proximities(bv, callgraph, attr='proximity')

    funcs = []
    for func, next_func in _window2(bv.functions + [None]):
        if next_func:
            size = next_func.start - func.start
        else:
            size = section.end - func.start
        func_range = range(func.start, func.start + size)
        jumptable_count = len([x for x in probable_jumptable_addrs if x in func_range])
        funcs.append({
            'name': func.name,
            'addr': func.start,
            'size': size,
            'jumptables': jumptable_count,
            'incoming-calls': len(bv.get_code_refs(func.start)),
            'static-proximity': callgraph.nodes[func.start]['proximity'],
        })

    return {
        'bits': bits,
        'funcs': funcs,
        'start': section.start,
    }

def get_callgraph(bv: bn.BinaryView):
    from networkx import DiGraph

    g = DiGraph()
    for func in bv.functions:
        g.add_node(func.start)
    for func in bv.functions:
        for ref in bv.get_code_refs(func.start):
            caller = bv.get_functions_containing(ref.address)[0].start
            g.add_edge(caller, func.start)
    return g

def __add_static_proximities(bv: bn.BinaryView, g, max_count=6, attr='proximity'):
    for node in g.nodes:
        g.nodes[node]['proximity'] = {}

    # Fake nodes will be added for the static functions and strings,
    # so that they can be handled by the same logic as all else.
    fake_nodes = {}

    # Strings
    for key, d in find_strings(bv).items():
        fake_nodes[key] = [d['str']]
        g.add_node(key)

    # IAT symbols
    for (name, symbol) in bv.symbols.items():
        if name.endswith('@IAT'):
            static_addresses = [symbol.address]
            wrapper_symbol = bv.get_symbol_by_raw_name(name[:-4])
            if wrapper_symbol:
                static_addresses.append(wrapper_symbol.address)
            fake_nodes[name] = static_addresses
            g.add_node(name)

    for name in fake_nodes:
        for static_address in fake_nodes[name]:
            for ref in bv.get_code_refs(static_address):
                caller = bv.get_functions_containing(ref.address)[0].start
                g.add_edge(caller, name)

    for node in g.nodes:
        g.nodes[node][attr] = {}

    reverse_g = g.reverse()
    for name in fake_nodes:
        # Assign nodes a proximity to each static based on their callgraph distance.
        #
        # The fake nodes get proximity -1 so direct users get proximity 0.
        total_count = 0
        for proximity, group in enumerate(__bfs_groups(reverse_g, [name]), start=-1):
            # Only do this for a small number of nodes for each static.
            total_count += len(group)
            if total_count > max_count:
                break
            for addr in group:
                g.nodes[addr][attr][name] = proximity

    g.remove_nodes_from(fake_nodes)

def __bfs_groups(g, start_nodes):
    """
    Iterates over groups of nodes (as sets) with increasing distance from an initial set.
    (i.e. first the initial set itself, then nodes whose minimum distance from the set is 1,
    then a distance of 2, etc.)
    """
    prev_group = set(start_nodes)
    all_seen = set(prev_group)
    while prev_group:
        yield prev_group
        next_group = set()
        for prev in prev_group:
            next_group |= set(g.neighbors(prev))
        next_group -= all_seen
        all_seen |= next_group
        prev_group = next_group

# Find strings that are only used by one caller.
def single_sub_strings(bv: bn.BinaryView, hex=False):
    results = find_strings(bv, hex=hex)
    results = {k:{'str': v['str'], 'sub': v['subs'][0]} for (k, v) in results.items() if len(v['subs']) == 1}
    return results

# Find strings and functions that use them.
def find_strings(bv: bn.BinaryView, hex=False):
    rdata_range = range(bv.sections['.rdata'].start, bv.sections['.rdata'].end)

    results = {}
    for func_start, llil in cached_llil(bv).items():
        for ins in llil:
            if ins.operation != bn.LowLevelILOperation.LLIL_PUSH:
                continue
            for str_addr in [op for op in ins.prefix_operands if isinstance(op, int) and op in rdata_range]:
                text = read_possible_shift_jis(bv, str_addr)
                if not text: continue
                if len(text) < 3: continue

                if text in results and func_start not in results[text]['subs']:
                    results[text]['subs'].append(func_start)
                else:
                    results[text] = {'str': str_addr, 'subs': [func_start]}
    if hex:
        for k in results:
            hexify = lambda x: f'{x:#x}'
            results[k]['str'] = hexify(results[k]['str'])
            results[k]['subs'] = list(map(hexify, results[k]['subs']))
    return results

def read_possible_shift_jis(bv: bn.BinaryView, addr, max_size=1024, max_end=float('inf')):
    end = min(addr + max_size, max_end)
    bits = bv.read(addr, end - addr)

    # Expect null-terminated string
    if 0 not in bits:
        return None
    bits = bits[:bits.index(0)]

    # Strings with non-printable characters are probably not really strings
    if any(c in range(0x01, 0x20) and c not in b'\t\r\n' for c in bits):
        return None

    try:
        return bits.decode('shift-jis')
    except UnicodeDecodeError:
        return None

def _window2(it: tp.Iterable[T]) -> tp.Iterator[tp.Tuple[T, T]]:
    it = iter(it)
    prev = next(it)
    for x in it:
        yield prev, x
        prev = x
