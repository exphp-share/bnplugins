from binaryninja import log
import binaryninja as bn
import numpy as np
from importlib import reload as _reload

# Reload all submodules before re-exporting from them.
#
# This ensures that calling reload() on THIS module will also update everything reexported from it.
# (otherwise you'd have to remember which file the thing you changed lives in, import it, and reload that
#  before reloading this. Yuck)
import touhouReverseBnutil as _touhouReverseBnutil
import touhouReverseLabels as _touhouReverseLabels
import touhouReverseStructs as _touhouReverseStructs
import touhouReverseSearch as _touhouReverseSearch
for mod in [_touhouReverseBnutil, _touhouReverseLabels, _touhouReverseStructs, _touhouReverseSearch]:
    _reload(mod)

# These are re-exports.
# (it'd be nice if we could reexport everything while still being forced to explicitly import the
#  things we actually use in this file...)
from touhouReverseBnutil import *  # pylint: disable=unused-wildcard-import
from touhouReverseLabels import *  # pylint: disable=unused-wildcard-import
from touhouReverseStructs import *  # pylint: disable=unused-wildcard-import
from touhouReverseSearch import *  # pylint: disable=unused-wildcard-import

def name_initialize_method_at(bv, addr): return name_method_at(bv, addr, 'initialize')
def name_destructor_method_at(bv, addr): return name_method_at(bv, addr, 'destructor')
def name_constructor_method_at(bv, addr): return name_method_at(bv, addr, 'constructor')
def name_on_tick_method_at(bv, addr): return name_method_at(bv, addr, 'on_tick')
def name_on_draw_method_at(bv, addr): return name_method_at(bv, addr, 'on_draw')
def name_on_registration_method_at(bv, addr): return name_method_at(bv, addr, 'on_registration')
def name_on_cleanup_method_at(bv, addr): return name_method_at(bv, addr, 'on_cleanup')

def name_method_at(bv, addr, method):
    this_func = bv.get_functions_containing(addr)[0]
    if '::' not in this_func.name:
        raise RuntimeError(f'function name does not contain ::')
    class_name = this_func.name.split(':')[0]
    desired_name = class_name + '::' + method
    return name_func_called_at(bv, addr, desired_name)

def get_stub_target_jump_ins(bv, func):
    jumps = []
    if len(list(func.instructions)) <= 5:
        for toks, ins_addr in func.instructions:
            if toks[0].text in ['call', 'jmp']:
                # Try to parse last token as an address
                if toks[-1].text[:2] != '0x':
                    continue
                try:
                    addr = int(toks[-1].text[2:], 16)
                except ValueError:
                    continue

                funcs = list(bv.get_functions_containing(addr))
                if funcs and funcs[0].start == addr:
                    jumps.append(ins_addr)

    if len(jumps) == 1:
        return jumps[0]
    else:
        return None

def name_func_called_at(bv, addr, desired_name):
    this_func = bv.get_functions_containing(addr)[0]
    for (toks, ins_addr) in this_func.instructions:
        if ins_addr == addr:
            break
    else:
        raise RuntimeError(f'no instruction at address {addr:#x}')

    if toks[0].text not in ['call', 'jmp', 'push', 'mov']:
        raise RuntimeError(f'instruction at {addr:#x} is not a call, jmp, or push')

    called_addr = int(toks[-1].text[2:], 16)
    called_func = bv.get_functions_containing(called_addr)[0]
    jump_ins = get_stub_target_jump_ins(bv, called_func)
    if jump_ins:
        desired_name += '__stub'

    if any(func.name == desired_name for func in bv.functions):
        raise RuntimeError(f'function with name {repr(desired_name)} already exists')

    bv.define_user_symbol(bn.Symbol(bn.SymbolType.FunctionSymbol, called_addr, desired_name))
    if jump_ins:
        name_func_called_at(bv, jump_ins, desired_name[:-len('__stub')])

def rename_type_in_funcs(bv, old, new):
    rename_func_prefix(bv, f'{old}::', f'{new}::')

def rename_func_prefix(bv, old_prefix, new_prefix):
    with recording_undo(bv) as rec:
        for func in bv.functions:
            if func.name.startswith(old_prefix):
                suffix = func.name[len(old_prefix):]
                new_name = new_prefix + suffix
                bv.define_user_symbol(bn.Symbol(bn.SymbolType.FunctionSymbol, func.start, new_name))
                rec.enable_auto_rollback()

def fix_vtable_method_names(bv, addr, type_name=None):
    datavar = bv.get_data_var_at(addr)
    start = datavar.address
    ty = datavar.type
    if isinstance(ty, bn.StructureType):
        structure = ty
    elif isinstance(ty, bn.NamedTypeReferenceType):
        structure = bv.get_type_by_id(ty.type_id)
    else:
        log.log_error(f'address {addr} is not inside a vtable struct')

    def get_type_name():
        # gather from first method
        symbol = bv.get_symbol_at(read_u32(bv, start))
        if not symbol:
            log.log_error(f'no symbol defined at {addr}')
            return None
        if symbol.type != bn.SymbolType.FunctionSymbol:
            log.log_error(f'{addr} is not a function')
            return None
        if '::' not in symbol.name:
            log.log_error(f'The first function in the VTable must have an obvious type name, e.g. "SomeStruct::do_a_thing". (got {repr(symbol.name)})')
            return None
        return symbol.name.split('::')[0]

    if type_name is None:
        type_name = get_type_name()
    if not type_name:
        return

    for member in structure.members:
        method_name = member.name.split('(')[0] # remove parameter list if any
        desired_name = f'{type_name}::{method_name}'
        function_address = read_u32(bv, start + member.offset)

        clashing_symbol = bv.get_symbol_by_raw_name(desired_name)
        if clashing_symbol and clashing_symbol.address != function_address:
            log.log_error(f'A symbol already exists named {repr(desired_name)}! Skipping...')
            continue

        bv.define_user_symbol(bn.Symbol(bn.SymbolType.FunctionSymbol, function_address, desired_name))

#bn.PluginCommand.register_for_address('Convert to single-precision float', 'Set the type at this location to a float', convert_to_float)

bn.PluginCommand.register_for_address('Fix VTable method names', 'Given an address anywhere inside a VTable in static memory, rename the referenced functions after the vtable struct fields.', fix_vtable_method_names)
bn.PluginCommand.register_for_address('Name initialize method', 'Name initialize method', name_initialize_method_at)
bn.PluginCommand.register_for_address('Name constructor method', 'Name constructor method', name_constructor_method_at)
bn.PluginCommand.register_for_address('Name destructor method', 'Name destructor method', name_destructor_method_at)
bn.PluginCommand.register_for_address('Name on_tick method', 'Name on_tick method', name_on_tick_method_at)
bn.PluginCommand.register_for_address('Name on_draw method', 'Name on_draw method', name_on_draw_method_at)
bn.PluginCommand.register_for_address('Name on_cleanup method', 'Name on_cleanup method', name_on_cleanup_method_at)
bn.PluginCommand.register_for_address('Name on_registration method', 'Name on_registration method', name_on_registration_method_at)

# ========================================================================

repack_name = 'zAnmManager'

def repack_anm_fields(bv, addr):
    t = bv.types[repack_name]
    assert isinstance(t, bn.StructureType)
    s = t.mutable_copy()

    remove_indices = [index for (index, field) in enumerate(s.members) if field.type.element_type == bn.Type.char() and field.name.startswith('__')]
    for index in reversed(remove_indices):
        s.remove(index)

    unknown_ranges = [range(t.width)]
    for member in s.members:
        log.log_error(str(unknown_ranges))
        last_range = unknown_ranges.pop()
        before = range(last_range.start, member.offset)
        after = range(member.offset + member.type.width, last_range.stop)

        if before:
            unknown_ranges.append(before)
        if after:
            unknown_ranges.append(after)

    for i, r in enumerate(unknown_ranges):
        s.insert(r.start, bn.Type.array(bn.Type.char(), len(r)), f'__filler_{i:02}')

    bv.define_user_type(repack_name, bn.Type.structure_type(s))

bn.PluginCommand.register_for_address('Repack AnmManagerFields', 'Repack AnmManagerFields', repack_anm_fields)

# ========================================================================

def bindiff(bv, path1, path2=None, skip_start=0, skip_end=0):
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

def export_func_meta(bv, path):
    import json
    meta = __func_meta(bv)
    with open(path, 'w') as f:
        json.dump(meta, f)
        print(file=f)

def __func_meta(bv):
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
    for func, next_func in window2(bv.functions + [None]):
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

def get_callgraph(bv):
    from networkx import DiGraph

    g = DiGraph()
    for func in bv.functions:
        g.add_node(func.start)
    for func in bv.functions:
        for ref in bv.get_code_refs(func.start):
            caller = bv.get_functions_containing(ref.address)[0].start
            g.add_edge(caller, func.start)
    return g

def __add_static_proximities(bv, g, max_count=6, attr='proximity'):
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
def single_sub_strings(bv, hex=False):
    results = find_strings(bv, hex=hex)
    results = {k:{'str': v['str'], 'sub': v['subs'][0]} for (k, v) in results.items() if len(v['subs']) == 1}
    return results

# Find strings and functions that use them.
def find_strings(bv, hex=False):
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
            results[k]['sub'] = list(map(hexify, results[k]['sub']))
    return results

def read_possible_shift_jis(bv, addr, max_size=1024, max_end=float('inf')):
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

def window2(it):
    it = iter(it)
    prev = next(it)
    for x in it:
        yield prev, x
        prev = x

# ========================================================================

_CARD_NAMES = ['Chimata', 'Life', 'Bomb', 'LifeFragment', 'BombFragment', 'Nazrin', 'Ringo', 'Mokou', 'Reimu1', 'Reimu2', 'Marisa1', 'Marisa2', 'Sakuya1', 'Sakuya2', 'Sanae1', 'Sanae2', 'Youmu', 'Alice', 'Cirno', 'Okina', 'Nue', 'Nitori', 'Kanako', 'Eirin', 'Tewi', 'Saki', 'Byakuren', 'Koishi', 'Suwako', 'Aya', 'Keiki', 'Kaguya', 'Mamizou', 'Yuyuko', 'Yachie', 'ShikiEiki', 'Narumi', 'Patchouli', 'Mike', 'Takane', 'Sannyo', 'Yukari', 'Shinmyoumaru', 'Tenshi', 'Clownpiece', 'Miko', 'Remilia', 'Utusho', 'LilyWhite', 'Raiko', 'Sumireko', 'Misumaru', 'Tsukasa', 'Megumu', 'Momoyo', 'Magatama', 'Null']
_CARD_BASE_CLASS_VTABLE = 0x4b6010
def name_card_vtables(bv, jump_addr):
    jumptable, _ = read_accessed_jumptable(bv, jump_addr)
    with recording_undo(bv) as rec:
        for card_id in jumptable:
            addr = jumptable[card_id]
            card_name = _CARD_NAMES[card_id]
            print(card_id, card_name, hex(addr))
            class_name = 'Card' + card_name
            vtable_name = 'VTABLE_' + _pascal_case_to_snake_case(class_name).upper()

            add_label(bv, addr, f'card__case_{card_id}__{card_name}')

            for tokens, size in bv.get_basic_blocks_at(addr)[0]:
                if size != 6: continue
                if not str(tokens[-1]).startswith('0x'): continue

                vtable_addr = int(str(tokens[-1]), 16)
                if vtable_addr == _CARD_BASE_CLASS_VTABLE: continue

                datavar = bv.get_data_var_at(vtable_addr)
                if datavar is None: continue
                table_type = datavar.type
                while table_type.named_type_reference is not None:
                    table_type = bv.get_type_by_id(table_type.named_type_reference.type_id)
                if table_type != bv.get_type_by_name('zVTableCard'): continue
                name_symbol(bv, vtable_addr, vtable_name)
                rec.enable_auto_rollback()

                fix_vtable_method_names(bv, vtable_addr, class_name)
                break
            else:
                print(f'no vtable found for {card_id}')
        fix_vtable_method_names(bv, _CARD_BASE_CLASS_VTABLE, 'CardBaseClass')

def _pascal_case_to_snake_case(name):
    import re
    return re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()

