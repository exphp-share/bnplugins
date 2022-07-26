from binaryninja import log
import binaryninja as bn
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
import touhouReverseAnalysis as _touhouReverseAnalysis
import touhouReverseConfig as _touhouReverseConfig
for mod in [_touhouReverseBnutil, _touhouReverseLabels, _touhouReverseStructs, _touhouReverseSearch, _touhouReverseAnalysis, _touhouReverseConfig]:
    _reload(mod)

# These are re-exports.
# (it'd be nice if we could reexport everything while still being forced to explicitly import the
#  things we actually use in this file...)
from touhouReverseBnutil import *  # pylint: disable=unused-wildcard-import
from touhouReverseLabels import *  # pylint: disable=unused-wildcard-import
from touhouReverseStructs import *  # pylint: disable=unused-wildcard-import
from touhouReverseSearch import *  # pylint: disable=unused-wildcard-import
from touhouReverseAnalysis import *  # pylint: disable=unused-wildcard-import
from touhouReverseConfig import *  # pylint: disable=unused-wildcard-import

def name_initialize_method_at(bv, addr): return name_method_at(bv, addr, 'initialize')
def name_destructor_method_at(bv, addr): return name_method_at(bv, addr, 'destructor')
def name_constructor_method_at(bv, addr): return name_method_at(bv, addr, 'constructor')
def name_on_tick_method_at(bv, addr): return name_method_at(bv, addr, 'on_tick')
def name_on_draw_method_at(bv, addr): return name_method_at(bv, addr, 'on_draw')
def name_on_registration_method_at(bv, addr): return name_method_at(bv, addr, 'on_registration')
def name_on_cleanup_method_at(bv, addr): return name_method_at(bv, addr, 'on_cleanup')

def name_method_at(bv: bn.BinaryView, addr, method):
    this_func = bv.get_functions_containing(addr)[0]
    if '::' not in this_func.name:
        raise RuntimeError(f'function name does not contain ::')
    class_name = this_func.name.split(':')[0]
    desired_name = class_name + '::' + method
    return name_func_called_at(bv, addr, desired_name)

def get_stub_target_jump_ins(bv: bn.BinaryView, func: bn.Function):
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

def name_func_called_at(bv: bn.BinaryView, addr, desired_name):
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

GamesSpec = str | list[str] | tuple[str, ...]

def parse_games(game: GamesSpec):
    if game is None:
        return sorted(GAME_VERSIONS)
    if isinstance((list, tuple), game):
        return list(game)
    if isinstance(str, game):
        if ',' in game:
            return list(game.split(','))
        if ':' in game:
            lo, hi = game.split(':', 1)
            return [g for g in sorted(GAME_VERSIONS) if lo <= g <= hi]
        return [game]
    assert False, type(game)

def iter_all_game_bndb_paths(games: GamesSpec):
    config = Config.read_system()
    for game in parse_games(games):
        version = GAME_VERSIONS[game]
        yield config.bndb_dir / f'{game}.{version}.bndb'

def rename_type_in_all_games(old, new, games: GamesSpec = None):
    if old.startswith('z') and new.startswith('z'):
        old_prefix = old[1:]
        new_prefix = new[1:]
    else:
        old_prefix = old
        new_prefix = new

    for bndb_path in iter_all_game_bndb_paths(games):
        print(bndb_path)
        with open_bv(bndb_path) as bv:
            rename_type_in_funcs(bv, old_prefix, new_prefix)
            if bv.get_type_by_name(old) is not None:
                bv.rename_type(old, new)
            bv.save_auto_snapshot()

def rename_fields_in_all_games(struct_name, renames: tp.Iterable[tuple[str, str]], games: GamesSpec = None):
    for bndb_path in iter_all_game_bndb_paths(games):
        print(bndb_path)
        with open_bv(bndb_path) as bv:
            if bv.get_type_by_name(struct_name) is not None:
                change_occurred = False
                with recording_undo(bv) as rec:
                    for (old, new) in renames:
                        this_change_occurred = struct_rename_member(bv, struct_name, old, new, missing_ok=True)
                        change_occurred = change_occurred or this_change_occurred

                if change_occurred:
                    bv.save_auto_snapshot()

def rename_type_in_funcs(bv: bn.BinaryView, old, new):
    rename_func_prefix(bv, f'{old}::', f'{new}::')

def rename_func_prefix(bv: bn.BinaryView, old_prefix, new_prefix):
    with recording_undo(bv) as rec:
        for func in bv.functions:
            if func.name.startswith(old_prefix):
                suffix = func.name[len(old_prefix):]
                new_name = new_prefix + suffix
                bv.define_user_symbol(bn.Symbol(bn.SymbolType.FunctionSymbol, func.start, new_name))
                rec.enable_auto_rollback()

def fix_vtable_method_names(bv: bn.BinaryView, addr, type_name=None):
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

def repack_anm_fields(bv: bn.BinaryView, addr):
    struct = bv.types[repack_name]
    assert isinstance(struct, bn.StructureType)
    struct = struct.mutable_copy()

    remove_indices = [
        index for (index, field) in enumerate(struct.members)
        if isinstance(field.type, bn.ArrayType)
        and field.type.element_type == bn.Type.char()
        and field.name.startswith('__')
    ]
    for index in reversed(remove_indices):
        struct.remove(index)

    unknown_ranges = [range(struct.width)]
    for member in struct.members:
        log.log_error(str(unknown_ranges))
        last_range = unknown_ranges.pop()
        before = range(last_range.start, member.offset)
        after = range(member.offset + member.type.width, last_range.stop)

        if before:
            unknown_ranges.append(before)
        if after:
            unknown_ranges.append(after)

    for i, r in enumerate(unknown_ranges):
        struct.insert(r.start, bn.Type.array(bn.Type.char(), len(r)), f'__filler_{i:02}')

    bv.define_user_type(repack_name, struct)

bn.PluginCommand.register_for_address('Repack AnmManagerFields', 'Repack AnmManagerFields', repack_anm_fields)

# ========================================================================

_CARD_NAMES = ['Chimata', 'Life', 'Bomb', 'LifeFragment', 'BombFragment', 'Nazrin', 'Ringo', 'Mokou', 'Reimu1', 'Reimu2', 'Marisa1', 'Marisa2', 'Sakuya1', 'Sakuya2', 'Sanae1', 'Sanae2', 'Youmu', 'Alice', 'Cirno', 'Okina', 'Nue', 'Nitori', 'Kanako', 'Eirin', 'Tewi', 'Saki', 'Byakuren', 'Koishi', 'Suwako', 'Aya', 'Keiki', 'Kaguya', 'Mamizou', 'Yuyuko', 'Yachie', 'ShikiEiki', 'Narumi', 'Patchouli', 'Mike', 'Takane', 'Sannyo', 'Yukari', 'Shinmyoumaru', 'Tenshi', 'Clownpiece', 'Miko', 'Remilia', 'Utusho', 'LilyWhite', 'Raiko', 'Sumireko', 'Misumaru', 'Tsukasa', 'Megumu', 'Momoyo', 'Magatama', 'Null']
_CARD_BASE_CLASS_VTABLE = 0x4b6010
def name_card_vtables(bv: bn.BinaryView, jump_addr):
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
                while isinstance(table_type, bn.NamedTypeReferenceType):
                    table_type = bv.get_type_by_id(table_type.type_id)
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

