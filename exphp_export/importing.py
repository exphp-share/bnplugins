import binaryninja as bn
from exphp_export.common import ENUM_IS_BITFIELDS_NAME, ENUM_IS_BITFIELDS_VALUE, window2

from touhouReverseBnutil import recording_undo, UndoRecorder

from .config import DEFAULT_FILTERS
from .export_types import EnumBitfield, structure_to_cereal_v1, enum_to_bitfields_cereal_v1

def import_funcs_from_json(bv, funcs: list, emit_status=print):
    """ Import funcs from JSON written in the V1 format. """
    with recording_undo(bv) as rec:
        return _import_symbols_from_json_v1(bv, funcs, bn.SymbolType.FunctionSymbol, rec=rec, emit_status=emit_status)

def import_statics_from_json(bv, statics: list, emit_status=print):
    """ Import statics from JSON written in the V1 format. """
    with recording_undo(bv) as rec:
        return _import_symbols_from_json_v1(bv, statics, bn.SymbolType.DataSymbol, rec=rec, emit_status=emit_status)

def _import_symbols_from_json_v1(bv: bn.BinaryView, symbols: list, symbol_type: bn.SymbolType, rec: UndoRecorder, emit_status=None):
    changed = False
    for d in symbols:
        addr = int(d['addr'], 16)
        name = d['name']
        ty = bv.parse_type_string(d['type'])[0] if 'type' in d else None

        existing_symbol = bv.get_symbol_at(addr)
        existing_data_var = bv.get_data_var_at(addr)
        if existing_symbol is not None:
            existing_name = existing_symbol.name
            if name == existing_name:
                if any([
                    existing_data_var is None and ty is None,
                    ty is not None and str(ty) == str(existing_data_var.type)
                ]):
                    continue
            else:
                if existing_data_var is not None:
                    bv.undefine_data_var(addr)
                    rec.enable_auto_rollback()

                if ty is None:
                    bv.define_user_symbol(bn.Symbol(symbol_type, addr, name))
                    rec.enable_auto_rollback()
                else:
                    assert symbol_type == bn.SymbolType.DataSymbol
                    bv.define_data_var(addr, ty, name)
                    rec.enable_auto_rollback()
                changed = True
                if emit_status:
                    emit_status(f'rename {existing_name} => {name}')
        else:
            bv.define_user_symbol(bn.Symbol(symbol_type, addr, name))
            rec.enable_auto_rollback()
            changed = True
            if emit_status:
                emit_status(f'define {name}')
    return changed

# =================================================

def import_structs_from_json(bv: bn.BinaryView, structs: dict, emit_status=print):
    """ Import structs from JSON written in the V1 format. """
    return _import_structs_from_json_v1(bv, structs, emit_status=emit_status)

def _import_structs_from_json_v1(bv: bn.BinaryView, structs: dict, emit_status=None):
    """ Import structs from JSON written in the V1 format. """
    changed = False
    with recording_undo(bv) as rec:
        # Forward-declare types so that they can be parsed when they refer to each other
        for name, members in structs.items():
            existing_type = bv.get_type_by_name(name)
            if existing_type is None:
                bv.define_user_type(name, bn.StructureBuilder.create())
                rec.enable_auto_rollback()
                changed = True

        for name, members in structs.items():
            changed = changed | _import_struct_from_json_v1(bv, name, members, rec=rec, emit_status=emit_status)
        return changed

def _import_struct_from_json_v1(bv: bn.BinaryView, name: str, members: list, rec: UndoRecorder, emit_status):
    new_type = _structure_from_cereal_v1(bv, members)

    existing_type = bv.get_type_by_name(name)
    if existing_type is not None:
        if not isinstance(existing_type, bn.StructureType):
            raise RuntimeError(f'Type {name} already exists but is not a struct!')

        existing_members = structure_to_cereal_v1(existing_type, filters=DEFAULT_FILTERS, _name_for_debug=name)
        if existing_members == members:
            return False

        if emit_status:
            get_offset = lambda item: item[0]
            _report_changes_to_struct(name, existing_members, members, get_offset=get_offset, emit_status=emit_status)

    bv.define_user_type(name, new_type)
    rec.enable_auto_rollback()
    return True

def _structure_from_cereal_v1(bv: bn.BinaryView, members: list) -> bn.StructureType:
    builder = bn.StructureBuilder.create()
    for offset, name, type_str in members:
        offset = int(offset, 16)

        match [name, type_str]:
            case ["__unknown", None]:
                pass
            case ["__end", None]:
                builder.width = offset
            case [name, type_str]:
                assert isinstance(name, str), f"field name should be str, not {type(name)}!"
                assert isinstance(type_str, str), f"field type should be str, not {type(type_str)}!"
                ty, _ = bv.parse_type_string(type_str)
                builder.insert(offset, ty, name)

    return builder.immutable_copy()


def import_bitfields_from_json(bv: bn.BinaryView, bitfields: dict, emit_status=print):
    """ Import bitfields from JSON written in the V1 format. """
    return _import_all_bitfields_from_json_v1(bv, bitfields, emit_status=emit_status)

def _import_all_bitfields_from_json_v1(bv: bn.BinaryView, bitfields: dict, emit_status=None):
    """ Import bitfields from JSON written in the V1 format. """
    changed = False
    with recording_undo(bv) as rec:
        for name, members in bitfields.items():
            changed = changed | _import_bitfields_from_json_v1(bv, name, members, rec=rec, emit_status=emit_status)
        return changed

def _import_bitfields_from_json_v1(bv: bn.BinaryView, name: str, members: list, rec: UndoRecorder, emit_status):
    new_type = _bitfields_from_cereal_v1(bv, members)

    existing_type = bv.get_type_by_name(name)
    if existing_type is not None:
        if not isinstance(existing_type, bn.EnumerationType):
            raise RuntimeError(f'Type {name} already exists but is not an enum!')

        existing_members = enum_to_bitfields_cereal_v1(existing_type, _name_for_debug=name)
        if existing_members == members:
            return False

        if emit_status:
            get_offset = lambda item: item[0]
            _report_changes_to_struct(name, existing_members, members, get_offset=get_offset, emit_status=emit_status)

    bv.define_user_type(name, new_type)
    rec.enable_auto_rollback()
    return True

def _bitfields_from_cereal_v1(bv: bn.BinaryView, members: list) -> bn.EnumerationType:
    assert members[-1][2] == '__end'
    assert members[-1][0] % 8 == 0
    width = members[-1][0] // 8

    builder = bn.EnumerationBuilder.create(width=width)
    builder.append(ENUM_IS_BITFIELDS_NAME, ENUM_IS_BITFIELDS_VALUE)
    for (offset, sign_str, name), (next_offset, _, _) in window2(members):
        match [name, sign_str]:
            case ["__unknown", None]:
                pass
            case ["__end", None]:
                pass
            case [name, sign_str]:
                assert isinstance(name, str), f"bitfield name should be str, not {type(name)}!"
                assert isinstance(sign_str, str), f"bitfield sign should be str, not {type(sign_str)}!"
                assert sign_str[0] in 'iu', f"bitfield sign should be 'i' or 'u', not {repr(sign_str)}"
                signed = sign_str[0] == 'i'
                size = next_offset - offset

                # sign str may be 'i' (for ease of writing definitions), or 'i6' (what we export)
                if len(sign_str) > 1:
                    assert int(sign_str[1:]) == size, f"mismatched size for field {repr(name)}"

                bf = EnumBitfield(start=offset, size=next_offset-offset, signed=signed, name=name)
                builder.append(bf.name_in_binja(), bf.value_in_binja())

    return builder.immutable_copy()


def _diff_two_struct_jsons_v1(a_members: list, b_members: list, get_offset):
    # We need peekable iteration so we can choose which one to advance.
    # That's hard to do with iterators in python so we use indices.
    a_index = 0
    b_index = 0

    def handle_identical():
        nonlocal a_index, b_index
        a_index += 1
        b_index += 1

    def handle_deletion():
        nonlocal a_index
        a_index += 1
        yield '-', a_members[a_index - 1]

    def handle_addition():
        nonlocal b_index
        b_index += 1
        yield '+', b_members[b_index - 1]

    while a_index < len(a_members) or b_index < len(b_members):
        a_has_more = a_index < len(a_members)
        b_has_more = b_index < len(b_members)

        if not b_has_more:
            yield from handle_deletion()
            continue
        if not a_has_more:
            yield from handle_addition()
            continue

        a_offset = get_offset(a_members[a_index])
        b_offset = get_offset(b_members[b_index])

        # unchanged members
        if a_members[a_index] == b_members[b_index]:
            handle_identical()
            continue

        if a_offset <= b_offset:
            yield from handle_deletion()
            continue
        else:
            yield from handle_addition()
            continue

def _report_changes_to_struct(struct_name: str, a_members: list, b_members: list, get_offset, emit_status):
    for diffchar, member in _diff_two_struct_jsons_v1(a_members, b_members, get_offset):
        emit_status(f'struct {struct_name}: {diffchar} {member}')
