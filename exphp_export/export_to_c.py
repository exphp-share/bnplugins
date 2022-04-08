import os
import re
import itertools
import binaryninja as bn

from .config import SymbolFilters, DEFAULT_FILTERS
from .common import lookup_named_type_definition, window2, resolve_actual_enum_values
from .export_types import _structure_fields
from .export_types import GAP_MEMBER_NAME, PADDING_MEMBER_NAME

def make_c_header_zip(bvs, games, outpath, filters: SymbolFilters = DEFAULT_FILTERS):
    from zipfile import ZipFile
    from io import StringIO

    bvs = list(bvs)
    games = list(games)
    assert len(bvs) == len(games)

    dirname_inside_zip = os.path.splitext(os.path.basename(outpath))[0]
    zipObj = ZipFile(outpath, 'w')
    for bv, game in zip(bvs, games):
        ofile = StringIO()
        export_everything_to_c_syntax(bv, ofile=ofile, filters=filters)
        text = ofile.getvalue()
        zipObj.writestr(f'{dirname_inside_zip}/{game}.h', text)
    zipObj.close()

def export_everything_to_c_syntax(bv: bn.BinaryView, ofile, filters: SymbolFilters):
    emit = lambda *args, **kw: print(*args, file=ofile, **kw)

    filter_re = re.compile('^(z|IDirect|D3D)')
    all_types = bv.types  # precompute computed property
    all_types = {key: all_types[key] for key in bv.types.keys() if filter_re.match(str(key))}
    for name, typ in bv.types.items():
        kind, expansion = lookup_named_type_definition(bv, name)
        if kind != 'typedef':
            emit(f'{kind} {name};')

    emit()
    for name, typ in all_types.items():
        kind, expansion = lookup_named_type_definition(bv, name)
        if kind == 'typedef':
            emit(f'typedef {_format_c_style_declaration(expansion, name)};')

    emit()
    for name, typ in all_types.items():
        kind, expansion = lookup_named_type_definition(bv, name)
        if kind == 'typedef':
            continue

        is_packed = kind == 'struct' and typ.packed
        emit(f'{kind} {name} {"__packed " if is_packed else ""}{{')

        if kind == 'struct':
            _struct_members_to_c_syntax(typ, emit=emit, filters=filters)
        elif kind == 'union':
            _union_members_to_c_syntax(typ, emit=emit)
        elif kind == 'enum':
            for constant in resolve_actual_enum_values(typ.members):
                emit(f'    {constant.name} = {constant.value},')
        else:
            assert False

        emit(f'}};  // {typ.width:#x}')
        emit()

def _struct_members_to_c_syntax(structure: bn.StructureType, emit, filters: SymbolFilters):
    # Use _structure_fields to identify gaps and padding
    ignore = lambda name, type: not filters.is_useful_struct_member(name, type)
    rows = list(_structure_fields(structure, ignore=ignore))
    assert structure.width % structure.alignment == 0

    members = [m for m in structure.members if filters.is_useful_struct_member(m.name, m.type)]

    # Make sure we are capable of matching
    assert len(members) == len([row for row in rows if row.type is not None])
    members_iter = iter(members)
    gap_indices = itertools.count(0)
    for row, nextRow in window2(rows):
        if row.type is None:
            if row.name == GAP_MEMBER_NAME:
                size = nextRow.offset - row.offset
                emit(f'    char __gap_{next(gap_indices)}[{size:#x}];  // {row["offset"]:#x}')
            elif row.name == PADDING_MEMBER_NAME:
                pass
            else: assert False, row.name
            continue

        member = next(members_iter)
        line = f'    {_format_c_style_declaration(member.type, member.name)};  // {member.offset:#x}'
        if not ('zCOMMENT' in line and nextRow['offset'] == row['offset']):
            emit(line)

    # make sure the two iterators didn't fall out of sync
    _expect_empty_iterator(members_iter)

def _union_members_to_c_syntax(structure: bn.StructureType, emit):
    for member in structure.members:
        emit(f'    {_format_c_style_declaration(member.type, member.name)};')

def _format_c_style_declaration(type: bn.Type, name):
    before = type.get_string_before_name()
    after = type.get_string_after_name()
    return f'{before} {name}{after}'

def _expect_empty_iterator(it):
    try:
        value = next(it)
        raise RuntimeError(f'leftover values in iterator: {repr([value] + list(it))}')
    except StopIteration:
        pass # expected
