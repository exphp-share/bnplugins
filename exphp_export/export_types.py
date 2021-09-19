import typing as tp
import re

from binaryninja import log
import binaryninja as bn

from .common import TAG_KEYWORD, TypeTree, lookup_named_type_definition, window2
from .config import DEFAULT_FILTERS, SymbolFilters, SimpleFilters

# ==============================================================================

def create_types_file_json(
        bv: bn.BinaryView,
        types_to_export: tp.Mapping[bn.QualifiedName, bn.Type],
        common_types: tp.Dict[str, TypeTree] = {},
        filters: SymbolFilters = DEFAULT_FILTERS,
):
    """ Write a single file like ``types-own.json`` for the given types. """
    return _create_types_file_json(bv, types_to_export, common_types, filters)

def _create_types_file_json(
        bv: bn.BinaryView,
        types_to_export: tp.Mapping[bn.QualifiedName, bn.Type],
        common_types: tp.Dict[str, TypeTree],
        filters: SymbolFilters,
):
    ttree_converter = TypeToTTreeConverter(bv)

    types = {}
    for (type_name, ty) in types_to_export.items():
        classification, expanded_ty = lookup_named_type_definition(bv, type_name)
        cereal = {
            TAG_KEYWORD: classification,
            'size': hex(ty.width),
            'align': ty.alignment,
        }
        if classification == 'struct' or classification == 'union':
            cereal.update(structure_to_cereal(ty.structure, ttree_converter, _name_for_debug=type_name, filters=filters))
        elif classification == 'enum':
            cereal.update(enum_to_cereal(ty))
        elif classification == 'typedef':
            cereal['type'] = ttree_converter.to_ttree(expanded_ty)

        types[str(type_name)] = cereal

    # Exclude types that already have matching definitions in common/
    for key in list(types):
        if types[key] == common_types.get(key):
            del types[key]

    return types

def enum_to_cereal(enumeration_ty):
    return {
        'signed': bool(enumeration_ty.signed),
        'values': [{'name': m.name, 'value': m.value} for m in enumeration_ty.enumeration.members],
    }

def structure_to_cereal(structure, ttree_converter: 'TypeToTTreeConverter', filters: SymbolFilters, _name_for_debug=None):
    keep = lambda name, ty: structure.union or filters.is_useful_struct_member(name, ty)
    ignore = lambda name, ty: not keep(name, ty)

    fields_iter = _structure_fields(structure, ignore=ignore, _name_for_debug=_name_for_debug)
    output_members = []
    for d in fields_iter:
        ty_json = None if d['type'] is None else ttree_converter.to_ttree(d['type'])

        out_row: tp.Dict[str, tp.Any] = {} if structure.union else {'offset': hex(d['offset'])}
        out_row.update({'name': d['name'], 'type': ty_json})
        output_members.append(out_row)

    out = {'packed': structure.packed, 'members': output_members}
    if not out['packed']:
        del out['packed']
    out['members'] = output_members
    return out

GAP_MEMBER_NAME = '__unknown'
PADDING_MEMBER_NAME = '__padding'
END_MEMBER_NAME = '__end'

class StructureField(tp.NamedTuple):
    offset: int
    name: str
    # This is None for things like the end marker and padding.
    # Parsing scripts can look at `name` to distinguish between the various special cases.
    type: tp.Optional[bn.Type]

def _structure_fields(
        structure: bn.Structure,
        ignore,  # field-ignoring predicate
        _name_for_debug=None,  # struct name, used only for diagnostic purposes
):
    if ignore is None:
        ignore = lambda name, ty: False

    end_marker = StructureField(offset=structure.width, name=END_MEMBER_NAME, type=None)

    # Ignore some fields.
    # A fake field at the max offset which helps simplify some things
    effective_members = [StructureField(offset=x.offset, name=x.name, type=x.type) for x in structure.members]
    effective_members = [m for m in effective_members if not ignore(m.name, m.type)]
    effective_members.append(end_marker)

    if not structure.packed and structure.width % structure.alignment != 0:
        # binary ninja allows width to not be a multiple of align, which makes arrays UB
        log.log_error(f'unpacked structure {_name_for_debug or ""} has width {structure.width} but align {structure.alignment}')

    # Edge case: First thing not at offset zero (or no members)
    if effective_members[0].offset != 0:
        yield StructureField(offset=0, name=GAP_MEMBER_NAME, type=None)

    for field, next_field in window2(effective_members):
        yield field
        if structure.union:
            continue # no gaps for unions

        # A gap may follow, but in a non-packed struct it may be identifiable as padding
        assert field.type  # in effective_members, only the end marker has None type
        gap_start = field.offset + field.type.width
        gap_name = GAP_MEMBER_NAME
        if not structure.packed:
            # note: next_ty is None at end of struct, which has alignment of the entire structure so that arrays can work
            alignment = next_field.type.alignment if next_field.type else structure.alignment
            padding_end = gap_start + (0 if gap_start % alignment == 0 else alignment - (gap_start % alignment))
            if next_field.offset == padding_end:
                gap_name = PADDING_MEMBER_NAME

        if next_field.offset != gap_start:
            yield StructureField(offset=field.offset + field.type.width, name=gap_name, type=None)

    if not structure.union:
        # Also put an end marker in the output because it's useful to downstream code
        yield end_marker

TTREE_VALID_ABBREV_REGEX = re.compile(r'^[_\$#:a-zA-Z][_\$#:a-zA-Z0-9]*$')

class TypeToTTreeConverter:
    def __init__(self, bv):
        self.bv = bv

    def to_ttree(self, ty):
        return self._to_ttree_flat(ty)

    def _to_ttree_flat(self, ty):
        ttree = self._to_ttree_nested(ty)
        ttree = _possibly_flatten_nested_ttree(ttree)
        ttree = _further_abbreviate_flattened_ttree(ttree)
        return ttree

    # Produces a typetree where the outermost node is not a list.
    #
    # Recursive calls should use '_to_ttree_flat' if and only if they are a place that
    # cannot be chained through.  (e.g. an object field not called 'inner').
    # Otherwise they should use '_to_ttree_nested'.
    def _to_ttree_nested(self, ty):
        if ty.type_class == bn.TypeClass.ArrayTypeClass:
            return {TAG_KEYWORD: 'array', 'len': ty.count, 'inner': self._to_ttree_nested(ty.element_type)}

        elif ty.type_class == bn.TypeClass.PointerTypeClass:
            # FIXME this check should probably resolve NamedTypeReferences in the target,
            # in case there are typedefs to bare (non-ptr) function types.
            if ty.target.type_class == bn.TypeClass.FunctionTypeClass:
                return self._function_ptr_type_to_ttree(ty.target)

            d = {TAG_KEYWORD: 'ptr', 'inner': self._to_ttree_nested(ty.target), 'const': ty.const}
            if not d['const']:
                del d['const']
            return d

        elif ty.type_class == bn.TypeClass.NamedTypeReferenceClass:
            if ty.registered_name is not None:
                # A raw typedef, instead of a reference to one.
                # Typically to get this, you'd have to call `bv.get_type_by_name` on a typedef name.
                #
                # It's not clear when type_to_ttree would ever be called with one.
                return {TAG_KEYWORD: 'named', 'name': str(ty.registered_name.name)}
            # could be a 'struct Ident' field, or a regular typedef
            return {TAG_KEYWORD: 'named', 'name': str(ty.named_type_reference.name)}

        elif ty.type_class in [bn.TypeClass.StructureTypeClass, bn.TypeClass.EnumerationTypeClass]:
            if ty.registered_name is not None:
                # A raw struct, enum, or union declaration, instead of a reference to one.
                #
                # It's not clear when type_to_ttree would ever be called with this.
                return {TAG_KEYWORD: 'named', 'name': str(ty.registered_name.name)}

            # an anonymous struct/union/enum
            output = {
                TAG_KEYWORD: None,  # to be filled
                'size': hex(ty.width),
                'align': ty.alignment,
            }
            if ty.type_class == bn.TypeClass.EnumerationTypeClass:
                output[TAG_KEYWORD] = 'enum'
                output.update(enum_to_cereal(ty.enumeration))
            else:
                assert ty.type_class == bn.TypeClass.StructureTypeClass
                output[TAG_KEYWORD] = 'union' if ty.structure.union else 'struct'
                output.update(structure_to_cereal(ty.structure, self, filters=SimpleFilters()))
            assert output[TAG_KEYWORD] is not None
            return output

        elif ty.type_class == bn.TypeClass.VoidTypeClass:
            return {TAG_KEYWORD: 'void'}
        elif ty.type_class == bn.TypeClass.IntegerTypeClass:
            return {TAG_KEYWORD: 'int', 'signed': bool(ty.signed), 'size': ty.width}
        elif ty.type_class == bn.TypeClass.FloatTypeClass:
            return {TAG_KEYWORD: 'float', 'size': ty.width}
        elif ty.type_class == bn.TypeClass.BoolTypeClass:
            return {TAG_KEYWORD: 'int', 'signed': False, 'size': ty.width}
        elif ty.type_class == bn.TypeClass.WideCharTypeClass:
            return {TAG_KEYWORD: 'int', 'signed': False, 'size': ty.width}

        elif ty.type_class == bn.TypeClass.FunctionTypeClass:
            raise RuntimeError(f"bare FunctionTypeClass not supported (only function pointers): {ty}")
        elif ty.type_class == bn.TypeClass.ValueTypeClass:
            # not sure where you get one of these
            raise RuntimeError(f"ValueTypeClass not supported: {ty}")
        elif ty.type_class == bn.TypeClass.VarArgsTypeClass:
            # I don't know how you get this;  va_list is just an alias for char*,
            # and variadic functions merely set .has_variable_arguments = True.
            raise RuntimeError(f"VarArgsTypeClass not supported: {ty}")
        else:
            raise RuntimeError(f"Unsupported type {ty}")

    def _function_ptr_type_to_ttree(self, func_ty):
        parameters = list(func_ty.parameters)
        abi = func_ty.calling_convention and str(func_ty.calling_convention)

        if (abi == 'stdcall'
            and parameters
            and parameters[0].location
            and parameters[0].location.name == 'ecx'
            and not any(p.location for p in parameters[1:])
        ):
            abi = 'fastcall'
            parameters[0] = bn.FunctionParameter(parameters[0].type, parameters[0].name)  # remove location

        def convert_parameter(p):
            out = {'type': self._to_ttree_flat(p.type), 'name': p.name}
            if not out['name']:
                del out['name']
            return out

        out = {
            TAG_KEYWORD: 'fn-ptr',
            'abi': abi,
            'ret': self._to_ttree_flat(func_ty.return_value),
            'params': list(map(convert_parameter, parameters))
        }
        if not out['abi']: del out['abi']
        if not out['params']: del out['params']
        return out

# Turn a nested object ttree into a list. (destructively)
def _possibly_flatten_nested_ttree(ttree):
    # Note: These used to be implemented, use 'git log -S' or smth if you want them back. _/o\_
    return ttree  # don't implement flattening for now

def _further_abbreviate_flattened_ttree(ttree):
    return ttree  # don't implement abbreviations for now

# Turn a list ttree into a nested object. (destructively)
def _possibly_nest_flattened_ttree(ttree):
    return ttree  # don't implement for now

# # ==============================================================================
# # V1 types

# def structure_to_cereal_v1(structure: bn.Structure, filters: SymbolFilters, _name_for_debug=None):
#     assert not structure.union

#     keep = lambda name, ty: filters.is_useful_struct_member(name, ty)
#     ignore = lambda name, ty: not keep(name, ty)
#     fields = _structure_fields(structure, ignore, _name_for_debug=_name_for_debug)

#     return [(hex(member.offset), member.name)]
