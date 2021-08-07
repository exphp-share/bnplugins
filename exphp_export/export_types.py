import typing as tp
import re

from binaryninja import (
    BinaryView, Type, log, TypeClass,
    FunctionParameter, QualifiedName,
)

from .common import TAG_KEYWORD, TypeTree, lookup_named_type_definition, window2

def create_types_file_json(
        bv: BinaryView,
        types_to_export: tp.Mapping[QualifiedName, Type],
        common_types: tp.Dict[str, TypeTree] = {},
):
    """ Write a single file like ``types-own.json`` for the given types. """
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
            cereal.update(structure_to_cereal(ty.structure, ttree_converter, _name_for_debug=type_name))
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

def structure_to_cereal(structure, ttree_converter, _name_for_debug=None):
    ignore = lambda name, ty: name and ty and ty.element_type and name.startswith('_') and ty.element_type.width == 1 and ty.width > 64

    fields_iter = _structure_fields(structure, ignore=ignore, _name_for_debug=_name_for_debug)
    output_members = []
    for d in fields_iter:
        ty_json = None if d['type'] is None else ttree_converter.to_ttree(d['type'])

        out_row = {} if structure.union else {'offset': hex(d['offset'])}
        out_row.update({'name': d['name'], 'type': ty_json})
        output_members.append(out_row)

    out = {}
    if structure.packed:
        out['packed'] = True
    out['members'] = output_members
    return out

# I use a plugin to fill extremely large gaps with char arrays to make the UI navigable.
# These should be counted as gaps.
def member_is_auto_inserted_filler(name, ty):
    return name and ty and ty.element_type and name.startswith('_') and ty.element_type.width == 1 and ty.width > 64

GAP_MEMBER_NAME = '__unknown'
PADDING_MEMBER_NAME = '__padding'
END_MEMBER_NAME = '__end'

def _structure_fields(
        structure,
        ignore=lambda name, ty: False,  # field-ignoring predicate
        _name_for_debug=None,  # struct name, used only for diagnostic purposes
):
    # Include a fake field at the max offset to help simplify things
    effective_members = [(x.offset, x.name, x.type) for x in structure.members]
    effective_members.append((structure.width, None, None))

    effective_members = [(off, name, ty) for (off, name, ty) in effective_members if not ignore(name, ty)]

    if not structure.packed and structure.width % structure.alignment != 0:
        # binary ninja allows width to not be a multiple of align, which makes arrays UB
        log.log_error(f'unpacked structure {_name_for_debug or ""} has width {structure.width} but align {structure.alignment}')

    # I use a plugin to fill extremely large gaps with char arrays to make the UI navigable.
    # These should be counted as gaps.
    is_filler = lambda name, ty: name and ty and ty.element_type and name.startswith('_') and ty.element_type.width == 1 and ty.width > 64
    effective_members = [(off, name, ty) for (off, name, ty) in effective_members if not is_filler(name, ty)]

    # Edge case: First thing not at offset zero (or no members)
    if effective_members[0][0] != 0:
        yield {'offset': 0, 'name': GAP_MEMBER_NAME, 'type': None}

    for (offset, name, ty), (next_offset, _, next_ty) in window2(effective_members):
        yield {'offset': offset, 'name': name, 'type': ty}
        if structure.union:
            continue # no gaps for unions

        # A gap may follow, but in a non-packed struct it may be identifiable as padding
        gap_start = offset + ty.width
        gap_name = GAP_MEMBER_NAME
        if not structure.packed:
            # note: next_ty is None at end of struct, which has alignment of the entire structure so that arrays can work
            alignment = next_ty.alignment if next_ty else structure.alignment
            padding_end = gap_start + (0 if gap_start % alignment == 0 else alignment - (gap_start % alignment))
            if next_offset == padding_end:
                gap_name = PADDING_MEMBER_NAME

        if next_offset != gap_start:
            yield {'offset': offset + ty.width, 'name': gap_name, 'type': None}

    if not structure.union:
        yield {'offset': structure.width, 'name': END_MEMBER_NAME, 'type': None}


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
        if ty.type_class == TypeClass.ArrayTypeClass:
            return {TAG_KEYWORD: 'array', 'len': ty.count, 'inner': self._to_ttree_nested(ty.element_type)}

        elif ty.type_class == TypeClass.PointerTypeClass:
            # FIXME this check should probably resolve NamedTypeReferences in the target,
            # in case there are typedefs to bare (non-ptr) function types.
            if ty.target.type_class == TypeClass.FunctionTypeClass:
                return self._function_ptr_type_to_ttree(ty.target)

            d = {TAG_KEYWORD: 'ptr', 'inner': self._to_ttree_nested(ty.target)}
            if ty.const:
                d['const'] = True
            return d

        elif ty.type_class == TypeClass.NamedTypeReferenceClass:
            if ty.registered_name is not None:
                # A raw typedef, instead of a reference to one.
                # Typically to get this, you'd have to call `bv.get_type_by_name` on a typedef name.
                #
                # It's not clear when type_to_ttree would ever be called with one.
                return {TAG_KEYWORD: 'named', 'name': str(ty.registered_name.name)}
            # could be a 'struct Ident' field, or a regular typedef
            return {TAG_KEYWORD: 'named', 'name': str(ty.named_type_reference.name)}

        elif ty.type_class in [TypeClass.StructureTypeClass, TypeClass.EnumerationTypeClass]:
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
            if ty.type_class == TypeClass.EnumerationTypeClass:
                output[TAG_KEYWORD] = 'enum'
                output.update(enum_to_cereal(ty.enumeration))
            else:
                assert ty.type_class == TypeClass.StructureTypeClass
                output[TAG_KEYWORD] = 'union' if ty.structure.union else 'struct'
                output.update(structure_to_cereal(ty.structure, self))
            assert output[TAG_KEYWORD] is not None
            return output

        elif ty.type_class == TypeClass.VoidTypeClass:
            return {TAG_KEYWORD: 'void'}
        elif ty.type_class == TypeClass.IntegerTypeClass:
            return {TAG_KEYWORD: 'int', 'signed': bool(ty.signed), 'size': ty.width}
        elif ty.type_class == TypeClass.FloatTypeClass:
            return {TAG_KEYWORD: 'float', 'size': ty.width}
        elif ty.type_class == TypeClass.BoolTypeClass:
            return {TAG_KEYWORD: 'int', 'signed': False, 'size': ty.width}
        elif ty.type_class == TypeClass.WideCharTypeClass:
            return {TAG_KEYWORD: 'int', 'signed': False, 'size': ty.width}

        elif ty.type_class == TypeClass.FunctionTypeClass:
            raise RuntimeError(f"bare FunctionTypeClass not supported (only function pointers): {ty}")
        elif ty.type_class == TypeClass.ValueTypeClass:
            # not sure where you get one of these
            raise RuntimeError(f"ValueTypeClass not supported: {ty}")
        elif ty.type_class == TypeClass.VarArgsTypeClass:
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
            parameters[0] = FunctionParameter(parameters[0].type, parameters[0].name)  # remove location

        def convert_parameter(p):
            out = {'type': self._to_ttree_flat(p.type)}
            if p.name:
                out['name'] = p.name
            return out

        out = {TAG_KEYWORD: 'fn-ptr'}

        if abi:
            out['abi'] = abi

        out['ret'] = self._to_ttree_flat(func_ty.return_value)

        if parameters:
            out['params'] = list(map(convert_parameter, parameters))

        return out

# Turn a nested object ttree into a list. (destructively)
def _possibly_flatten_nested_ttree(ttree):
    return ttree  # don't implement flattening for now
# def _possibly_flatten_nested_ttree(ttree):
#     if isinstance(ttree, dict) and 'inner' in ttree:
#         flattened = []
#         while isinstance(ttree, dict) and 'inner' in ttree:
#             flattened.append(ttree)
#             ttree = ttree.pop('inner')
#         flattened.append(ttree)
#         return flattened
#     return ttree

# assert (
#     _possibly_flatten_nested_ttree({'a': 1, 'inner': {'b': 2, 'inner': {'c': 3}}})
#     == [{'a': 1}, {'b': 2}, {'c': 3}]
# )

def _further_abbreviate_flattened_ttree(ttree):
    return ttree  # don't implement abbreviations for now
# def _further_abbreviate_flattened_ttree(ttree):
#     if isinstance(ttree, list):
#         out = []
#         for x in ttree:
#             if x == {'type': 'ptr'}:
#                 out.append('*')
#             elif isinstance(x, dict) and len(x) == 2 and x['type'] == 'array':
#                 out.append(x['len'])
#             else:
#                 out.append(x)
#         return out
#     return ttree

# Turn a list ttree into a nested object. (destructively)
def _possibly_nest_flattened_ttree(ttree):
    return ttree
# def _possibly_nest_flattened_ttree(ttree):
#     if isinstance(ttree, list):
#         out = ttree.pop()
#         while ttree:
#             new_out = ttree.pop()
#             assert isinstance(new_out, dict) and 'inner' not in new_out
#             new_out['inner'] = out
#             out = new_out
#         return out
#     return ttree
