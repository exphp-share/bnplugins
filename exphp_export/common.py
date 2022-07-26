import os
import typing as tp

import binaryninja as bn

TAG_KEYWORD = 'is'
TypeTree = tp.Dict
PathLike = tp.Union[str, os.PathLike]
T = tp.TypeVar('T')

ENUM_IS_BITFIELDS_NAME = '__IS_BITFIELD'
ENUM_IS_BITFIELDS_VALUE = 0

def lookup_named_type_definition(bv: bn.BinaryView, name: bn.QualifiedName) -> tp.Tuple[str, tp.Optional[bn.Type]]:
    """
    Look up a named type, while dealing with all of binary ninja's typedef oddities.

    This is the most proper way to look up the definition of a struct/enum/typedef!
    QualifiedNames are superior to type ids for this purpose, because there are certain kinds
    of typedefs that are impossible to recover from a type_id due to auto-expansion.

    Returns ``[kind, expansion_type]``, where ``kind`` is one of ``'struct', 'union', 'enum', 'typedef'``.
    In the case of ``'typedef'``, you should ignore the type binja returns from name and type-id lookups,
    because it is difficult to work with. ``expansion_type`` is an additional payload for ``'typedef'``
    which represents the type that the typedef expands into. (it is ``None`` for other kinds)
    """
    ty = bv.get_type_by_name(name)

    match ty:
        # Binja wouldn't have auto-expanded a typedef referring to a struct or enum,
        # so in these cases we can be sure that 'name' refers to the struct/enum itself.
        case bn.EnumerationType():
            if ty.members[0].name == ENUM_IS_BITFIELDS_NAME and ty.members[0].value == ENUM_IS_BITFIELDS_VALUE:
                return ('bitfields', None)
            else:
                return ('enum', None)
        case bn.StructureType():
            return ({
                bn.StructureVariant.StructStructureType: 'struct',
                bn.StructureVariant.UnionStructureType: 'union',
            }[ty.type], None)

        # If we make it here, it's a typedef.
        #
        # When you lookup a typedef (either by name or type_id), the following occurs:
        #
        # - If the expansion of the typedef is itself a named type (struct, enum, typedef),
        #   binja returns a NamedTypeReference representing the typedef itself. (not the target!)
        # - Otherwise, binja returns a type representing the expansion (and you lose
        #   all context related to the typedef)
        case bn.NamedTypeReferenceType() if ty.registered_name and ty.registered_name.name == name:
            # This is the typedef itself.  We want the expansion!
            #
            # Thankfully, we know that the resulting type is named, so we can call
            # 'Type.named_type_from_registered_type' which is one of the very few methods capable
            # of producing an unexpanded typedef that points to an unnamed type.
            # (dodging a nasty corner case when dealing with a typedef to a typedef to an unnamed type)
            expn_type_name = ty.name
            return ('typedef', bn.Type.named_type_from_registered_type(bv, expn_type_name))
        case _:
            # This is the expansion.
            return ('typedef', ty)

def lookup_type_id(bv: bn.BinaryView, type_id):
    """
    Look up a type by type id.  This will always produce a NamedTypeReference for typedefs,
    even when the normal lookup mechanism wouldn't.
    """
    name = bv.get_type_name_by_id(type_id)
    if name:
        ty = bv.get_type_by_name(name)
        # See comments in lookup_named_type_definition
        if ty.type_class not in [
            bn.TypeClass.StructureTypeClass,    # a struct/union (and not a typedef to one)
            bn.TypeClass.EnumerationTypeClass,  # a enum (and not a typedef to one)
        ]:
            # We enter this branch IFF it is a typedef.
            # 'ty' is unreliable but the following is guaranteed to work
            return bn.Type.named_type_from_registered_type(bv, name)

    # Not a typedef, so we can trust the normal lookup.
    return bv.get_type_by_id(type_id)

def resolve_actual_enum_values(members: tp.Iterable[bn.EnumerationMember]) -> tp.Iterator[bn.EnumerationMember]:
    """ Replace all `None`'s in an enumeration's member list with their actual integer values. """
    next_auto = 0
    for member in members:
        value = member.value if member.value is not None else next_auto
        next_auto = value + 1
        yield bn.EnumerationMember(name=member.name, value=value)

def window2(it: tp.Iterable[T]) -> tp.Iterator[tp.Tuple[T, T]]:
    it = iter(it)
    prev = next(it)
    for x in it:
        yield prev, x
        prev = x
