import os
import typing as tp

import binaryninja as bn

TAG_KEYWORD = 'is'
TypeTree = tp.Dict
PathLike = tp.Union[str, os.PathLike]

def lookup_named_type_definition(bv, name: bn.QualifiedName) -> tp.Tuple[str, tp.Optional[bn.Type]]:
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

    # Binja wouldn't have auto-expanded a typedef referring to a struct or enum,
    # so in these cases we can be sure that 'name' refers to the struct/enum itself.
    if ty.type_class == bn.TypeClass.EnumerationTypeClass:
        return ('enum', None)
    elif ty.type_class == bn.TypeClass.StructureTypeClass:
        return ('union' if ty.structure.union else 'struct', None)

    # If we make it here, it's a typedef.
    #
    # When you lookup a typedef (either by name or type_id), the following occurs:
    #
    # - If the expansion of the typedef is itself a named type (struct, enum, typedef),
    #   binja returns a NamedTypeReference representing the typedef itself. (not the target!)
    # - Otherwise, binja returns a type representing the expansion (and you lose
    #   all context related to the typedef)
    if (
        ty.type_class == bn.TypeClass.NamedTypeReferenceClass
        and ty.registered_name
        and ty.registered_name.name == name
    ):
        # This is the typedef itself.  We want the expansion!
        #
        # Thankfully, we know that the resulting type is named, so we can call
        # 'Type.named_type_from_registered_type' which is one of the very few methods capable
        # of producing an unexpanded typedef that points to an unnamed type.
        # (dodging a nasty corner case when dealing with a typedef to a typedef to an unnamed type)
        expn_type_name = ty.named_type_reference.name
        return ('typedef', bn.Type.named_type_from_registered_type(bv, expn_type_name))
    else:
        # This is the expansion.
        return ('typedef', ty)

def lookup_type_id(bv, type_id):
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

def window2(it):
    it = iter(it)
    prev = next(it)
    for x in it:
        yield prev, x
        prev = x
