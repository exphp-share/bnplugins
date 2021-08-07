from binaryninja import Type, TypeClass, Structure, log
from touhouReverseBnutil import recording_undo, add_label, get_type_reader, open_th_bv

def import_type(bv, source, name):
    """ Import one or more types (recursively) from another touhou game. """
    with recording_undo(bv) as rec:
        with open_th_bv(bv, source, update_analysis=False) as src_bv:
            import_type_from_bv(bv, src_bv, name, rec=rec)

def import_type(bv, source, name):
    """ Import one or more types (recursively) from another touhou game. """
    with recording_undo(bv) as rec:
        with open_th_bv(bv, source, update_analysis=False) as src_bv:
            import_type_from_bv(bv, src_bv, name, rec=rec)

def import_type_from_bv(dest_bv, src_bv, name, exist_ok=False, rec=None):
    """
    Import one or more types from another BinaryView.

    Preexisting types with matching names for any fields are reused.  Otherwise those
    field types are recursively imported. Circular types are okay. (e.g. pointers to self)
    """
    if isinstance(name, (list, tuple)):
        for n in name:
            import_type_from_bv(dest_bv, src_bv, n, exist_ok=True, rec=rec)
        return

    if dest_bv.get_type_by_name(name) is not None:
        if exist_ok:
            return
        raise RuntimeError(f'type {name} already exists in this bv. Delete it first if you want to replace.')

    src_type = src_bv.get_type_by_name(name)
    if src_type is None:
        raise RuntimeError(f'type {name} not found in source bv')

    if src_type.type_class == TypeClass.EnumerationTypeClass:
        raise RuntimeError(f'cannot import {name}: enum import not yet implemented')
    elif src_type.type_class == TypeClass.StructureTypeClass:
        dest_structure = Structure()
        dest_structure.packed = src_type.structure.packed

        # first add a dummy type in case it has pointers to itself (or pointers to things that point to it, etc.)
        dest_bv.define_user_type(name, Type.structure_type(dest_structure))
        if rec:
            rec.enable_auto_rollback()
        dest_structure = dest_structure.mutable_copy()

        offset_delta = 0
        for member in src_type.structure.members:
            src_member_type = member.type

            err_loc = f'member {member.name} of {name}'
            dest_member_type = _lookup_or_import_type(dest_bv, src_bv, src_member_type, rec=rec, err_loc=err_loc)
            if dest_member_type is None:
                raise RuntimeError(f'missing member type')
            dest_structure.insert(member.offset + offset_delta, dest_member_type, member.name)
            # if the destination BV had a pre-existing definition for a member's type and it is a different size from the source BV,
            # adjust future offsets accordingly.  This is for the case in version tracking where a struct gets a new member,
            # but many larger structs containing this struct are otherwise unchanged.
            offset_delta += dest_member_type.width - src_member_type.width

        dest_final_width = src_type.width + offset_delta
        assert dest_structure.width <= dest_final_width, ('{:x}'.format(dest_structure.width), '{:x}'.format(dest_final_width), '{:x}'.format(offset_delta))
        # (it is important to do this conditionally; 'width' is a property, and if it is already equal to dest_final_width
        #  then performing this assignment will chop off any zero-width members at the end of the struct)
        if dest_structure.width < dest_final_width:
            dest_structure.width = dest_final_width

        dest_bv.define_user_type(name, Type.structure_type(dest_structure))
        log.log_warn(f'Imported type {name}')
        return get_named_type_reference(dest_bv, name)
    else:
        raise RuntimeError(f'type {name} cannot be imported from source bv ({repr(src_type.type_class)})')

def _lookup_or_import_type(dest_bv, src_bv, src_type, rec=None, err_loc='<unknown>'):
    while src_type.type_class == TypeClass.NamedTypeReferenceClass:
        src_type = src_bv.get_type_by_id(src_type.named_type_reference.type_id)
        if src_type is None:
            raise RuntimeError(
                f'Possible stale type reference in {err_loc}, go fix its type in the original DB '
                'by opening the Change Type dialog on the variable, hitting Enter to confirm what\'s already there, and saving.'
            )

    klass = src_type.type_class

    if klass == TypeClass.ArrayTypeClass:
        return Type.array(_lookup_or_import_type(dest_bv, src_bv, src_type.element_type, rec=rec, err_loc='element type of ' + err_loc), src_type.count)

    elif klass == TypeClass.PointerTypeClass:
        return Type.pointer(dest_bv.arch, _lookup_or_import_type(dest_bv, src_bv, src_type.target, rec=rec, err_loc='target type of ' + err_loc))

    elif klass in [
        TypeClass.EnumerationTypeClass,
        TypeClass.StructureTypeClass,
    ]:
        # Use existing types when they exist rather than always recursively copying everything.
        # (e.g. maybe we're importing struct A which has a pointer to struct B, and B changed, but A didn't)
        if src_type.registered_name is None:
            raise RuntimeError(f'type {src_type} at {err_loc} has no registered name')

        name = src_type.registered_name.name
        existing_type = get_named_type_reference(dest_bv, name)
        if existing_type is not None:
            return existing_type

        return import_type_from_bv(dest_bv, src_bv, name, rec=rec)

    # don't know whether it's safe to just return the original for these simple cases
    elif klass == TypeClass.BoolTypeClass: return Type.bool()
    elif klass == TypeClass.FloatTypeClass: return Type.float(src_type.width)
    elif klass == TypeClass.IntegerTypeClass: return Type.int(src_type.width, src_type.signed)
    elif klass == TypeClass.VoidTypeClass: return Type.void()

    else:
        raise RuntimeError(f"don't know how to locally resolve {src_type}! {klass}")

# bv.get_type_by_name() returns a type that, if you try to use it as a member type, it will
# create a nested anonymous type. We actually want a NamedTypeReference. :/
def get_named_type_reference(bv, name, start=None, end=None, size=None):
    t = bv.get_type_by_name(name)
    if t is None:
        return None
    return Type.named_type(t.registered_name, width=t.width, align=t.alignment)

def make_struct_packed(bv, name, packed=True):
    type = bv.get_type_by_name(name)
    if type.structure is None:
        raise RuntimeError(f'{name} is not a struct')
    structure = type.structure.mutable_copy()
    structure.packed = packed
    bv.define_user_type(name, Type.structure_type(structure))

# ========================================================================

def factor_out_struct(bv, from_name, new_name, new_member='', *, start=None, end=None, size=None, autotrim=False):
    """
    Define a new struct by extracting a group of fields from another.

    :param from_name: The struct to extract fields from.
    :param new_name: The struct to create.
    :param new_member: Name for the new member in the original struct that will replace the extracted fields.
    :param autotrim:
        If True, instances of new_member are trimmed from the beginning of the field, possibly after underscores.
        (leading underscores are kept; underscores after new_member are removed)
    """
    start, end, size = _resolve_struct_offset_range(start, end, size)

    if from_name == new_name:
        raise ValueError(f"Cannot factor {new_name} out from itself!")

    from_struct = bv.get_type_by_name(from_name).structure
    new_struct = Structure()
    new_struct.width = size
    new_struct.packed = from_struct.packed
    for member in from_struct.members:
        if member.offset in range(start, end):
            if member.offset + member.type.width > end:
                raise RuntimeError(f'Requested region would split member {repr(member.name)}')
            n = member.name
            if autotrim:
                n = _strip_member_prefix(n, new_member)
            new_struct.insert(member.offset - start, member.type, n)
        elif member.offset >= end:
            pass
        elif member.offset + member.type.width > start:
            raise RuntimeError(f'Requested region would split member {repr(member.name)}')

    with recording_undo(bv) as rec:
        bv.define_user_type(new_name, Type.structure_type(new_struct))
        rec.enable_auto_rollback()

        # replace the fields in the original struct
        from_struct = from_struct.mutable_copy()
        from_struct.insert(start, get_named_type_reference(bv, new_name), new_member)
        bv.define_user_type(from_name, Type.structure_type(from_struct))

def _strip_member_prefix(name, prefix):
    import re
    trimmed = name.lstrip('_')
    leading_unders = len(name) - len(trimmed)
    if trimmed.startswith(prefix):
        trimmed = trimmed[len(prefix):]
        trimmed = trimmed.lstrip('_')

    if not trimmed:
        return name
    return '_' * leading_unders + trimmed

# ========================================================================

def delete_range_from_struct(bv, name, *, start=None, end=None, size=None, update_parents=True):
    """
    Delete a range of offsets from a struct.

    If update_parents=True, any struct containing this struct will have offsets and
    sizes adjusted accordingly. (otherwise, gaps are left behind)
    """
    with recording_undo(bv) as rec:
        if update_parents:
            return _delete_range_from_struct_with_parents(bv, name, base_start=start, base_end=end, base_size=size, rec=rec)
        else:
            return _delete_range_from_single_struct(bv, name, start=start, end=end, size=size, rec=rec)

def _delete_range_from_struct_with_parents(bv, base_name, *, base_start, base_end, base_size, rec=None):
    base_start, base_end, base_size = _resolve_struct_offset_range(base_start, base_end, base_size)

    dependents = _build_dependents_dag(bv)
    topological_order = _get_struct_dag_topological_order(bv, base_name, dependents)

    assert topological_order[0] == base_name
    all_changes = list(_get_struct_changes(bv, topological_order, base_name, base_end, base_size))

    # When deleting, we go in topological order.  Deleting a range from a child struct
    # will leave behind gaps in its dependents, which we later delete when the loop reaches them.
    for affected_name, changes in all_changes:
        # Go in descending order by offset to keep offsets stable
        for (end_offset, delta_size) in reversed(changes):
            _delete_range_from_single_struct(bv, affected_name, end=end_offset, size=delta_size, rec=rec)

def _delete_range_from_single_struct(bv, name, *, start=None, end=None, size=None, rec=None):
    start, end, size = _resolve_struct_offset_range(start, end, size)

    old_struct = bv.get_type_by_name(name).structure
    new_struct = Structure()
    new_struct.width = old_struct.width - size
    new_struct.packed = old_struct.packed

    if end > old_struct.width:
        raise ValueError(f'Range {hex(start)}:{hex(end)} is outside size of {name} ({hex(old_struct.width)})')
    for member in old_struct.members:
        rcmp = _range_cmp((member.offset, member.offset + member.type.width), (start, end))
        if rcmp in [RANGE_CUT_AFTER, RANGE_CUT_BEFORE, RANGE_AROUND]:
            raise RuntimeError(f'Requested region would split member {repr(member.name)}')
        elif rcmp in [RANGE_WITHIN, RANGE_EQUAL]:
            log.log_warn(f'Deleting field {member.name}')
            pass # entire field inside deleted range
        elif rcmp is RANGE_BEFORE:
            new_struct.insert(member.offset, member.type, member.name)
        elif rcmp is RANGE_AFTER:
            new_struct.insert(member.offset - size, member.type, member.name)

    bv.define_user_type(name, Type.structure_type(new_struct))
    if rec:
        rec.enable_auto_rollback()

def insert_space_in_struct(bv, name, start, size, *, update_parents=True):
    """
    Insert an empty region into a struct.

    If update_parents=True, any struct containing this struct will have offsets and
    sizes adjusted accordingly. (otherwise, members after an instance of the struct
    might get clobbered)
    """
    with recording_undo(bv) as rec:
        if update_parents:
            return _insert_space_in_struct_with_parents(bv, name, start, size, rec=rec)
        else:
            return _insert_space_in_single_struct(bv, name, start, size, rec=rec)

def _insert_space_in_struct_with_parents(bv, base_name, base_start, base_size, *, rec=None):
    dependents = _build_dependents_dag(bv)
    topological_order = _get_struct_dag_topological_order(bv, base_name, dependents)

    assert topological_order[0] == base_name
    all_changes = list(_get_struct_changes(bv, topological_order, base_name, base_start, base_size))

    # When inserting space, we reverse the list so that dependents are adjusted first.
    # (basically, we add space to the dependent, and then later when we increase the size
    #  of the dependency, it will harmlessly grow to fill that space rather than potentially
    #  clobbering other fields)
    for affected_name, changes in reversed(all_changes):
        # Go in descending order by offset to keep offsets stable
        for (end_offset, delta_size) in reversed(changes):
            _insert_space_in_single_struct(bv, affected_name, end_offset, delta_size, rec=rec)

def _insert_space_in_single_struct(bv, name, start, size, *, rec=None):
    assert size >= 0
    log.log_info(f'{name} at {start:#x}: +{size:#x}')

    old_struct = bv.get_type_by_name(name).structure
    new_struct = Structure()
    new_struct.width = old_struct.width + size
    new_struct.packed = old_struct.packed

    if start > old_struct.width:
        raise ValueError(f'Range {hex(start)} is outside size of {name} ({hex(old_struct.width)})')
    for member in old_struct.members:
        if start <= member.offset:  # listed first to ensure we insert before size-zero fields
            new_struct.insert(member.offset + size, member.type, member.name)
        elif member.offset + member.type.width <= start:  # <= to ensure we can go between fields
            new_struct.insert(member.offset, member.type, member.name)
        #elif member.offset < start < member.offset + member.type.width:
        else:
            raise RuntimeError(f'Requested offset would split member {repr(member.name)}')

    bv.define_user_type(name, Type.structure_type(new_struct))
    if rec:
        rec.enable_auto_rollback()

RANGE_EQUAL = object()   # a == b
RANGE_BEFORE = object()  # a is entirely after b (and not equal, if empty)
RANGE_AFTER = object()   # a is entirely before b (and not equal, if empty)
RANGE_WITHIN = object()  # a is contained within b (and not equal)
RANGE_AROUND = object()  # a contains b and more
RANGE_CUT_BEFORE = object()  # a is partially before b but there's overlap
RANGE_CUT_AFTER = object()   # a is partially after b but there's overlap
def _range_cmp(r1, r2):
    """ Compares (start1, end1) to (start2, end2).  Returns RANGE_EQUAL, RANGE_BEFORE, RANGE_AFTER,
    RANGE_WITHIN, RANGE_AROUND, RANGE_CUT_BEFORE, or RANGE_CUT_AFTER. """
    start1, end1 = r1
    start2, end2 = r2
    assert start1 <= end1
    assert start2 <= end2
    if (start1, end1) == (start2, end2): return RANGE_EQUAL
    if end1 <= start2: return RANGE_BEFORE
    if end2 <= start1: return RANGE_AFTER
    if start1 < start2 < end1 < end2: return RANGE_CUT_BEFORE
    if start2 < start1 < end2 < end1: return RANGE_CUT_AFTER
    if start1 < start2 or end2 < end1: return RANGE_AROUND
    if start2 < start1 or end1 < end2: return RANGE_WITHIN
    assert False, 'impossible!'

def _resolve_struct_offset_range(start=None, end=None, size=None):
    if [start, end, size].count(None) > 1:
        raise TypeError('Must supply two of: start, end, size')
    if [start, end, size].count(None) == 0 and start + size != end:
        raise TypeError('Mismatch between start, end, and size')
    if start is None: start = end - size
    if end is None: end = start + size
    if size is None: size = end - start
    return (start, end, size)

# -----

def _build_dependents_dag(bv):
    ty_dict = bv.types
    dependencies = {}
    for ty_name, ty in ty_dict.items():
        # NOTE: typedefs aren't supported, because I never use them for the
        #       types that I would use this functionality on, and they are tricky.
        #       (you can have e.g. typedefs to typedefs, typedefs to arrays... and
        #        even though they must be in the dep tree, they're not modified)
        #
        # It'd be nice if we could at least *detect* them and bail out (e.g. put them
        # in the dep tree, fail if they show up in the topological order), but that's a
        # lot of work for little benefit.
        if ty.type_class == TypeClass.StructureTypeClass:
            dependencies[ty_name] = set(name for (_, name, _) in _get_embedded_struct_fields(bv, ty.structure))
    dependents = _reverse_dag(dependencies)
    return dependents

def _reverse_dag(dag):
    from collections import defaultdict

    out = defaultdict(set)
    for source, targets in dag.items():
        for target in targets:
            out[target].add(source)
    return out

def _get_struct_dag_topological_order(bv, start_name, dependents):
    #dependents = _build_dependents_dag(bv)

    DONE = object()
    IN_PROGRESS = object()

    postorder = []
    colors = {}
    def visit(name):
        if name in colors:
            if colors[name] is DONE:
                return
            if colors[name] is IN_PROGRESS:
                raise RuntimeError(f'dependency cycle: struct {name} includes itself!')
            assert False, 'unreachable'

        colors[name] = IN_PROGRESS
        for target in dependents[name]:
            visit(target)
        postorder.append(name)
        colors[name] = DONE

    visit(start_name)

    return postorder[::-1]

# Given the fact that one struct's size is changing by some amount,
# determine the changes that will be made to all structs.
#
# (when deleting, first_offset should be the *end* of the range, and first_delta should be positive)
#
# returns list of (struct_name, changes) in topological order, where changes is a
# list of (member_end_offset, member_size_delta) sorted by offset.
# These are each either the offset to insert a gap, or the end offset of a range to delete,
# depending on what you're using it for.
def _get_struct_changes(bv, topological_order, first_name, first_offset, first_delta):
    assert first_delta >= 0, first_delta
    assert topological_order[0] == first_name

    yield first_name, [(first_offset, first_delta)]
    total_size_changes = {first_name: first_delta}

    all_affected_structs = set(topological_order)

    for dependent_name in topological_order[1:]:
        struct = bv.get_type_by_name(dependent_name).structure
        assert struct, f'dependent {dependent_name} is not a struct?'

        struct_changes = []
        struct_total_delta = 0

        for (start_offset, inner_name, multiplicity) in _get_embedded_struct_fields(bv, struct):
            if inner_name not in all_affected_structs:
                continue

            elem_size = bv.get_type_by_name(inner_name).width
            end_offset = start_offset + elem_size * multiplicity
            size_change = total_size_changes[inner_name] * multiplicity
            struct_total_delta += size_change

            struct_changes.append((end_offset, size_change))

        yield (dependent_name, struct_changes)
        total_size_changes[dependent_name] = struct_total_delta

# Iterate (start_offset, type_name, multiplicity) of all members in a struct
# that directly embed another struct (or an array of them).
def _get_embedded_struct_fields(bv, struct):
    for member in struct.members:
        ty = member.type
        multiplicity = 1
        if ty.type_class == TypeClass.ArrayTypeClass:
            multiplicity = ty.count
            ty = ty.element_type

        # embedded structs are always(?) type references
        if ty.type_class != TypeClass.NamedTypeReferenceClass:
            continue

        name = ty.named_type_reference.name
        if bv.get_type_by_name(name).structure:
            yield (member.offset, name, multiplicity)

# ========================================================================

def add_struct_comment(bv, name):
    """ Add a ``zCOMMENT[0]`` comment field to the end of a struct that doesn't have one.
    A workaround for a type parsing bug introduced in binja in May 2021 that turns ``T[0]`` into ``T*``. """

    with recording_undo(bv) as rec:
        struct = bv.get_type_by_name(name).structure
        struct = struct.mutable_copy()
        if struct.members and struct.members[-1].offset == struct.width:
            return  # already has a zero-sized member at the end

        comment_type = Type.array(bv.get_type_by_name('zCOMMENT'), 0)
        struct.insert(struct.width, comment_type, '__comment')
        bv.define_user_type(name, Type.structure_type(struct))
        rec.enable_auto_rollback()

# ========================================================================
