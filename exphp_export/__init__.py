from __future__ import print_function

# Script used to export these data files from binja.
#
# In binja's python console:
#
# >>> import exphp_export; exphp_export.run(bv)

import os
import json
import glob
from collections import defaultdict
import contextlib
import typing as tp
from binaryninja import (
    BinaryView, Symbol, SymbolType, Type, log, BinaryViewType,
    QualifiedName, TypeLibrary
)

from .common import TypeTree, TAG_KEYWORD
from .export_types import create_types_file_json, TypeToTTreeConverter
from .test import run_tests  # re-export

BNDB_DIR = r"E:\Downloaded Software\Touhou Project"
JSON_DIR = r"F:\asd\clone\th16re-data\data"
MD5SUMS_FILENAME = 'md5sums.json'
ALL_MD5_KEYS = ['bndb', 'funcs.json', 'labels.json', 'statics.json', 'types-own.json']
COMMON_DIRNAME = '_common' # FIXME: rename to _modules
SHARED_DIRNAME = '_shared'
GAMES = [
    "th06.v1.02h",
    "th07.v1.00b",
    "th08.v1.00d",
    "th09.v1.50a",
    "th095.v1.02a",
    "th10.v1.00a",
    "th11.v1.00a",
    "th12.v1.00b",
    "th125.v1.00a",
    "th128.v1.00a",
    "th13.v1.00c",
    "th14.v1.00b",
    "th143.v1.00a",
    "th15.v1.00b",
    "th16.v1.00a",
    "th165.v1.00a",
    "th17.v1.00b",
    "th18.v1.00a",
]

def export(bv, path, common_types={}):
    export_symbols(bv, path=path)
    export_types(bv, path=path, common_types=common_types)

def open_bv(path, **kw):
    # Note: This is now a context manager, hurrah!
    return BinaryViewType.get_view_of_file(str(path), **kw)

def compute_md5(path):
    import hashlib
    return hashlib.md5(open(path,'rb').read()).hexdigest()

def dict_get_path(d, parts, default=None):
    for part in parts:
        if part not in d:
            return default
        d = d[part]
    return d

def export_all(games=GAMES, bndb_dir=BNDB_DIR, json_dir=JSON_DIR, force=False, emit_status=print, update_analysis=False):
    # we will autocreate some subdirs, but for safety against mistakes
    # we won't create anything above the output dir itself
    require_dir_exists(os.path.dirname(json_dir))

    old_md5sums = {} if force else read_md5s_file(json_dir)

    common_types = read_common_types(json_dir)

    for game in games:
        bndb_path = os.path.join(bndb_dir, f'{game}.bndb')
        json_subdir = os.path.join(json_dir, f'{game}')
        if compute_md5(bndb_path) == lookup_md5(old_md5sums, game, 'bndb'):
            emit_status(f"{game}: up to date")
            continue

        emit_status(f"{game}: exporting...")
        with open_bv(bndb_path, update_analysis=update_analysis) as bv:
            os.makedirs(json_subdir, exist_ok=True)
            export(bv, path=json_subdir, common_types=common_types)

        update_md5s(games=[game], keys=ALL_MD5_KEYS, bndb_dir=bndb_dir, json_dir=json_dir)
    emit_status("done")

def export_all_common(bv, json_dir=JSON_DIR, force=False, emit_status=print):
    """ Update the json files in the _common directory, acquiring types from the given BV. """
    require_dir_exists(os.path.dirname(json_dir))
    os.makedirs(os.path.join(json_dir, COMMON_DIRNAME), exist_ok=True)

    # We want to make sure everything actually updates, or else we could be left with inconsistencies.
    get_types_path = lambda name: os.path.join(json_dir, COMMON_DIRNAME, name, 'types-ext.json')
    invalidated_dirs = [name for name in os.listdir(json_dir) if os.path.exists(get_types_path(name))]

    things_to_update = {}
    for type_library in bv.type_libraries:
        if not type_library.named_types:
            continue  # empty, don't bother
        dirname = type_library.name.rsplit('.', 1)[0]
        things_to_update[dirname] = (export_types_from_type_library, bv, get_types_path(dirname), type_library)

    things_to_update['pe'] = (export_pe_types, bv, get_types_path('pe'))

    things_to_update[bv.platform.name] = (export_types_from_dict, bv, get_types_path(bv.platform.name), bv.platform.types, {})

    names_unable_to_update = [name for name in invalidated_dirs if name not in things_to_update]
    if names_unable_to_update:
        err_msg = f'unable to update: {names_unable_to_update}.  Perhaps this is only available in another BV?'
        log.log_error(err_msg)
        if not force:
            raise RuntimeError(err_msg)

    for key, (func, *args) in things_to_update.items():
        print(get_types_path(key))
        os.makedirs(os.path.join(json_dir, COMMON_DIRNAME, key), exist_ok=True)
        func(*args)

def export_symbols(bv, path):
    # precompute expensive properties
    bv_data_vars = bv.data_vars
    bv_symbols = bv.symbols

    datas = []
    funcs = []
    labels = defaultdict(list)
    ttree_converter = TypeToTTreeConverter(bv)
    for name, symbol in bv_symbols.items():
        if isinstance(symbol, list):
            symbol = symbol[0]
        address = symbol.address
        if symbol.type == SymbolType.DataSymbol:
            # Skip statics that I didn't rename.
            if any(
                name.startswith(prefix) and is_hex(name[len(prefix):])
                for prefix in ['data_', 'jump_table_']
            ):
                continue

            if name in [
                '__dos_header', '__dos_stub', '__rich_header', '__coff_header',
                '__pe32_optional_header', '__section_headers',
            ]:
                continue

            # There's a large number of symbols autogenerated by binja for DLL functions.
            # Since they can be autogenerated, there's no point sharing them.
            if name.startswith('__import_') or name.startswith('__export_'):
                continue

            # My naming pattern for case labels.
            for infix in ['__case_', '__cases_']:
                if infix in name:
                    kind, rest = name.split(infix)
                    labels[kind].append(dict(addr=hex(address), label=rest))
                    break
            else:
                try:
                    t = bv_data_vars[address].type
                except KeyError:
                    continue

                datas.append(dict(addr=hex(address), name=name, type=ttree_converter.to_ttree(t), comment=bv.get_comment_at(address) or None))
                if datas[-1]['comment'] is None:
                    del datas[-1]['comment']

        elif symbol.type == SymbolType.FunctionSymbol:
            # Identify functions that aren't worth sharing
            def is_boring(name):
                # Done by binja, e.g. 'j_sub_45a83#4'
                if '#' in name:
                    return True

                # these suffixes don't convey enough info for the name to be worth sharing if there's nothing else
                name = strip_suffix(name, '_identical_twin')
                name = strip_suffix(name, '_twin')
                name = strip_suffix(name, '_sister')
                name = strip_suffix(name, '_sibling')

                # For some things I've done nothing more than change the prefix using a script
                for prefix in ['sub', 'leaf', 'seh', 'SEH', 'j_sub']:
                    if name.startswith(prefix + '_') and is_hex(name[len(prefix):].lstrip('_')):
                        return True
                return False

            if is_boring(name):
                continue

            funcs.append(dict(addr=hex(address), name=name, comment=bv.get_comment_at(address) or None))
            if funcs[-1]['comment'] is None:
                del funcs[-1]['comment']

    datas.sort(key=lambda x: int(x['addr'], 16))
    funcs.sort(key=lambda x: int(x['addr'], 16))
    for v in labels.values():
        v.sort(key=lambda x: int(x['addr'], 16))

    with open_output_json_with_validation(os.path.join(path, 'statics.json')) as f:
        nice_json(f, datas, {'@type': 'block-array'})

    with open_output_json_with_validation(os.path.join(path, 'funcs.json')) as f:
        nice_json(f, funcs, {'@type': 'block-array'})

    with open_output_json_with_validation(os.path.join(path, 'labels.json')) as f:
        nice_json(f, labels, {'@type': 'block-mapping', 'element': {'@type': 'block-array'}})

def strip_suffix(s, suffix):
    return s[:len(s)-len(suffix)] if s.endswith(suffix) else s

def export_types(bv, path, common_types: tp.Dict[str, TypeTree] = {}):
    """ Writes all type-related json files for a bv to a directory. """
    our_types = {}
    ext_types = {}
    for k, v in bv.types.items():
        if str(k).startswith('z'):
            our_types[k] = v
        else:
            ext_types[k] = v

    export_version_props(bv, path)
    export_types_from_dict(bv, os.path.join(path, 'types-own.json'), our_types, common_types)
    export_types_from_dict(bv, os.path.join(path, 'types-ext.json'), ext_types, common_types)

def export_types_from_type_library(bv, path, type_library: TypeLibrary):
    """ Write a single file like ``types-own.json`` containing all types from a type library. """
    # Totally ignore the input bv and create one with no other type libraries to avoid competition
    bv = BinaryView()
    bv.add_type_library(type_library)
    # trick the bv into actually loading all of the types
    for name in type_library.named_types:
        bv.parse_type_string(str(name))  # the bv will automatically load type library types while parsing

    types_to_export = {}
    for name in type_library.named_types:
        types_to_export[name] = bv.get_type_by_name(name)

    export_types_from_dict(bv, path, types_to_export, common_types={})

def export_pe_types(bv, path):
    """ Write a single file like ``types-own.json`` containing the PE header types. """
    types = {k: v for (k, v) in bv.types.items() if bv.get_type_id(k).startswith('pe:')}
    export_types_from_dict(bv, path, types, common_types={})

def export_types_from_dict(
        bv: BinaryView,
        path: str,
        types_to_export: tp.Mapping[QualifiedName, Type],
        common_types: tp.Dict[str, TypeTree] = {},
):
    """ Write a single file like ``types-own.json`` for the given types. """
    types = create_types_file_json(bv, types_to_export, common_types)
    with open_output_json_with_validation(path) as f:
        nice_json(f, types, {
            '@type': 'block-mapping',
            '@line-sep': 1,
            'element': {
                '@type': 'object-variant',
                '@tag': TAG_KEYWORD,
                'struct': {
                    '@type': 'block-object',
                    'members': {'@type': 'block-array'},
                },
                'enum': {
                    '@type': 'block-object',
                    'values': {'@type': 'block-array'}
                },
                'union': {
                    '@type': 'block-object',
                    'members': {'@type': 'block-array'}
                },
                'typedef': {
                    '@type': 'inline',
                },
            },
        })

def read_common_types(json_dir):
    types = {}
    for path in glob.glob(os.path.join(json_dir, '_common', '*', 'types*.json')):
        types.update(json.load(open(path)))
    return types

def export_version_props(bv, path):
    props = {'pointer-size': bv.arch.address_size}
    with open_output_json_with_validation(os.path.join(path, 'version-props.json')) as f:
        nice_json(f, props, {'@type': 'block-object'})

# =================================================

def import_all_functions(games=GAMES, bndb_dir=BNDB_DIR, json_dir=JSON_DIR, emit_status=print):
    return _import_all_symbols(
        games=games, bndb_dir=bndb_dir, json_dir=json_dir, emit_status=print,
        json_filename='funcs.json', symbol_type=SymbolType.FunctionSymbol,
    )

def import_all_statics(games=GAMES, bndb_dir=BNDB_DIR, json_dir=JSON_DIR, emit_status=print):
    return _import_all_symbols(
        games=games, bndb_dir=bndb_dir, json_dir=json_dir, emit_status=print,
        json_filename='statics.json', symbol_type=SymbolType.DataSymbol,
    )

# =================================================

def _import_all_symbols(games, bndb_dir, json_dir, json_filename, symbol_type, emit_status):
    old_md5sums = read_md5s_file(json_dir)

    for game in games:
        bndb_path = os.path.join(bndb_dir, f'{game}.bndb')
        json_path = os.path.join(json_dir, f'{game}', json_filename)
        try:
            with open(json_path) as f:
                funcs_json = json.load(f)
        except (IOError, json.decoder.JSONDecodeError) as e:
            emit_status(f'{game}: {e}')
            continue

        if compute_md5(json_path) == lookup_md5(old_md5sums, game, json_filename):
            emit_status(f"{game}: up to date")
            continue

        emit_status(f"{game}: checking...")
        with open_bv(bndb_path, update_analysis=False) as bv:
            if _import_symbols_from_json(bv, funcs_json, symbol_type, emit_status=lambda s: emit_status(f'{game}: {s}')):
                emit_status(f'{game}: saving...')
                bv.save_auto_snapshot()

        update_md5s(games=[game], keys=['bndb', json_filename], bndb_dir=bndb_dir, json_dir=json_dir)
    emit_status("done")

def import_funcs_from_json(bv, funcs, emit_status=None):
    return _import_symbols_from_json(bv, funcs, SymbolType.FunctionSymbol, emit_status=emit_status)
def import_statics_from_json(bv, statics, emit_status=None):
    return _import_symbols_from_json(bv, statics, SymbolType.DataSymbol, emit_status=emit_status)

def _import_symbols_from_json(bv, symbols, symbol_type, emit_status=None):
    changed = False
    for d in symbols:
        addr = int(d['addr'], 16)
        name = d['name']
        existing = bv.get_symbol_at(addr)
        if existing is not None:
            if name == existing.name:
                continue
            else:
                bv.define_user_symbol(Symbol(symbol_type, addr, name))
                changed = True
                if emit_status:
                    emit_status(f'rename {existing.name} => {name}')
        else:
            bv.define_user_symbol(Symbol(symbol_type, addr, name))
            changed = True
            if emit_status:
                emit_status(f'name {existing.name}')
    return changed

def merge_function_files(games=GAMES, json_dir=JSON_DIR, emit_status=print):
    return _merge_symbol_files(games, json_dir, 'funcs.json', emit_status)
def merge_static_files(games=GAMES, json_dir=JSON_DIR, emit_status=print):
    return _merge_symbol_files(games, json_dir, 'statics.json', emit_status)

def _merge_symbol_files(games, json_dir, filename, emit_status):
    require_dir_exists(json_dir)
    os.makedirs(os.path.join(json_dir, 'composite'), exist_ok=True)

    composite_path = os.path.join(json_dir, 'composite', filename)
    composite_items = []
    for game in games:
        with open(os.path.join(json_dir, f'{game}/{filename}')) as f:
            game_items = json.load(f)
        composite_items.extend(dict(game=game, **d) for d in game_items)

    composite_items.sort(key=lambda d: d['name'])

    with open(composite_path, 'w') as f:
        nice_json(f, composite_items, {'@type': 'block-array'})

def split_function_files(games=GAMES, json_dir=JSON_DIR, emit_status=print):
    return _split_symbol_files(games, json_dir, 'funcs.json', emit_status)
def split_static_files(games=GAMES, json_dir=JSON_DIR, emit_status=print):
    return _split_symbol_files(games, json_dir, 'statics.json', emit_status)

def _split_symbol_files(games, json_dir, filename, emit_status):
    require_dir_exists(json_dir)

    with open(os.path.join(json_dir, 'composite', filename)) as f:
        composite_items = json.load(f)
    for game in games:
        game_items = [dict(d) for d in composite_items if d['game'] == game]
        for d in game_items:
            del d['game']
        game_items.sort(key=lambda d: d['addr'])
        with open(os.path.join(json_dir, f'{game}/{filename}'), 'w') as f:
            nice_json(f, game_items, {'@type': 'block-array'})

def nice_json(file, value, schema, indent=0):
    if schema is None:
        schema = {'@type': 'inline'}

    if schema['@type'] == 'inline':
        json.dump(value, file)

    elif schema['@type'] == 'block-array':
        # Homogenous list
        assert isinstance(value, (list, tuple))
        def do_item(item):
            nice_json(file, item, schema.get('element', None), indent + 2)
        _nice_json_block(file, '[', ']', indent, schema.get('@line-sep', 0), list(value), do_item)

    elif schema['@type'] == 'block-object':
        # Heterogenous dict
        assert isinstance(value, dict)
        def do_key(key):
            print(json.dumps(key) + ': ', end='', file=file)
            nice_json(file, value[key], schema.get(key, None), indent + 2)
        _nice_json_block(file, '{', '}', indent, schema.get('@line-sep', 0), list(value), do_key)

    elif schema['@type'] == 'block-mapping':
        # Homogenous dict
        assert isinstance(value, dict)
        def do_key(key):
            print(json.dumps(key) + ': ', end='', file=file)
            nice_json(file, value[key], schema.get('element', None), indent + 2)
        _nice_json_block(file, '{', '}', indent, schema.get('@line-sep', 0), list(value), do_key)

    elif schema['@type'] == 'object-variant':
        assert isinstance(value, dict)
        tag = schema['@tag']
        variant_name = value[tag]
        sub_schema = schema.get(variant_name)
        if not sub_schema:
            sub_schema = schema['@default']
        nice_json(file, value, schema[variant_name], indent)

    else:
        assert False, schema

def _nice_json_block(file, open: str, close: str, indent: int, line_sep: int, items: tp.List, do_item: tp.Callable):
    if not items:
        print(' ' * indent + f'{open}{close}', end='', file=file)
        return
    first = True
    for item in items:
        print(file=file)
        print(' ' * indent + (f'{open} ' if first else ', '), end='', file=file)
        first = False
        do_item(item)
        print('\n' * line_sep, end='', file=file)
    print('\n' + ' ' * indent + close, end='', file=file)

#============================================================================

def read_md5s_file(json_dir=JSON_DIR):
    md5sum_path = os.path.join(json_dir, MD5SUMS_FILENAME)
    try:
        with open(md5sum_path) as f:
            return json.load(f)
    except IOError: return {}
    except json.decoder.JSONDecodeError: return {}

def update_md5s(games, keys, bndb_dir, json_dir):
    md5s = read_md5s_file(json_dir)

    path_funcs = {
        'bndb': (lambda game: os.path.join(bndb_dir, f'{game}.bndb')),
        'funcs.json': (lambda game: os.path.join(json_dir, game, 'funcs.json')),
        'labels.json': (lambda game: os.path.join(json_dir, game, 'labels.json')),
        'statics.json': (lambda game: os.path.join(json_dir, game, 'statics.json')),
        'types-own.json': (lambda game: os.path.join(json_dir, game, 'types-own.json')),
    }
    assert set(path_funcs) == set(ALL_MD5_KEYS)
    for game in games:
        if game not in md5s:
            md5s[game] = {}
        for key in keys:
            md5s[game][key] = compute_md5(path_funcs[key](game))

    with open(os.path.join(json_dir, MD5SUMS_FILENAME), 'w') as f:
        nice_json(f, md5s, {'@type': 'block-mapping'})

def lookup_md5(md5s_dict, game, key):
    assert key in ALL_MD5_KEYS # protection against typos
    print(game, key)
    return md5s_dict.get(game, {}).get(key, None)

@contextlib.contextmanager
def open_output_json_with_validation(path):
    """ Open a file for writing json.  Once the 'with' block is exited, the file will be
    reopened for reading to validate the JSON. """
    with open(path, 'w') as f:
        yield f

    with open(path) as f:
        json.load(f) # this will fail if the JSON is invalid

#============================================================================

def require_dir_exists(path):
    if not os.path.exists(path):
        raise IOError(f"{path}: No such directory")

def is_hex(s):
    try:
        int('0x' + s, 16)
    except ValueError:
        return False
    return True

#============================================================================

# Check if any of the given named tpyes have inconsistent definitions
# between all of the version types files
def check_all_structs(names, root_name=None):
    ds = {}
    for k in os.listdir(os.path.join(JSON_DIR)):
        fpath = os.path.join(JSON_DIR, k, 'types-ext.json')
        if os.path.exists(fpath):
            ds[k] = json.load(open(fpath))

    versions = list(ds)
    if root_name:
        versions = [v for v in versions if root_name in ds[v]]
    print(versions)

    for name in names:
        first = None
        for version in versions:
            if (not root_name) and name not in ds[version]:
                continue
            if first is None:
                first = ds[version][name]
            else:
                if ds[version][name] != first:
                    print('==================')
                    print(version, name, first)
                    print(version, name, ds[version][name])

def all_game_bvs(games=GAMES):
    bvs = []
    for game in games:
        print(game)
        bndb_path = os.path.join(BNDB_DIR, f'{game}.bndb')
        bvs.append(open_bv(bndb_path, update_analysis=False))
    return bvs

#============================================================================

def make_c_header_zip(bvs, games, outpath=os.path.join(JSON_DIR, 'th-re-c-defs.zip')):
    from .export_to_c import make_c_header_zip as impl
    impl(bvs, games, outpath)

# def fix_vtable_names(bvs, names_to_consider):
#     for bv in bvs:
#         for k in names_to_consider:
#             typ = bv.get_type_by_name(k)
#             if typ is not None and typ.type_class == TypeClass.StructureTypeClass:
#                 if typ.structure.members and typ.structure.members[0].name == 'lpVtbl':
#                     # print('-', k, bv)
#                     fix_vtable_name(bv, k)

# def fix_super_names(bvs, names_to_consider):
#     for bv in bvs:
#         for k in names_to_consider:
#             typ = bv.get_type_by_name(k)
#             if typ is not None and typ.type_class == TypeClass.StructureTypeClass:
#                 if typ.structure.members and typ.structure.members[0].name == 'parent':
#                     # print('-', k, bv)
#                     fix_super_name(bv, k)

# def fix_iunknown_types(bvs, names_to_consider):
#     for bv in bvs:
#         for k in names_to_consider:
#             typ = bv.get_type_by_name(k)
#             if typ is not None and typ.type_class == TypeClass.StructureTypeClass:
#                 if typ.structure.members and typ.structure.members[0].name == 'parent':
#                     # print('-', k, bv)
#                     fix_super_name(bv, k)

# def fix_vtable_name(bv, name):
#     typ = bv.get_type_by_name(name)
#     structure = typ.structure.mutable_copy()
#     assert structure.members[0].name == 'lpVtbl'
#     structure.replace(0, structure.members[0].type, 'vtable')
#     bv.define_user_type(name, Type.structure_type(structure))


# def fix_super_name(bv, name):
#     typ = bv.get_type_by_name(name)
#     structure = typ.structure.mutable_copy()
#     assert structure.members[0].name == 'parent'
#     structure.replace(0, structure.members[0].type, 'super')
#     bv.define_user_type(name, Type.structure_type(structure))

# def fix_all_object_sizes(bvs):
#     for bv in bvs:
#         for name, ty in bv.types.items():
#             if ty.alignment == 4 and ty.width == 5:
#                 if not (ty.structure is not None and ty.structure.members and ty.structure.members[0].name == 'vtable'):
#                     print('skipping', name)
#                     continue

#                 s = ty.structure.mutable_copy()
#                 assert s.members[1].type.width == 1
#                 s.replace(1, Type.int(4), name='__make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read')
#                 bv.define_user_type(name, Type.structure_type(s))

# def fix_struct_sizes_for_alignment(bv):
#     for name, ty in bv.types.items():
#         if ty.width % ty.alignment == 0:
#             continue
#         print(name)
#         s = ty.structure.mutable_copy()
#         new_width = (ty.width - (ty.width % ty.alignment)) + ty.alignment

#         assert new_width >= s.width
#         assert new_width - s.alignment < s.width
#         s.width = new_width
#         assert s.width % s.alignment == 0

#         bv.define_user_type(name, Type.structure_type(s))

# def fff(r, bvs):
#     for (i,g) in enumerate(GAMES):
#         #if g != 'th14.v1.00b'# and bvs[i].symbols['Direct3DCreate9']:
#             print(g)
#             if 'IUnknown' in bvs[i].types:
#                 continue
#             print('DO DEFS')
#             for k, v in  bvs[i].parse_types_from_string('''
# struct IUnknown;
# struct IUnknownVtbl {
#     int32_t (* QueryInterface)(struct IUnknown*, GUID*, void**);
#     uint32_t (* AddRef)(struct IUnknown*);
#     uint32_t (* Release)(struct IUnknown*);
# };

# struct IUnknown {
#     struct IUnknownVtbl* vtable;
#     char __make_struct_bigger_than_a_dword_so_binja_sees_when_vtable_is_read;
# };
# ''').types.items():
#                 bvs[i].define_user_type(k, v)
#             # try:
#             #     r.import_type_from_bv(bvs[i], bvs[GAMES.index('th14.v1.00b')], 'IUnknown', exist_ok=True)
#             # except:
#             #     print(g)
#             #     pass
