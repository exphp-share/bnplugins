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
from binaryninja import log
import binaryninja as bn
from pathlib import Path

from .common import TypeTree, TAG_KEYWORD, PathLike
from .config import SymbolFilters, DEFAULT_FILTERS
from .export_types import _create_types_file_json, TypeToTTreeConverter

from .export_types import create_types_file_json  # re-export
from .test import run_tests  # re-export

BNDB_DIR = r"E:\Downloaded Software\Touhou Project"
JSON_DIR = r"F:\asd\clone\th16re-data\data"
MD5SUMS_FILENAME = 'md5sums.json'
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
JsonFormatVersion = int  # tp.Literal[1, 2]  # needs python 3.8

def export(bv, path, common_types={}, version=2, filters=DEFAULT_FILTERS):
    return _export(bv, path, common_types, version, filters)

def _export(bv: bn.BinaryView, path: PathLike, common_types, version: JsonFormatVersion, filters: SymbolFilters):
    _export_symbols(bv, path=path, filters=filters, version=version)
    _export_types(bv, path=path, common_types=common_types, filters=filters, version=version)

def open_bv(path: PathLike, **kw):
    # Note: This is now a context manager, hurrah!
    return bn.BinaryViewType.get_view_of_file(str(path), **kw)

def _compute_md5(path: PathLike):
    import hashlib
    return hashlib.md5(open(path,'rb').read()).hexdigest()

def dict_get_path(d, parts, default=None):
    for part in parts:
        if part not in d:
            return default
        d = d[part]
    return d

def export_all(
        games = GAMES,
        bndb_dir: PathLike = BNDB_DIR,
        json_dir: PathLike = JSON_DIR,
        force: bool = False,
        version: JsonFormatVersion = 2,
        emit_status: tp.Callable = print,
        update_analysis: bool = False,
        filters: SymbolFilters = DEFAULT_FILTERS,
):
    # we will autocreate some subdirs, but for safety against mistakes
    # we won't create anything above the output dir itself
    _require_dir_exists(Path(json_dir).parent)

    old_md5sums = {} if force else _read_md5s_file(json_dir)

    common_types = _read_common_types(json_dir, version=version)

    for game in games:
        bndb_path = os.path.join(bndb_dir, f'{game}.bndb')
        json_subdir = os.path.join(json_dir, f'{game}')
        if _compute_md5(bndb_path) == _lookup_md5(old_md5sums, game, 'bndb', version=version):
            emit_status(f"{game}: up to date")
            continue

        emit_status(f"{game}: exporting...")
        with open_bv(bndb_path, update_analysis=update_analysis) as bv:
            os.makedirs(json_subdir, exist_ok=True)
            _export(bv, path=json_subdir, common_types=common_types, filters=filters, version=version)

        _update_md5s(games=[game], keys=all_md5_keys(version), bndb_dir=bndb_dir, json_dir=json_dir, version=version)
    emit_status("done")

def export_all_common(bv, json_dir=JSON_DIR, force=False, emit_status=print, filters=DEFAULT_FILTERS):
    """ Update the json files in the _common directory, acquiring types from the given BV. """
    _require_dir_exists(os.path.dirname(json_dir))
    os.makedirs(os.path.join(json_dir, COMMON_DIRNAME), exist_ok=True)

    # We want to make sure everything actually updates, or else we could be left with inconsistencies.
    get_types_path = lambda name: os.path.join(json_dir, COMMON_DIRNAME, name, 'types-ext.json')
    invalidated_dirs = [name for name in os.listdir(json_dir) if os.path.exists(get_types_path(name))]

    things_to_update = {}
    for type_library in bv.type_libraries:
        if not type_library.named_types:
            continue  # empty, don't bother
        dirname = type_library.name.rsplit('.', 1)[0]
        # the outer closure (an IIFE) is to create a permanent binding to the current value of 'type_library';
        # otherwise, all closures would be for the last type library in the BV
        things_to_update[dirname] = (lambda lib: lambda: _export_types_from_type_library(bv, get_types_path(dirname), lib, filters))(type_library)

    things_to_update[bv.platform.name] = lambda: _export_types_from_dict(bv, get_types_path(bv.platform.name), bv.platform.types, {}, filters)

    names_unable_to_update = [name for name in invalidated_dirs if name not in things_to_update]
    if names_unable_to_update:
        err_msg = f'unable to update: {names_unable_to_update}.  Perhaps this is only available in another BV?'
        log.log_error(err_msg)
        if not force:
            raise RuntimeError(err_msg)

    for key, func in things_to_update.items():
        print(get_types_path(key))
        os.makedirs(os.path.join(json_dir, COMMON_DIRNAME, key), exist_ok=True)
        func()

class SymbolsToWrite:
    """ All exportable symbols from an exe in a format independent of JSON database version. """
    class Static(tp.NamedTuple):
        address: int
        name: str
        bn_type: bn.Type
        comment: tp.Optional[str]

    class Func(tp.NamedTuple):
        address: int
        name: str
        comment: tp.Optional[str]

    class Case(tp.NamedTuple):
        address: int
        name: str

    statics: tp.List[Static]
    funcs: tp.List[Func]
    cases: tp.Mapping[str, tp.List[Case]]

    def __init__(self, statics, funcs, cases):
        self.statics = statics
        self.funcs = funcs
        self.cases = cases

def _export_symbols(bv, path, version: JsonFormatVersion, filters: SymbolFilters):
    symbols = _get_exported_symbols(bv, filters)
    _write_symbols_files(bv, path, symbols=symbols, version=version)

def _get_exported_symbols(bv, filters: SymbolFilters):
    # precompute expensive properties
    bv_data_vars = bv.data_vars
    bv_symbols = bv.symbols

    statics = []
    funcs = []
    cases = defaultdict(list)
    for name, symbol in bv_symbols.items():
        if isinstance(symbol, list):
            symbol = symbol[0]  # FIXME: document why
        address = symbol.address
        if symbol.type == bn.SymbolType.DataSymbol:
            case_data = filters.as_case_label(name)
            if case_data:
                cases[case_data.table_name].append(SymbolsToWrite.Case(address, case_data.case))
                continue

            try:
                t = bv_data_vars[address].type
            except KeyError:
                continue

            export_name = filters.as_useful_static_symbol(name)
            if export_name is None:
                continue
            comment = bv.get_comment_at(address) or None  # note: bn returns '' for no comment
            statics.append(SymbolsToWrite.Static(address, export_name, t, comment))

        elif symbol.type == bn.SymbolType.FunctionSymbol:
            export_name = filters.as_useful_func_symbol(name)
            if export_name is None:
                continue
            comment = bv.get_comment_at(address) or None
            funcs.append(SymbolsToWrite.Func(address, export_name, comment))

    statics.sort(key=lambda x: x.address)
    funcs.sort(key=lambda x: x.address)
    for v in cases.values():
        v.sort(key=lambda x: x.address)
    return SymbolsToWrite(statics=statics, funcs=funcs, cases=cases)

def _write_symbols_files(bv, path, version: JsonFormatVersion, symbols: SymbolsToWrite):
    return {
        1: lambda: _write_symbols_files_v1(bv, path, symbols),
        2: lambda: _write_symbols_files_v2(bv, path, symbols),
    }[version]()

def _write_symbols_files_v2(bv, path, symbols: SymbolsToWrite):
    ttree_converter = TypeToTTreeConverter(bv)

    def strip_missing_comment(d):
        if d['comment'] is None:
            del d['comment']
        return d

    def transform_static(data: SymbolsToWrite.Static):
        return strip_missing_comment(dict(
            addr=hex(data.address),
            name=data.name,
            type=ttree_converter.to_ttree(data.bn_type),
            comment=data.comment,
        ))

    def transform_func(data: SymbolsToWrite.Func):
        return strip_missing_comment(dict(
            addr=hex(data.address),
            name=data.name,
            comment=data.comment,
        ))

    def transform_case(data: SymbolsToWrite.Case):
        return dict(
            addr=hex(data.address),
            label=data.name,
        )

    schema: tp.Any  # mypy memes, in any better language the 'schema' vars would be block-scoped

    with open_output_json_with_validation(os.path.join(path, 'statics.json')) as f:
        schema = {'@type': 'block-array'}
        nice_json(f, list(map(transform_static, symbols.statics)), schema)

    with open_output_json_with_validation(os.path.join(path, 'funcs.json')) as f:
        schema = {'@type': 'block-array'}
        nice_json(f, list(map(transform_func, symbols.funcs)), schema)

    with open_output_json_with_validation(os.path.join(path, 'labels.json')) as f:
        schema = {'@type': 'block-mapping', 'element': {'@type': 'block-array'}}
        json = {k: list(map(transform_case, v)) for (k, v) in symbols.cases.items()}
        nice_json(f, json, schema)

def _write_symbols_files_v1(bv, path, symbols: SymbolsToWrite):
    def transform_static(data: SymbolsToWrite.Static):
        return dict(
            addr=hex(data.address),
            name=data.name,
            type=str(data.bn_type),
            comment=data.comment,
        )

    def transform_func(data: SymbolsToWrite.Func):
        return dict(
            addr=hex(data.address),
            name=data.name,
            comment=data.comment,
        )

    def transform_case(data: SymbolsToWrite.Case):
        return (hex(data.address), data.name)

    schema: tp.Any  # mypy memes, in any better language the 'schema' vars would be block-scoped

    with open_output_json_with_validation(os.path.join(path, 'statics.json')) as f:
        schema = {'@type': 'block-array'}
        nice_json(f, list(map(transform_static, symbols.statics)), schema)

    with open_output_json_with_validation(os.path.join(path, 'funcs.json')) as f:
        schema = {'@type': 'block-array'}
        nice_json(f, list(map(transform_func, symbols.funcs)), schema)

    with open_output_json_with_validation(os.path.join(path, 'labels.json')) as f:
        schema = {'@type': 'block-mapping', '@line-sep': 1, 'element': {'@type': 'block-array'}}
        json = {k: list(map(transform_case, v)) for (k, v) in symbols.cases.items()}
        nice_json(f, json, schema)

def _export_types(bv, path, common_types: tp.Dict[str, TypeTree], version: JsonFormatVersion, filters: SymbolFilters):
    """ Writes all type-related json files for a bv to a directory. """
    if version != 2:
        return  # FIXME

    our_types = {}
    ext_types = {}
    for k, v in bv.types.items():
        if str(k).startswith('z'):
            our_types[k] = v
        else:
            ext_types[k] = v

    export_version_props(bv, path)
    _export_types_from_dict(bv, os.path.join(path, 'types-own.json'), our_types, common_types, filters)
    _export_types_from_dict(bv, os.path.join(path, 'types-ext.json'), ext_types, common_types, filters)

def _export_types_from_type_library(bv, path, type_library: bn.TypeLibrary,filters: SymbolFilters):
    """ Write a single file like ``types-own.json`` containing all types from a type library. """
    # Here's the annoying thing:
    #  - BinaryView is a central part of our type serialization
    #  - A BinaryView will only lazily load types from a type library as they are needed
    #    through certain API functions.
    #  - We want to export all of the types in the library, since we can't tell ahead of time
    #    which types are used by OTHER games.

    # We don't just want to tell the current BV to load all the types from the library because this
    # will have the effect of making all of the types permanently appear in the GUI's type list.
    #
    # So we make a new BV.
    original_bv = bv
    bv = bn.BinaryView()

    # TypeLibraries do not include platform types.
    # Luckily, bv.platform appears to settable.
    bv.platform = original_bv.platform

    # Import the types from the type library
    bv.add_type_library(type_library)
    for name in type_library.named_types:
        bv.import_library_type(name)

    _export_types_from_dict(bv, path, type_library.named_types, common_types={}, filters=filters)

def _export_types_from_dict(
        bv: bn.BinaryView,
        path: str,
        types_to_export: tp.Mapping[bn.QualifiedName, bn.Type],
        common_types: tp.Dict[str, TypeTree],
        filters: SymbolFilters,
):
    """ Write a single file like ``types-own.json`` for the given types. """
    types = _create_types_file_json(bv, types_to_export, common_types, filters=filters)
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

def _read_common_types(json_dir, version: JsonFormatVersion):
    return {
        1: lambda: {},
        2: lambda: _read_common_types_v2(json_dir),
    }[version]()

def _read_common_types_v2(json_dir):
    types = {}
    for path in glob.glob(os.path.join(json_dir, '_common', '*', 'types*.json')):
        types.update(json.load(open(path)))
    return types

def export_version_props(bv, path):
    props = {'pointer-size': bv.arch.address_size}
    with open_output_json_with_validation(os.path.join(path, 'version-props.json')) as f:
        nice_json(f, props, {'@type': 'block-object'})

# =================================================

def import_all_functions(games=GAMES, bndb_dir=BNDB_DIR, json_dir=JSON_DIR, version=1, emit_status=print):
    return _import_all_symbols(
        games=games, bndb_dir=bndb_dir, json_dir=json_dir, version=version, emit_status=print,
        json_filename='funcs.json', symbol_type=bn.SymbolType.FunctionSymbol,
    )

def import_all_statics(games=GAMES, bndb_dir=BNDB_DIR, json_dir=JSON_DIR, version=1, emit_status=print):
    return _import_all_symbols(
        games=games, bndb_dir=bndb_dir, json_dir=json_dir, version=version, emit_status=print,
        json_filename='statics.json', symbol_type=bn.SymbolType.DataSymbol,
    )

# =================================================

# NOTE: Old and not used in a while.
#       The thought was that if people submit Pull Requests to th-re-data I should be able to merge them into
#       my local databases with this function.  But only one person has ever done that, and instead normally
#       I just manually add contributions by tossing a list into 'import_funcs_from_json' instead.
def _import_all_symbols(games, bndb_dir, json_dir, json_filename, symbol_type, version, emit_status):
    assert version == 1  # importing of version 2 not supported

    old_md5sums = _read_md5s_file(json_dir)

    for game in games:
        bndb_path = os.path.join(bndb_dir, f'{game}.bndb')
        json_path = os.path.join(json_dir, f'{game}', json_filename)
        try:
            with open(json_path) as f:
                funcs_json = json.load(f)
        except (IOError, json.decoder.JSONDecodeError) as e:
            emit_status(f'{game}: {e}')
            continue

        if _compute_md5(json_path) == _lookup_md5(old_md5sums, game, json_filename, version=version):
            emit_status(f"{game}: up to date")
            continue

        emit_status(f"{game}: checking...")
        with open_bv(bndb_path, update_analysis=False) as bv:
            if _import_symbols_from_json_v1(bv, funcs_json, symbol_type, emit_status=lambda s: emit_status(f'{game}: {s}')):
                emit_status(f'{game}: saving...')
                bv.save_auto_snapshot()

        _update_md5s(games=[game], keys=['bndb', json_filename], bndb_dir=bndb_dir, json_dir=json_dir, version=version)
    emit_status("done")

def import_funcs_from_json(bv, funcs, emit_status=None):
    return _import_symbols_from_json_v1(bv, funcs, bn.SymbolType.FunctionSymbol, emit_status=emit_status)
def import_statics_from_json(bv, statics, emit_status=None):
    return _import_symbols_from_json_v1(bv, statics, bn.SymbolType.DataSymbol, emit_status=emit_status)

def _import_symbols_from_json_v1(bv, symbols, symbol_type, emit_status=None):
    changed = False
    for d in symbols:
        addr = int(d['addr'], 16)
        name = d['name']
        existing = bv.get_symbol_at(addr)
        if existing is not None:
            if name == existing.name:
                continue
            else:
                bv.define_user_symbol(bn.Symbol(symbol_type, addr, name))
                changed = True
                if emit_status:
                    emit_status(f'rename {existing.name} => {name}')
        else:
            bv.define_user_symbol(bn.Symbol(symbol_type, addr, name))
            changed = True
            if emit_status:
                emit_status(f'name {existing.name}')
    return changed

def nice_json(file, value, schema, final_newline=True, starting_indent=0, indent=2):
    """
    A recursive json formatter which uses a schema to allow the caller to specify which
    things should be formatted block-style versus inline.
    """
    _NiceJsonContext(file=file, indent_step=indent).format_value(value=value, schema=schema, indent=starting_indent)
    if final_newline:
        print(file=file)

class _NiceJsonContext:
    def __init__(self, file, indent_step):
        self.file = file
        self.indent_step = indent_step

    def format_value(self, value, schema, indent):
        if schema is None:
            schema = {'@type': 'inline'}

        if schema['@type'] == 'inline':
            json.dump(value, self.file)

        elif schema['@type'] == 'block-array':
            # Homogenous list
            assert isinstance(value, (list, tuple)), (value, schema)
            def do_item(item):
                self.format_value(item, schema.get('element', None), indent + self.indent_step)
            self.format_block('[', ']', indent, schema.get('@line-sep', 0), list(value), do_item)

        elif schema['@type'] == 'block-object':
            # Heterogenous dict
            assert isinstance(value, dict), (value, schema)
            def do_key(key):
                print(json.dumps(key) + ': ', end='', file=self.file)
                self.format_value(value[key], schema.get(key, None), indent + self.indent_step)
            self.format_block('{', '}', indent, schema.get('@line-sep', 0), list(value), do_key)

        elif schema['@type'] == 'block-mapping':
            # Homogenous dict
            assert isinstance(value, dict), (value, schema)
            def do_key(key):
                print(json.dumps(key) + ': ', end='', file=self.file)
                self.format_value(value[key], schema.get('element', None), indent + self.indent_step)
            self.format_block('{', '}', indent, schema.get('@line-sep', 0), list(value), do_key)

        elif schema['@type'] == 'object-variant':
            assert isinstance(value, dict), (value, schema)
            tag = schema['@tag']
            variant_name = value[tag]
            sub_schema = schema.get(variant_name)
            if not sub_schema:
                sub_schema = schema['@default']
            self.format_value(value, schema[variant_name], indent=indent)

        else:
            assert False, schema

    def format_block(self, open: str, close: str, indent: int, line_sep: int, items: tp.List, do_item: tp.Callable):
        if not items:
            print(' ' * indent + f'{open}{close}', end='', file=self.file)
            return
        first = True
        for item in items:
            print(file=self.file)
            print(' ' * indent + (f'{open} ' if first else ', '), end='', file=self.file)
            first = False
            do_item(item)
            print('\n' * line_sep, end='', file=self.file)
        print('\n' + ' ' * indent + close, end='', file=self.file)

#============================================================================

def all_md5_keys(version: JsonFormatVersion):
    return {
        1: ['bndb', 'funcs.json', 'labels.json', 'statics.json', 'type-structs-own.json'],
        2: ['bndb', 'funcs.json', 'labels.json', 'statics.json', 'types-own.json'],
    }[version]

def _read_md5s_file(json_dir=JSON_DIR):
    md5sum_path = os.path.join(json_dir, MD5SUMS_FILENAME)
    try:
        with open(md5sum_path) as f:
            return json.load(f)
    except IOError: return {}
    except json.decoder.JSONDecodeError: return {}

def _update_md5s(games, keys, bndb_dir, json_dir, version: JsonFormatVersion):
    md5s = _read_md5s_file(json_dir)

    path_funcs = {
        # files not in json_dir
        'bndb': (lambda game: os.path.join(bndb_dir, f'{game}.bndb')),
    }
    for filename in all_md5_keys(version):
        if filename not in path_funcs:
            path_funcs[filename] = lambda game: os.path.join(json_dir, game, filename)

    assert set(path_funcs) == set(all_md5_keys(version))
    for game in games:
        if game not in md5s:
            md5s[game] = {}
        for key in keys:
            md5s[game][key] = _compute_md5(path_funcs[key](game))

    with open(os.path.join(json_dir, MD5SUMS_FILENAME), 'w') as f:
        nice_json(f, md5s, {'@type': 'block-mapping'})

def _lookup_md5(md5s_dict, game, key, version: JsonFormatVersion):
    assert key in all_md5_keys(version) # protection against typos
    print(game, key)
    return md5s_dict.get(game, {}).get(key, None)

@contextlib.contextmanager
def open_output_json_with_validation(path: PathLike):
    """ Open a file for writing json.  Once the 'with' block is exited, the file will be
    reopened for reading to validate the JSON. """
    with open(path, 'w') as f:
        yield f

    with open(path) as f:
        json.load(f) # this will fail if the JSON is invalid

#============================================================================

def _require_dir_exists(path: PathLike):
    if not Path(path).exists:
        raise IOError(f"{path}: No such directory")

#============================================================================

# Check if any of the given named tpyes have inconsistent definitions
# between all of the version types files
def check_all_structs(names, root_name=None):
    ds = {}
    for child in Path(JSON_DIR).iterdir():
        fpath = child / 'types-ext.json'
        if fpath.exists:
            version = child.name
            ds[version] = json.load(open(fpath))

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
        bndb_path = Path(BNDB_DIR) / f'{game}.bndb'
        bvs.append(open_bv(bndb_path, update_analysis=False))
    return bvs

#============================================================================

def make_c_header_zip(bvs, games, outpath: PathLike = Path(JSON_DIR) / 'th-re-c-defs.zip'):
    from .export_to_c import make_c_header_zip as impl
    impl(bvs, games, outpath)

#============================================================================
# things used at least once in the past to perform mass changes to my db to fix consistency/integrity errors and etc.
#
# some of these are pretty specific to my DB.  They're only here in __init__ because I use them
# directly from the repl.

def fix_label_names(bvs: tp.List[bn.BinaryView]):
    """ Add missing '__case_' infixes to special case labels. (hack for personal use) """
    for bv in bvs:
        print(bv)
        # gather all label groups
        symbols = [v[0] for v in bv.symbols.values() if v[0].type == bn.SymbolType.DataSymbol]
        group_prefixes = set()
        is_valid_case_name = lambda name: '__case_' in name or '__cases_' in name
        for symbol in symbols:
            name = str(symbol.name)  # in case of QualifiedName
            if is_valid_case_name(name):
                group_prefixes.add(name[:name.index('__case')])

        for symbol in symbols:
            name = str(symbol.name)  # in case of QualifiedName
            if is_valid_case_name(name):
                continue
            parts = name.split('__', 1)
            if len(parts) > 1 and parts[0] in group_prefixes:
                new_name = parts[0] + '__case_' + parts[1]
                bv.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, symbol.address, new_name))

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
