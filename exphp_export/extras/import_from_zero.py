# Importing from zero318's CSV files

import enum
from touhouReverseBnutil import recording_undo
import typing as tp
import binaryninja as bn
import re
from binaryninja import BinaryView

from exphp_export.common import PathLike

Pattern = tp.Union[str, tp.Pattern[str]]

def import_csv(bv: BinaryView, path: PathLike, filters=None):
    csv_symbols = _read_zero_csv(path)

    if csv_symbols.kind == CsvSymbolType.User:
        filtered = _filter_user_symbols(bv, csv_symbols.user)
        rename_filters = filters or RENAME_NOTHING

    elif csv_symbols.kind == CsvSymbolType.System:
        filtered = _filter_system_symbols(bv, csv_symbols.system)
        rename_filters = filters or RENAME_ALL

    else: assert False, csv_symbols.kind

    results = _apply_bv_symbols_with_undo(bv, filtered.symbols, rename_filters)
    results.write(emit=print)

def _read_zero_csv(path: PathLike):
    import csv

    with open(path, newline='') as csvfile:
        dialect = csv.Sniffer().sniff(csvfile.read())
        csvfile.seek(0)
        reader = csv.DictReader(csvfile, dialect=dialect)

        read_rva = lambda s: int(s, 16) + 0x40_0000
        if reader.fieldnames == ['RVA', 'label', 'comment']:
            return CsvSymbols(CsvSymbolType.User, [
                CsvUserSymbol(address=read_rva(row['RVA']), name=row['label'], comment=row['comment'])
                for row in reader
            ])
        elif reader.fieldnames == ['RVA', 'label_type', 'label']:
            return CsvSymbols(CsvSymbolType.System, [
                CsvSystemSymbol(address=read_rva(row['RVA']), type=CsvSystemLabelType[row['label_type']], name=row['label'])
                for row in reader
            ])

class CsvSymbolType(enum.Enum):
    User = enum.auto()
    System = enum.auto()

class CsvSystemLabelType(enum.Enum):
    ANALYSIS_LABEL = enum.auto()
    IMPORT = enum.auto()
    EXPORT = enum.auto()

class CsvUserSymbol(tp.NamedTuple):
    """ Record from user CSV. """
    address: int
    name: str
    comment: str
class CsvSystemSymbol(tp.NamedTuple):
    """ Record from system CSV. """
    address: int
    type: CsvSystemLabelType
    name: str

class CsvSymbols:
    """ ADT for a parsed CSV file. """
    kind: CsvSymbolType
    user: tp.Optional[tp.List['CsvUserSymbol']]
    system: tp.Optional[tp.List['CsvSystemSymbol']]
    def __init__(self, kind, arg):
        self.kind = kind
        self.user = None
        self.system = None
        if kind == CsvSymbolType.User:
            self.user = arg
        elif kind == CsvSymbolType.System:
            self.system = arg
        else: assert False, kind

# =============================================================================
# Filtering stage

def _filter_user_symbols(bv: BinaryView, symbols: tp.List['CsvUserSymbol']):
    out = FilteredSymbols()
    for symbol in symbols:
        if symbol_is_probably_constant(symbol.name):
            out.ignored.append((IgnoreReason.Const, symbol))
            continue
        if symbol_address_is_function(bv, symbol.address):
            out.ignored.append((IgnoreReason.Static, symbol))
            continue

        effective_name = symbol.name
        effective_name = effective_name.strip()
        effective_name = _strip_function_signature(effective_name)
        effective_name = _convert_label_case_name(effective_name)
        kind = bn.SymbolType.FunctionSymbol if symbol_address_is_function(bv, symbol.address) else bn.SymbolType.DataSymbol

        out.symbols.append(bn.Symbol(bn.SymbolType.FunctionSymbol, symbol.address, effective_name))

    assert out.total_count() == len(symbols)
    return out

OPERATOR_RE = re.compile(r'\boperator\b')
def _strip_function_signature(s):
    # Zero puts function signatures in symbol names because he's using a Ollydbg plugin
    # that uses these to annotate things like `[ebp+4]`.  Strip 'em out.
    if not (s.endswith(')') and '(' in s):
        return s
    # Places where the '()' may have come from my own symbols;
    # I use it here in my own names to disambiguate overloads.
    if OPERATOR_RE.match(s):
        return s
    return s[:s.index('(')]

ZERO_ECL_INS_RE = re.compile('ecl_ins_([0-9]{3}.+)')
ZERO_ETEX_INS_RE = re.compile('([0-9]{2}__EX_.+)')
def _convert_label_case_name(s):
    match = ZERO_ECL_INS_RE.fullmatch(s)
    if match:
        return 'ecl__case_' + match.group(1)

    match = ZERO_ETEX_INS_RE.fullmatch(s)
    if match:
        return 'etex__case_' + match.group(1)

    return s

def _filter_system_symbols(bv: BinaryView, symbols: tp.List['CsvSystemSymbol']):
    out = FilteredSymbols()
    for symbol in symbols:
        if symbol.type in [CsvSystemLabelType.IMPORT, CsvSystemLabelType.EXPORT]:
            out.ignored.append((IgnoreReason.ImportExport, symbol))
            continue
        assert symbol.type == CsvSystemLabelType.ANALYSIS_LABEL

        nonsense_patterns = [
            "`string'",
            "_Int32ToUInt32",
            re.compile(r'[-_]*nan', re.IGNORECASE),
        ]
        if any(_match_str(symbol.name, pat) for pat in nonsense_patterns):
            out.ignored.append((IgnoreReason.Nonsense, symbol))
            continue

        if not symbol_address_is_function(bv, symbol.address):
            out.ignored.append((IgnoreReason.Nonsense, symbol))
            continue

        out.symbols.append(bn.Symbol(bv.SymbolType.FunctionSymbol, symbol.address, symbol.name))

    assert out.total_count() == len(symbols)
    return out

PROBABLY_FLOAT_RES = [
    re.compile(r'^[0-9PIfd.*/+() -]+$'),
    re.compile(r'N[aA]N[fd]'),
]
def symbol_is_probably_constant(s):
    if '/' in s:
        return True
    if '"' in s:
        return True
    if '.' in s:
        return True
    if any(r.match(s) for r in PROBABLY_FLOAT_RES):
        return True
    return False

def symbol_address_is_function(bv: BinaryView, addr: int):
    return bv.get_function_at(addr) is not None

def _match_str(s, pattern: tp.Union[str, tp.Pattern]):
    if isinstance(pattern, str):
        return s == pattern
    else:
        return pattern.fullmatch(s)

class IgnoreReason(enum.Enum):
    Const = enum.auto()
    Static = enum.auto()
    ImportExport = enum.auto()
    Nonsense = enum.auto()

class FilteredSymbols:
    symbols: tp.List[bn.Symbol]
    ignored: tp.List[tp.Tuple[IgnoreReason, bn.Symbol]]

    def __init__(self):
        self.symbols = []
        self.ignored = []

    def total_count(self):
        return len(self.symbols) + len(self.ignored)

# =============================================================================
# Apply-to-BV stage

# combination blacklist-whitelist type deal
RenameFilters = tp.List[tp.Tuple[Pattern, bool]]
RENAME_NOTHING: RenameFilters = [(re.compile('.*'), False)]
RENAME_ALL: RenameFilters = [(re.compile('.*'), True)]
def _apply_bv_symbols_with_undo(bv, symbols: tp.List[bn.Symbol], filters: RenameFilters):
    with recording_undo(bv) as rec:
        return _apply_bv_symbols(bv, symbols, filters, rec)

def _apply_bv_symbols(bv, symbols: tp.List[bn.Symbol], filters: RenameFilters, rec):
    """ NOTE: does not manage undo state. Do that externally. """
    filters = filters + RENAME_NOTHING  # if a custom list doesn't have a grab-all, default to whitelist semantics

    results = Results()
    for symbol in symbols:
        existing = bv.get_symbol_at(symbol.address)
        if existing is None:
            bv.define_user_symbol(symbol)
            rec.enable_auto_rollback()
            results.created.append(symbol)
            continue

        if symbol.name == existing.name:
            results.skipped_existing.append(symbol)
            continue

        # Find first matching filter
        for pat, should_rename in filters:
            if _match_str(symbol.name, pat):
                if should_rename:
                    bv.define_user_symbol(symbol)
                    rec.enable_auto_rollback()
                    results.renamed.append(Results.SymbolChange(old=existing, new=symbol))
                else:
                    results.skipped_conflict.append(Results.SymbolChange(old=existing, new=symbol))
                break
        else:
            assert False, "no pattern matched, this should be impossible"

    assert results.total_count() == len(symbols)
    return results

class Results:
    class SymbolChange(tp.NamedTuple):
        new: bn.Symbol
        old: bn.Symbol

    created: tp.List[bn.Symbol]
    renamed: tp.List[SymbolChange]
    skipped_existing: tp.List[bn.Symbol]
    skipped_conflict: tp.List[SymbolChange]

    def __init__(self):
        self.created = []
        self.renamed = []
        self.skipped_existing = []
        self.skipped_conflict = []

    def total_count(self):
        return len(self.created) + len(self.renamed) + len(self.skipped_existing) + len(self.skipped_conflict)

    def write(self, emit=print, verbose=False):
        self._write_log(emit, verbose=verbose)
        emit()
        self._write_summary(emit)

    def _write_summary(self, emit):
        emit(f'Actions performed:')
        emit(f'  Created: {len(self.created):4}')
        emit(f'  Renamed: {len(self.renamed):4}')
        emit(f'Entries skipped:')
        emit(f'  Existing: {len(self.skipped_existing):4}')
        emit(f'  Conflict: {len(self.skipped_conflict):4}')

    def _write_log(self, emit, verbose: bool):
        if verbose:
            for row in self.skipped_existing:
                emit(f'   Skipped (exists):  {row.name}')
        for row in self.skipped_conflict:
            emit(f' Skipped (conflict):  {row.old.name} -> {row.new.name}')
        for row in self.created:
            emit(f'            Created:  {row.name}')
        for row in self.skipped_conflict:
            emit(f'            Renamed:  {row.old.name} -> {row.new.name}')
