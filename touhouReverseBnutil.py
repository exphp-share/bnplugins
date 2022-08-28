import contextlib
import struct
import os
from binaryninja import log
import binaryninja as bn
import threading
import typing as tp

# ========================================================================

class UndoRecorder:
    def __init__(self): self.active = False
    def enable_auto_rollback(self): self.active = True

class _RecordingUndoState(tp.NamedTuple):
    rec: UndoRecorder
    thread_ident: int

_RECORDING_UNDO: tp.Optional[_RecordingUndoState] = None

@contextlib.contextmanager
def recording_undo(bv: bn.BinaryView):
    """ Context manager for ``bv.begin_undo_actions()``.  The contents of the ``with`` block
    will become a single undo-able action. (assuming at least one change was made inside)

    Changes made inside the ``with`` block can be rolled back on uncaught exceptions. However,
    for this to occur, you must call ``.enable_auto_rollback()`` on the returned object at least
    once after performing at least one successful modification to the ``BinaryView``.

    This context manager can be used recursively, but is not reentrant across multiple threads
    (it will detect this and throw an exception).

    >>> def rename_type_in_funcs(bv, old, new):
    ...     old_prefix = f'{old}::'
    ...     new_prefix = f'{new}::'
    ...     with recording_undo(bv) as rec:
    ...         for func in bv.functions:
    ...             if func.name.startswith(old_prefix):
    ...                 suffix = func.name[len(old_prefix):]
    ...                 new_name = new_prefix + suffix
    ...                 bv.define_user_symbol(Symbol(SymbolType.FunctionSymbol, func.start, new_name))
    ...                 rec.enable_auto_rollback()
    """
    global _RECORDING_UNDO

    if _RECORDING_UNDO:
        if _RECORDING_UNDO.thread_ident != threading.get_ident():
            # We can't possibly be re-entrant across multiple threads; how would you
            # define partially overlapping undo actions?!
            raise RuntimeError(f'Attempted to use `recording_undo` from multiple threads!')

        # Recursive call.  Just produce the existing 'rec' and do not use the API.
        #
        # This way, only the outermost call results in an undoable change.
        rec = _RECORDING_UNDO.rec
        try:
            yield rec
            return
        finally:
            if _RECORDING_UNDO.rec is not rec:
                log.log_warn('nested `recording_undo`s appear to have been closed out of order')

    rec = UndoRecorder()

    _RECORDING_UNDO = _RecordingUndoState(rec=rec, thread_ident=threading.get_ident())
    bv.begin_undo_actions()
    try:
        yield rec
    except:
        # If at least one action was performed, 'cancel' it by committing and undoing.
        # Even if no actions were performed, make BN stop recording by committing.
        bv.commit_undo_actions()
        if rec.active:
            bv.undo()
        raise
    finally:
        _RECORDING_UNDO = None

    bv.commit_undo_actions()

# ========================================================================

def name_function(bv: bn.BinaryView, addr, name):
    bv.define_user_symbol(bn.Symbol(bn.SymbolType.FunctionSymbol, addr, name))

def name_symbol(bv: bn.BinaryView, addr, name):
    bv.define_user_symbol(bn.Symbol(bn.SymbolType.DataSymbol, addr, name))

add_label = name_symbol

# ========================================================================

def read_f32(bv, addr): return struct.unpack('<f', bv.read(addr, 4))[0]
def read_f64(bv, addr): return struct.unpack('<d', bv.read(addr, 8))[0]
def read_u64(bv, addr): return struct.unpack('<Q', bv.read(addr, 8))[0]
def read_i64(bv, addr): return struct.unpack('<q', bv.read(addr, 8))[0]
def read_u32(bv, addr): return struct.unpack('<I', bv.read(addr, 4))[0]
def read_i32(bv, addr): return struct.unpack('<i', bv.read(addr, 4))[0]
def read_u16(bv, addr): return struct.unpack('<H', bv.read(addr, 2))[0]
def read_i16(bv, addr): return struct.unpack('<h', bv.read(addr, 2))[0]
def read_u8(bv, addr): return struct.unpack('<B', bv.read(addr, 1))[0]
def read_i8(bv, addr): return struct.unpack('<b', bv.read(addr, 1))[0]

__FLOAT_READERS = { 4: read_f32, 8: read_f64, }
__INT_READERS = { 1: read_i8, 2: read_i16, 4: read_i32, 8: read_i64, }
__UINT_READERS = { 1: read_u8, 2: read_u16, 4: read_u32, 8: read_u64, }
def get_type_reader(type: bn.Type):
    match type:
        case bn.FloatType():
            return __FLOAT_READERS[type.width]
        case bn.IntegerType():
            if type.signed:
                return __INT_READERS[type.width]
            else:
                return __UINT_READERS[type.width]
        case _:
            raise ValueError(f'cannot read type {type}')

def open_bv(path, **kw):
    # Note: This is now a context manager, hurrah!
    return bn.BinaryViewType.get_view_of_file(path, **kw)

class Game:
    thname: str
    num: int

    def __new__(cls, arg: 'Game | int | str'):
        return cls._lookup(arg)

    @classmethod
    def _lookup(cls, arg: 'Game | int | str'):
        if isinstance(arg, Game): return arg
        if isinstance(arg, int): return GAME_NUM_TO_GAME[arg]
        if isinstance(arg, str): return GAME_THNAME_TO_GAME[arg]
        raise TypeError(f'cannot convert {type(arg)} to Game')

    @classmethod
    def _create(cls, thname: str, num: int):
        obj = object.__new__(cls)
        obj.thname = thname
        obj.num = num
        return obj

    @classmethod
    def parse(cls, s: str):
        if all(ord(c) in range(ord('0'), ord('9')+1) for c in s):
            # numeric
            if s[0] > '4':
                s = '0' + s
            thname = 'th' + s
        elif s == 'alcostg':
            thname = 'th103'
        else:
            thname = s
        return GAME_THNAME_TO_GAME[thname]

    def __repr__(self): return f'Game({self.num})'
    def __str__(self): return self.thname
    def __hash__(self): return self.thname.__hash__()
    def __int__(self): return self.num
    def __eq__(self, other): return self.thname == Game._lookup(other).thname
    def __ne__(self, other): return self.thname != Game._lookup(other).thname
    def __lt__(self, other): return self.thname < Game._lookup(other).thname
    def __gt__(self, other): return self.thname > Game._lookup(other).thname
    def __le__(self, other): return self.thname <= Game._lookup(other).thname
    def __ge__(self, other): return self.thname >= Game._lookup(other).thname

Version = str
GAME_VERSIONS: tp.Dict[Game, Version] = {
    Game._create(thname='th06', num=6): 'v1.02h',
    Game._create(thname='th07', num=7): 'v1.00b',
    Game._create(thname='th08', num=8): 'v1.00d',
    Game._create(thname='th09', num=9): 'v1.50a',
    Game._create(thname='th095', num=95): 'v1.00a',
    Game._create(thname='th10', num=10): 'v1.00a',
    Game._create(thname='th103', num=103): 'v1.00a',
    Game._create(thname='th11', num=11): 'v1.00b',
    Game._create(thname='th12', num=12): 'v1.00c',
    Game._create(thname='th125', num=125): 'v1.00b',
    Game._create(thname='th128', num=128): 'v1.00b',
    Game._create(thname='th13', num=13): 'v1.00a',
    Game._create(thname='th14', num=14): 'v1.00b',
    Game._create(thname='th143', num=143): 'v1.00a',
    Game._create(thname='th15', num=15): 'v1.02a',
    Game._create(thname='th16', num=16): 'v1.00a',
    Game._create(thname='th165', num=165): 'v1.00a',
    Game._create(thname='th17', num=17): 'v1.00a',
    Game._create(thname='th18', num=18): 'v1.00a',
    Game._create(thname='th185', num=185): 'v1.00a',
    # NEWHU: 185
}
ALL_GAMES = sorted(GAME_VERSIONS)
GAME_NUM_TO_GAME = {game.num: game for game in ALL_GAMES}
GAME_THNAME_TO_GAME = {game.thname: game for game in ALL_GAMES}

def open_th_bv(bv: bn.BinaryView, source: str, update_analysis=False, **kw):
    """ Open a touhou bndb.  Another touhou bv is used to get a search directory.

    This is a context manager. (usable in `with`) """

    if os.sep not in source and '/' not in source:
        if source.startswith('th') and 'v' not in source:
            source += '.' + GAME_VERSIONS[Game(source)]
        source = os.path.join(os.path.dirname(bv.file.filename), source)

    if not source.lower().endswith('.bndb'):
        source += '.bndb'

    return bn.BinaryViewType.get_view_of_file(source, update_analysis=update_analysis, **kw)

def get_game_and_version(bv: bn.BinaryView) -> tp.Optional[tp.Tuple[Game, Version]]:
    filename = os.path.basename(bv.file.filename)
    if not filename.endswith('.bndb'):
        return None

    stem = filename[:-len('.bndb')]
    for game_obj in ALL_GAMES:
        game = str(game_obj)
        if stem.startswith(game):
            if stem[len(game)] != '.':
                continue
            version = stem[len(game) + 1:]
            return game_obj, version
    return None

# ========================================================================

def func_name_at(bv: bn.BinaryView, addr):
    funcs = bv.get_functions_containing(addr)
    if not funcs:
        return None
    return funcs[0].name

def llil_at(bv: bn.BinaryView, addr):
    funcs = bv.get_functions_containing(addr)
    if not funcs:
        return None
    func = funcs[0]

    llil = None
    for _ in range(20):
        llil = func.get_low_level_il_at(addr)
        if llil: return llil
        addr -= 1
    raise RuntimeError('could not find start of LLIL')

def llil_begin_addr(bv: bn.BinaryView, addr):
    llil = llil_at(bv, addr)
    if llil:
        return llil.address
    else:
        return None

# ========================================================================

def cached_llil(bv: bn.BinaryView):
    """
    Get LLIL instructions as {func_addr: [LowLevelILInstruction]}.

    This caches the result because constructing the LLIL instruction objects takes binja
    a rather long amount of time.
    """
    if 'exphp-cached-llil' not in bv.session_data:
        log.log_warn(f"Computing LLIL for '{bv.file.filename}'")
        bv.session_data['exphp-cached-llil'] = {func.start: list(func.llil_instructions) for func in bv.functions}
    return bv.session_data['exphp-cached-llil']

def drop_llil_cache(bv: bn.BinaryView):
    if 'exphp-cached-llil' in bv.session_data:
        log.log_warn(f"Dropping LLIL cache from '{bv.file.filename}'")
        del bv.session_data['exphp-cached-llil']

# ========================================================================

class Address(int):
    def __repr__(self): return f'{self:#x}'
    def __str__(self): return f'{self:#x}'
    def __add__(self, other): return Address(super().__add__(other))
    def __sub__(self, other): return Address(super().__sub__(other))
    def __mul__(self, other): return Address(super().__mul__(other))
    def __floordiv__(self, other): return Address(super().__floordiv__(other))
    def __mod__(self, other): return Address(super().__mod__(other))
    def __pow__(self, other, *args): return Address(super().__pow__(other, *args))
    def __lshift__(self, other): return Address(super().__lshift__(other))
    def __rshift__(self, other): return Address(super().__rshift__(other))
    def __and__(self, other): return Address(super().__and__(other))
    def __xor__(self, other): return Address(super().__xor__(other))
    def __or__(self, other): return Address(super().__or__(other))
    def __radd__(self, other): return Address(super().__radd__(other))
    def __rsub__(self, other): return Address(super().__rsub__(other))
    def __rmul__(self, other): return Address(super().__rmul__(other))
    def __rand__(self, other): return Address(super().__rand__(other))
    def __rxor__(self, other): return Address(super().__rxor__(other))
    def __ror__(self, other): return Address(super().__ror__(other))
    # don't want these
    # def __rfloordiv__(self, other): return Address(super().__rfloordiv__(other))
    # def __rmod__(self, other): return Address(super().__rmod__(other))
    # def __rpow__(self, other): return Address(super().__rpow__(other))
    # def __rlshift__(self, other): return Address(super().__rlshift__(other))
    # def __rrshift__(self, other): return Address(super().__rrshift__(other))

# shorthand
A = Address

