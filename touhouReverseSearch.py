import weakref
import typing as tp
import struct
import os
from collections import defaultdict
from binaryninja import log

_BYTE_PAIR_INDEX = weakref.WeakKeyDictionary()  # type: ignore

# These take either a single value or an iterable of them (producing the union of results).
def search_f32(bv, arg): return _search_maybe_iter(bv, arg, lambda x: struct.pack('<f', x))
def search_f64(bv, arg): return _search_maybe_iter(bv, arg, lambda x: struct.pack('<d', x))
def search_u64(bv, arg): return _search_maybe_iter(bv, arg, lambda x: struct.pack('<Q', x))
def search_i64(bv, arg): return _search_maybe_iter(bv, arg, lambda x: struct.pack('<q', x))
def search_u32(bv, arg): return _search_maybe_iter(bv, arg, lambda x: struct.pack('<I', x))
def search_i32(bv, arg): return _search_maybe_iter(bv, arg, lambda x: struct.pack('<i', x))
def search_u16(bv, arg): return _search_maybe_iter(bv, arg, lambda x: struct.pack('<H', x))
def search_i16(bv, arg): return _search_maybe_iter(bv, arg, lambda x: struct.pack('<h', x))
def search_u8(bv, arg): return _search_maybe_iter(bv, arg, lambda x: struct.pack('<B', x))
def search_i8(bv, arg): return _search_maybe_iter(bv, arg, lambda x: struct.pack('<b', x))

def _search_maybe_iter(bv, arg, packer):
    from collections.abc import Iterable

    if not isinstance(arg, Iterable):
        arg = [arg]

    results = []
    for value in arg:
        results.extend(search_bytes(bv, packer(value)))
    return results

def search_bytes(bv, bs):
    index = _get_byte_pair_index(bv)
    if len(bs) < 2:
        raise RuntimeError('searching for less than two bytes is a bad idea...')

    matches = set(index[bs[0], bs[1]])
    for offset, (byte1, byte2) in enumerate(_window2(bs[1:]), start=1):
        matches = matches & set(addr - offset for addr in index[byte1, byte2])
    return sorted(matches)

def _get_byte_pair_index(bv):
    if bv not in _BYTE_PAIR_INDEX:
        log.log_warn(f'Generating index for {os.path.basename(bv.file.filename)}')
        _BYTE_PAIR_INDEX[bv] = _generate_byte_pair_index(bv)

    return _BYTE_PAIR_INDEX[bv]

def _generate_byte_pair_index(bv):
    out = defaultdict(list)
    address_start = bv.sections['.text'].start
    address_end   = bv.sections['.text'].end
    bits = bv.read(address_start, address_end - address_start)
    for addr, (byte1, byte2) in enumerate(_window2(bits), start=address_start):
        out[byte1, byte2].append(addr)
    return out

def _window2(it):
    it = iter(it)
    prev = next(it)
    for x in it:
        yield prev, x
        prev = x
