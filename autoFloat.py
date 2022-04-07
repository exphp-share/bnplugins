from binaryninja import log, Type, PluginCommand, Symbol, SymbolType
import binaryninja as bn
import numpy as np
import struct

from touhouReverseBnutil import recording_undo

def convert_to_float(bv: bn.BinaryView, addr, width):
    with recording_undo(bv) as rec:
        _do_convert_to_float(bv, addr, width, rec=rec)

def _do_convert_to_float(bv: bn.BinaryView, addr, width, rec=None):
    if len(bv.get_functions_containing(addr)) > 0:
        # so I can't trigger it by accident and create dumb data vars
        # (though oftentimes it still gets past this somehow...)
        log.log_error(f'autoFloat: This is inside a function. Are you mad?')
        return

    data = bv.read(addr, width)
    if len(data) < width:
        log.log_error(f'could not read float at {addr:#x}')
        return

    # numpy's float32 has pretty good formatting for single precision floats.
    # (it appears to be minimal round-trip precision implemented directly on SP floats,
    #  rather than a hack that tries to accomplish this by formatting doubles)
    #
    # Read the float into a numpy float32.  Not actually sure if there's a nice API for
    # this so just parse the IEEE-754 format.
    if width == 4:
        as_int = sum(x * 256**i for (i, x) in enumerate(data))
        mantissa = as_int % 2**23
        exponent = (as_int >> 23) % 2**8
        if exponent == 0 or exponent == 0xFF:
            log.log_error(f'formatting of infinities, denorms, and NaN not implemented')
            return
        sign = as_int >> 31
        f32 = np.float32((-1)**sign) * np.float32(1 + mantissa * 2**-23) * np.float32(2**(exponent - 127))

        # '{}'.__format__(x) and str(x) are not the same for np.float32.  str is the nice one.
        f32s = str(f32)
        if f32s.endswith('.0'):
            f32s = f32s[:-len('.0')]

        name = f'float({f32s})'

    elif width == 8:
        f64, = struct.unpack('<d', data)

        if not (np.isfinite(f64) and abs(f64) > np.finfo(float).tiny):
            log.log_error(f'formatting of infinities, denorms, and NaN not implemented')
            return

        name = f'double({f64})'

    else: assert False, f'bad width: {width}'

    # duplicate symbols are allowed now so no need to check
    bv.define_user_symbol(Symbol(SymbolType.DataSymbol, addr, name))
    rec.enable_auto_rollback()
    bv.define_user_data_var(addr, Type.float(width))

convert_to_single = lambda bv, addr: convert_to_float(bv, addr, 4)
convert_to_double = lambda bv, addr: convert_to_float(bv, addr, 8)
PluginCommand.register_for_address('Convert to single-precision float', 'Set the type at this location to a float', convert_to_single)
PluginCommand.register_for_address('Convert to double-precision float', 'Set the type at this location to a double', convert_to_double)
