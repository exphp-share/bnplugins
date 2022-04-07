from binaryninja import BinaryView, DataRenderer, InstructionTextToken, InstructionTextTokenType, DisassemblyTextLine
from binaryninja import log, TypeClass, Type, ArrayType, PluginCommand
from touhouReverseBnutil import recording_undo

# datavar = bv.get_data_var_at(here)
# datavar.type.type_class == TypeClass.ArrayTypeClass and datavar.type.element_type == Type.char()

# bdr.CONTEXT[0].type == Type.named_type_from_registered_type(bv, 'BAR')

def convert_to_shift_jis(bv: BinaryView, addr):
    shift_jis = Type.named_type_from_registered_type(bv, 'ShiftJis')
    if shift_jis == Type.void():
        log.log_error('No ShiftJis type.  This should be a 1-byte struct.')
        return

    if shift_jis.width != 1:
        log.log_error('ShiftJis type has wrong size; it must be 1 byte.')
        return

    data = bv.read(addr, 4096)
    try:
        count = data.index(0) + 1
    except ValueError:
        log.log_error('Cannot find NUL for ShiftJis string')
        return

    with recording_undo(bv) as rec:
        bv.define_user_data_var(addr, Type.array(shift_jis, count))
        rec.enable_auto_rollback()

PluginCommand.register_for_address('Convert to ShiftJis', 'Set the type at this location to a ShiftJis[], if this type exists.', convert_to_shift_jis)

class ShiftJisDataRenderer(DataRenderer):
    def __init__(self):
        DataRenderer.__init__(self)

    def perform_is_valid_for_data(self, ctxt, bv: BinaryView, addr: int, ty: Type, context):
        try:
            sjis_type = Type.named_type_from_registered_type(bv, 'ShiftJis')
        except (AssertionError, ValueError, KeyError):
            # NOTE: currently binja throws AssertionError if it doesn't exist, which is odd.
            return False

        return isinstance(ty, ArrayType) and ty.element_type == sjis_type

    def perform_get_lines_for_data(self, ctxt, bv: BinaryView, addr: int, type: ArrayType, prefix, width, context):
        log.log_info('width: %s' % width)
        data = bv.read(addr, type.count)
        prefix.extend(render_shift_jis_with_fallback(data))
        return [DisassemblyTextLine(prefix, addr)]

    def __del__(self):
        pass

def render_shift_jis_with_fallback(text: bytes):
    # We won't even bother pulling out the trailing 0 like binja normally does
    # because it won't display properly (binja gets confused by the wider characters)
    try:
        text = escape_unicode(text.decode('shift-jis'))
    except UnicodeDecodeError:
        text = escape_bytes(text).decode('ascii')

    return [InstructionTextToken(InstructionTextTokenType.StringToken, text)]

DBL_QUOTE_BYTE_ESCAPES = [None] * 256
DBL_QUOTE_UNI_ESCAPES = None
def _init_escapes():
    global DBL_QUOTE_BYTE_ESCAPES
    global DBL_QUOTE_UNI_ESCAPES

    for x in range(32):
        DBL_QUOTE_BYTE_ESCAPES[x] = '\\x{:02}'.format(x).encode('ascii')

    for x in range(32, 127):
        DBL_QUOTE_BYTE_ESCAPES[x] = chr(x).encode('ascii')

    DBL_QUOTE_BYTE_ESCAPES[127] = b'\\x7f'
    for x in range(128, 256):
        DBL_QUOTE_BYTE_ESCAPES[x] = '\\x{:02}'.format(x).encode('ascii')

    DBL_QUOTE_BYTE_ESCAPES[ord('"')] = b'\\"'
    DBL_QUOTE_BYTE_ESCAPES[ord('\0')] = b'\\0' # Python2 repr does '\x00', blech
    # FIXME: look up actual list of escapes in C and compare against python
    for c in '\\\r\n\t\a\b':
        DBL_QUOTE_BYTE_ESCAPES[ord(c)] = repr(c)[1:-1].encode('ascii')

    DBL_QUOTE_UNI_ESCAPES = [s.decode('ascii') for s in DBL_QUOTE_BYTE_ESCAPES[:128]]

_init_escapes()

def escape_bytes(text):
    def escape_single(c):
        i = ord(c)
        return DBL_QUOTE_BYTE_ESCAPES[i] if i < 256 else c
    escaped = b''.join(map(escape_single, text))
    return b'"{}"'.format(escaped)

def escape_unicode(text):
    def escape_single(c):
        i = ord(c)
        return DBL_QUOTE_UNI_ESCAPES[i] if i < 128 else c
    escaped = ''.join(map(escape_single, text))
    return '"{}"'.format(escaped)

ShiftJisDataRenderer().register_type_specific()

# Hide large objects
class BigDataRenderer(DataRenderer):
    def __init__(self):
        DataRenderer.__init__(self)

    def perform_is_valid_for_data(self, ctxt, bv: BinaryView, addr, ty: Type, context):
        # Must be large
        if ty.width < 1000: return False

        # Over a megabyte?
        if ty.width > 1024*1024: return True

        # Medium size; only hide if all zeros
        bs = bv.read(addr, ty.width)
        return bs.count(b'\0') == ty.width

    def perform_get_lines_for_data(self, ctxt, bv, addr, type, prefix, width, context):
        prefix.append(InstructionTextToken(InstructionTextTokenType.StringToken, "{{{ BIG }}}"))
        return [DisassemblyTextLine(prefix, addr)]

    def __del__(self):
        pass

BigDataRenderer().register_type_specific()
