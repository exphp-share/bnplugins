import math
import os
import re
from binaryninja import log
import binaryninja as bn
from dataclasses import dataclass
import typing as tp

from touhouReverseBnutil import recording_undo, UndoRecorder, add_label, name_function, get_type_reader

ECLMAP_SEARCH_DIR = r'F:\asd\clone\ecl-parse\map'

EX_MAP_14 = {
    0x1: 'EX_DIST',
    0x2: 'EX_ANIM',
    0x4: 'EX_ACCEL',
    0x8: 'EX_ANGLE_ACCEL',
    0x10: 'EX_ANGLE',
    0x40: 'EX_BOUNCE',
    0x80: 'EX_INVULN',
    0x100: 'EX_OFFSCREEN',
    0x200: 'EX_SETSPRITE',
    0x400: 'EX_DELETE',
    0x800: 'EX_PLAYSOUND',
    0x1000: 'EX_WRAP',
    0x2000: 'EX_SHOOT',
    0x4000: 'EX_DUMMY', # holds more args for EX_SHOOT
    0x8000: 'EX_REACT',
    0x10000: 'EX_LOOP', # formerly EX_GOTO
    0x20000: 'EX_MOVE',
    0x40000: 'EX_VEL',
    0x80000: 'EX_VELADD',
    0x100000: 'EX_BRIGHT',
    0x200000: 'EX_VELTIME',
    0x400000: 'EX_SIZE',
    0x800000: 'EX_SAVEANGLE',
    0x1000000: 'EX_SPECIAL',
    0x2000000: 'EX_LAYER',
    0x4000000: 'EX_DELAY',
    0x8000000: 'EX_LASER',
    0x20000000: 'EX_HITBOX',
    0x40000000: 'UNUSED',
    0x80000000: 'EX_WAIT',
}
EX_MAP_12 = {
    2**0: 'EX_DIST',
    2**1: 'EX_ANIM',
    2**2: 'EX_ACCEL',
    2**3: 'EX_ANGLE_ACCEL',
    2**4: 'EX_TURN_ADD',
    2**5: 'EX_TURN_AIM',
    2**6: 'EX_TURN_FIXED',
    2**8: 'EX_BOUNCE',
    2**9: 'EX_INVULN',
    2**10: 'EX_OFFSCREEN',
    2**11: 'EX_SETSPRITE_ANIM',
    2**12: 'EX_WAIT',
    2**13: 'EX_CANCEL',
    2**14: 'EX_PLAYSOUND',
    2**19: 'EX_SHOOT',
    2**20: 'EX_DUMMY',
    2**22: 'EX_LOOP',
    2**24: 'EX_SETSPRITE_NOANIM',
    2**25: 'EX_STEER',
    2**27: 'EX_VELADD',
    2**28: 'EX_BRIGHT',
    2**29: 'EX_VELTIME',
}
EX_MAP_11 = {
    2**0: 'EX_DIST',
    2**4: 'EX_ACCEL',
    2**5: 'EX_ANGLE_ACCEL',
    2**6: 'EX_TURN_ADD',
    2**7: 'EX_TURN_AIM',
    2**8: 'EX_TURN_FIXED',
    2**9: 'EX_PLAYSOUND',
    2**10: 'EX_BOUNCE_UDLR_SETSPEED',
    2**11: 'EX_BOUNCE_LR_SETSPEED',
    2**12: 'EX_INVULN',
    2**13: 'EX_OFFSCREEN',
    2**14: 'EX_SETSPRITE',
    2**15: 'EX_WAIT',
    2**16: 'EX_CANCEL',
    2**19: 'EX_SHOOT',
    2**20: 'EX_WRAP_LR',
    2**21: 'EX_BOUNCE_D',
    2**22: 'EX_LOOP',
    2**24: 'EX_SETSPRITE_NOANIM',
    2**25: 'EX_STEER',
    2**27: 'EX_BOUNCE_LR',
    2**28: 'EX_BRIGHT',
    2**29: 'EX_VELTIME',
}

# Global config used by add_ex_label, which must be set by the user.
@dataclass
class _ExLabelConfig:
    label_prefix: tp.Optional[str]
    ex_reg: tp.Optional[str]
    ex_map: tp.Optional[dict[int, str]]

EX_LABEL_CONFIG = _ExLabelConfig(label_prefix=None, ex_reg=None, ex_map=None)

def add_ex_label(bv: bn.BinaryView, addr, value=None):
    """
    For labeling the branches in Bullet::run_ex, LaserLine::run_ex and friends.

    Bullet::run_ex is the function generally called within Bullet::on_tick which checks if any *new* `et_ex` instructions are to be
    evaluated on this frame. This function appears to have been written as a ``switch`` whose ``cases`` were powers of two, and
    it generally gets compiled into a nested tree of conditional jumps which seems ugly to traverse.
    Hence, this plugin relies on a small amount of manual labor.

    Usage is as follows:
    - Set a keybind for this function.
    - Set the attributes of touhouReverse.EX_LABEL_CONFIG in the python console.
    - In graph disassembly view of Bullet::run_ex, click on the first instruction in any basic block which is specific
      to a single ex flag, and use the keybind.  If the register named in ex_reg can be proven to have a single possible value,
      a label will be generated at this case with the appropriate name.
    - If it worked, try clicking on all of the other cases and using the keybind.  (It's kinda fun, actually.)

    Typically, a number of branches for the smallest bits get compiled into an indirect jump table. (for instance, in TH17,
    bits 0 through 6 all go in a jump table).  Sometimes, the evaluation of this jump clobbers the register holding the EX bit,
    preventing proper case detection.
    For those cases, you can manually call this function. E.g. ``touhouReverse.add_ex_label(bv, 0x416976, 1 << 4)`` in TH17.
    """
    # We have to take these as globals since this function gets bound to keybinds.
    public_config_path = 'touhouReverse.EX_LABEL_CONFIG'
    bad = False
    if EX_LABEL_CONFIG.label_prefix is None:
        log.log_error(f'must set {public_config_path}.label_prefix first. (e.g. to "etex", which will create "etex__case_00040000__EX_VEL")')
        bad = True
    if EX_LABEL_CONFIG.ex_reg is None:
        log.log_error(f'must set {public_config_path}.ex_reg first. (to register that holds type of ex, e.g. "eax")')
        bad = True
    if EX_LABEL_CONFIG.ex_map is None:
        log.log_error(f'must set {public_config_path}.ex_map first. (to one of the EX_MAP_* constants, e.g. {__name__}.EX_MAP_12)')
        bad = True

    if bad:
        raise RuntimeError('could not add EX label. See log for errors.')

    _add_ex_label(bv, addr, label_prefix=EX_LABEL_CONFIG.label_prefix, ex_reg=EX_LABEL_CONFIG.ex_reg, ex_map=EX_LABEL_CONFIG.ex_map, value=value)


def _add_ex_label(bv: bn.BinaryView, addr, label_prefix, ex_reg, ex_map, value=None):
    if value is None:
        function = bv.get_functions_containing(addr)[0]
        ins = function.get_low_level_il_at(addr)
        values = ins.get_possible_reg_values(ex_reg)
        if values is None or not hasattr(values, 'value') or values.value is None:
            log.log_error(f"Register {ex_reg} does not have a const value at this address. ({values})")
            return
        value = values.value

    bit = round(math.log(value) / math.log(2))
    if 2**bit != value:
        log.log_error(f"Register {ex_reg} does not have a const value at this address. ({values})")
        return

    if value in ex_map:  # pylint: disable=unsupported-membership-test
        name = ex_map[value]  # pylint: disable=unsubscriptable-object
    else:
        name = ''

    label = f'{label_prefix}__case_{bit:02}{"__" if name else ""}{name}'
    comment = f'==== BIT {bit} - {name if name else "????"} ====\n\n'
    log.log_info(f'Labeling Ex {bit} at {addr}')

    with recording_undo(bv) as rec:
        add_label(bv, addr, label)
        bv.set_comment_at(addr, comment)
        rec.enable_auto_rollback()

bn.PluginCommand.register_for_address('Create etEx label', 'Create an etEx label.', add_ex_label)

# ========================================================================

# Fallback dicts for things that have multiple numbers mapping to them.
# (the dict key is the minimal number)

ECL_06_INS_FALLBACK = {
    4: ('cases_4', 'set'),
    13: ('cases_13', 'add'),
    14: ('cases_14', 'sub'),
    15: ('cases_15', 'mul'),
    16: ('cases_16', 'div'),
    17: ('cases_17', 'mod'),
    67: ('cases_67', 'et'),
    85: ('cases_85', 'laserOn'),
}

ECL_11_INS_FALLBACK = {
    280: ('cases_2xx', 'movePos'),
    281: ('cases_2xx', 'movePosTime'),
    284: ('cases_2xx', 'moveVel'),
    285: ('cases_2xx', 'moveVelTime'),
    288: ('cases_2xx', 'moveCircle'),
    289: ('cases_2xx', 'moveCircleTime'),
    292: ('cases_2xx', 'moveRand'),
    296: ('cases_2xx', 'movePos3d'),
    298: ('cases_2xx', 'moveAdd'),
    300: ('cases_2xx', 'moveEllipse'),
    301: ('cases_2xx', 'moveEllipseTime'),
    305: ('cases_2xx', 'moveEBezier'),
    342: ('cases_3xx', 'spell'),
    412: ('cases_4xx', 'laserOnA'),
    413: ('cases_4xx', 'laserStOn'),
    428: ('cases_4xx', 'laserOn'),
    429: ('cases_4xx', 'laserStOn2'),
}

ECL_12_INS_FALLBACK = {
    256: ('cases_2xx', 'enmCreate'),
    300: ('cases_3xx', 'movePos'),
    301: ('cases_3xx', 'movePosTime'),
    304: ('cases_3xx', 'moveVel'),
    305: ('cases_3xx', 'moveVelTime'),
    308: ('cases_3xx', 'moveCircle'),
    309: ('cases_3xx', 'moveCircleTime'),
    312: ('cases_3xx', 'moveRand'),
    316: ('cases_3xx', 'movePos3d'),
    318: ('cases_3xx', 'moveAdd'),
    320: ('cases_3xx', 'moveEllipse'),
    321: ('cases_3xx', 'moveEllipseTime'),
    325: ('cases_3xx', 'moveBezier'),
    422: ('cases_4xx', 'spell'),
}
ECL_12_VAR_FALLBACK = {
    -9997: ('case_9997', 'FINAL_X'),
    -9996: ('case_9996', 'FINAL_Y'),
    -9995: ('case_9994', 'ABS_X'),
    -9994: ('case_9993', 'ABS_Y'),
    -9993: ('case_9991', 'REL_X'),
    -9992: ('case_9990', 'REL_Y'),
}

ECL_13_INS_FALLBACK = {
    300: ('cases_3xx', 'enmCreate'),
    309: ('cases_3xx', 'enmCreateF'),
    319: ('cases_3xx', 'anmModify'),
    400: ('cases_4xx', 'movePos'),
    401: ('cases_4xx', 'movePosTime'),
    404: ('cases_4xx', 'moveVel'),
    405: ('cases_4xx', 'moveVelTime'),
    408: ('cases_4xx', 'moveCircle'),
    409: ('cases_4xx', 'moveCircleTime'),
    412: ('cases_4xx', 'moveRand'),
    416: ('cases_4xx', 'movePos3d'),
    418: ('cases_4xx', 'moveAdd'),
    420: ('cases_4xx', 'moveEllipse'),
    421: ('cases_4xx', 'moveEllipseTime'),
    425: ('cases_4xx', 'moveBezier'),
    434: ('cases_4xx', 'moveCurve'),
    440: ('cases_4xx', 'moveAngle'),
    441: ('cases_4xx', 'moveAngleTime'),
    444: ('cases_4xx', 'moveSpeed'),
    445: ('cases_4xx', 'moveSpeedTime'),
    522: ('cases_5xx', 'spell'),
    609: ('cases_6xx', 'etEx'),
}
ECL_165_INS_FALLBACK = dict(ECL_13_INS_FALLBACK)
ECL_165_INS_FALLBACK[509] = ('cases_509', 'dropItems')
ECL_165_INS_FALLBACK[615] = ('cases_615', 'etCancel')
ECL_165_INS_FALLBACK[635] = ('cases_635', 'etCancel2')

ECL_13_VAR_FALLBACK = {
    -9997: ('case_9997', 'FINAL_X'),
    -9996: ('case_9996', 'FINAL_Y'),
    -9995: ('case_9995', 'FINAL_Z'),
    -9994: ('case_9994', 'ABS_X'),
    -9993: ('case_9993', 'ABS_Y'),
    -9992: ('case_9992', 'ABS_Z'),
    -9991: ('case_9991', 'REL_X'),
    -9990: ('case_9990', 'REL_Y'),
    -9989: ('case_9989', 'REL_Z'),
}

ANM_V0_INS_FALLBACK = {
    6: ('case_0', 'nop'),
}
ANM_V7_INS_FALLBACK = {
    -0: ('case_0', 'nop'),
    -1: ('case_1', 'delete'),
}
ANM_V8_INS_FALLBACK = {
    -1: ('case_1', 'delete'),
}

def add_anm_labels(*args, **kw):
    """ Alias for add_ecl_labels. """
    return add_ecl_labels(*args, **kw)

def add_ecl_labels(bv: bn.BinaryView, addr, ins_offset, label_prefix, eclmap_path=None, fallback=None):
    """
    Note: addr is the address of the instruction that uses the table.
    For an indirect table, use the address of the first instruction.
    If the two table accesses are not in consecutive instructions, use a tuple of addresses
    for the two instructions.
    """
    if fallback is None:
        fallback = {}

    jumptable, jumptable_last_address = read_accessed_jumptable(bv, addr)
    jumptable = {k+ins_offset:v for (k,v) in jumptable.items()}
    eclmap = _read_eclmap(eclmap_path) if eclmap_path is not None else None

    if label_prefix[-4:] in ['ival', 'fval', 'iptr', 'fptr']:
        comment_prefix = 'var'
        mapping = eclmap['vars'] if eclmap else {}
        num_formatter = lambda x: str(abs(x))
    else:
        comment_prefix = 'ins'
        mapping = eclmap['ins'] if eclmap else {}
        num_formatter = str  # FIXME why not always do str(abs(x))? I forgot.

    nums_by_address = {}
    for num, address in jumptable.items():
        if address not in nums_by_address:
            nums_by_address[address] = []
        nums_by_address[address].append(num)

    fail = False
    labels_to_make = {}
    comments_to_make = {}
    for address in nums_by_address:
        if len(nums_by_address[address]) == 1:
            num = nums_by_address[address][0]
            if num in mapping:
                labels_to_make[address] = f'{label_prefix}__case_{num_formatter(num)}__{mapping[num]}'
                comments_to_make[address] = f'==== {comment_prefix} {num} - {mapping[num]} ===='
            else:
                labels_to_make[address] = f'{label_prefix}__case_{num_formatter(num)}'
                comments_to_make[address] = f'==== {comment_prefix} {num} - ???? ===='
        else:
            bad_nums = nums_by_address[address]
            fallback_key = min(bad_nums)
            if fallback_key in fallback:
                case_str, name = fallback[fallback_key]
                # my exporter relies on these, don't let them get accidentally left out
                if not (case_str.startswith('case_') or case_str.startswith('cases_')):
                    fail = True
                    log.log_error(f'fallback case str {repr(case_str)} for {repr(name)} does not start with "case_" or "cases_"')
                    continue
                labels_to_make[address] = f'{label_prefix}__{case_str}__{name}'
                comments_to_make[address] = '\n'.join(
                    f'==== {comment_prefix} {num} - {mapping[num] if num in mapping else "????"} ===='
                    for num in sorted(bad_nums)
                )
            elif address == jumptable_last_address:
                labels_to_make[address] = f'{label_prefix}__case_default'
            else:
                labels_to_make[address] = f'{label_prefix}__case_{fallback_key}__multiple'
                # fail = True
                # log.log_error(f'no fallback for {fallback_key}: {[(mapping[num] if num in mapping else num) for num in sorted(bad_nums)]}')
                # continue

    if fail:
        raise RuntimeError('There were errors. See the log.')

    with recording_undo(bv) as rec:
        for address, label in labels_to_make.items():
            add_label(bv, address, label)
            rec.enable_auto_rollback()
        for address, comment in comments_to_make.items():
            bv.set_comment_at(address, comment)
            rec.enable_auto_rollback()

def _read_eclmap(path):
    out = {
        'ins': {},
        'vars': {},
    }

    second_path = os.path.join(ECLMAP_SEARCH_DIR, path)
    if not os.path.exists(path) and os.path.exists(second_path):
        path = second_path
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    with open(path) as f:
        for line in f:
            if '#' in line:
                line = line[:line.index('#')]
            line = line.strip()
            if not line:
                continue
            if line.startswith('!'):
                mode = line[1:]
                continue
            if mode == 'ins_names':
                words = line.split()
                out['ins'][int(words[0])] = words[1]
            if mode == 'gvar_names':
                words = line.split()
                out['vars'][int(words[0])] = words[1]

    # assert out['ins'], 'no instructions'
    # assert out['vars'], 'no vars'
    return out

def read_accessed_jumptable(bv: bn.BinaryView, addr):
    """
    Read a jumptable, either direct or indirect.

    Returns ``(dict, last_address)``.  Last address is provided for indirect tables
    because it's typically the default case.  (it's None for direct tables)

    For indirect jump tables, the jmp is assumed to be the instruction after the mov.
    If there are instructions between the two, you can supply a tuple ``(addr1, addr2)``
    for the two instructions that access the tables.
    """
    from collections import abc
    addr2 = None
    if isinstance(addr, abc.Iterable):
        addr, addr2 = addr

    function = bv.get_functions_containing(addr)[0]
    ins = function.get_low_level_il_at(addr)
    tokens = ins.tokens
    if str(tokens[0]).startswith('jump'):
        # Direct table
        table = read_accessed_table(bv, addr)
        return {i:v for (i,v) in enumerate(table)}, None
    if str(tokens[1]).strip() == '=':
        # Indirect table
        addr2 = addr2 or addr + bv.get_instruction_length(addr)
        table_1 = read_accessed_table(bv, addr)
        table_2 = read_accessed_table(bv, addr2)
        return {i:table_2[v] for (i,v) in enumerate(table_1)}, table_2[-1]
    raise RuntimeError('unable to detect jumptable type')

def read_accessed_table(bv: bn.BinaryView, addr):
    function = bv.get_functions_containing(addr)[0]
    table_address = _find_address_in_llil(bv, function.get_low_level_il_at(addr))
    table_var = bv.get_data_var_at(table_address)
    if table_var is None:
        raise RuntimeError(f'no data var at {table_address}')

    item_type = table_var.type.element_type
    if item_type is None:
        raise RuntimeError(f'data var at {table_address} is not an array ({table_var.type_class})')

    reader = get_type_reader(item_type)
    item_width = item_type.width
    return [reader(bv, table_address + i*item_width) for i in range(table_var.type.count)]

def _find_address_in_llil(bv: bn.BinaryView, llil: bn.LowLevelILInstruction):
    def try_finding_type(search_type, llil: bn.LowLevelILInstruction):
        if llil.operation == bn.LowLevelILOperation.LLIL_JUMP_TO:
            # This has a shitton of address tokens and its AST is useless to us because there's
            # no way for us to tell what indices go where.
            # Easier for us to just read the table ourselves after locating its token somewhere inside the first operand.
            return try_finding_type(search_type, llil.operands[0])

        addresses = [tok.value for tok in llil.tokens if tok.type == search_type and bv.is_offset_readable(tok.value)]
        if len(addresses) == 1:
            return addresses[0]
        if len(addresses) > 1:
            joined = ', '.join(hex(x) for x in addresses)
            raise RuntimeError(f'ambiguous; multiple addresses ({joined})')
        return None

    out = try_finding_type(bn.InstructionTextTokenType.PossibleAddressToken, llil)
    if out is not None:
        return out
    out = try_finding_type(bn.InstructionTextTokenType.IntegerToken, llil)
    if out is not None:
        return out
    raise RuntimeError(f'no addresses found in tokens')

# ============================================================

def label_on_draw_instructions(bv: bn.BinaryView, game, func_name):
    with recording_undo(bv) as rec:
        _label_on_draw_instructions(bv, game, func_name, rec)

def _label_on_draw_instructions(bv: bn.BinaryView, game, func_name, rec: UndoRecorder):
    register_on_draw = next(_find_functions_by_re(bv, '^(UpdateFuncRegistry::)?register__?on_draw$'))
    function = bv.get_function_at(bv.get_symbols_by_name(func_name)[0].address)

    if game == '11':
        # 11 and 12 have crazy ABIs, and we can't even rely on the HLIL to abstract that away
        # because the HLIL basically strips away ebx and fails to recognize it as an argument.
        priority_register = 'ebx' # register that holds priority arg to register__on_draw

        text_section = bv.sections['.text']

        priority_value = None
        callback_addr = None
        for instr in function.llil_instructions:
            if instr.operation == bn.LowLevelILOperation.LLIL_CALL and instr.dest.value == register_on_draw.start:
                priority_value = instr.get_possible_reg_values(priority_register).value

                if callback_addr is None:
                    raise RuntimeError(f'a callback was not found for priority {priority_value}')

                callback_name = func_name.split('::')[0] + f'::on_draw_{priority_value:02x}'
                if func_name == 'AnmManager::initialize':
                    callback_name += _get_AnmManager_on_draw_suffix(bv, game, callback_addr)

                name_function(bv, callback_addr, callback_name)
                rec.enable_auto_rollback()

                callback_addr = None
                continue

            # callback is always the most recently seen immediate argument that resembles a function pointer
            for operand in instr.prefix_operands:
                if isinstance(operand, int) and text_section.start < operand < text_section.end:
                    callback_addr = operand
    else:
        raise RuntimeError('no applicable implementation yet for this game, go add one!')

def _get_AnmManager_on_draw_suffix(bv: bn.BinaryView, game, addr):
    function = bv.get_function_at(addr)
    render_layer = bv.get_symbols_by_name('AnmManager::render_layer')[0]

    if game == '11':
        layer_register = 'eax'
        for instr in function.llil_instructions:
            if isinstance(instr, bn.LowLevelILCall) and instr.dest.value == render_layer.address:
                layer_value = instr.get_possible_reg_values(layer_register).value
                if len(function.llil) <= 6:
                    return f'_just_renders_layer_{layer_value:02}'
                else:
                    return f'_also_renders_layer_{layer_value:02}'
    raise RuntimeError(f'no layer rendered by {addr:#10x}')

def _find_functions_by_re(bv: bn.BinaryView, s):
    r = re.compile(s)
    for f in bv.functions:
        if r.match(f.name):
            yield f

def label_tmagic_err_handlers(bv: bn.BinaryView):
    with recording_undo(bv) as rec:
        for func in bv.functions:
            for (ins_1, ins_2) in _window2(func.llil_instructions):
                if ins_1.operation != bn.LowLevelILOperation.LLIL_PUSH:
                    continue
                if ins_2.operation != bn.LowLevelILOperation.LLIL_PUSH:
                    continue
                operands_1 = ins_1.postfix_operands
                operands_2 = ins_2.postfix_operands
                if len(operands_1) != 3:
                    continue
                if str(operands_2[0]) != 'fsbase':
                    continue
                address = operands_1[0]
                log.log_info(f'error handler found at {address:#x}')
                add_label(bv, address, f'sub_{address:x}_err_handler')
                rec.enable_auto_rollback()

def label_tmagic_incref(bv: bn.BinaryView):
    with recording_undo(bv) as rec:
        for func in bv.functions:
            instrs = list(func.llil_instructions)
            for (ins_1, ins_2, ins_3) in zip(instrs, instrs[1:], instrs[2:]):
                if ins_1.operation != bn.LowLevelILOperation.LLIL_SET_REG:
                    continue
                if ins_2.operation != bn.LowLevelILOperation.LLIL_SET_REG:
                    continue
                if ins_3.operation != bn.LowLevelILOperation.LLIL_SET_REG:
                    continue
                operands_1 = ins_1.postfix_operands
                operands_2 = ins_2.postfix_operands
                operands_3 = ins_3.postfix_operands
                if len(operands_1) != 8:
                    continue
                if not isinstance(operands_1[2], bn.LowLevelILOperationAndSize):
                    continue
                if operands_1[2].operation != bn.LowLevelILOperation.LLIL_REG:
                    continue
                if operands_1[3] != -8:
                    continue
                if not isinstance(operands_1[5], bn.LowLevelILOperationAndSize):
                    continue
                if operands_1[5].operation != bn.LowLevelILOperation.LLIL_ADD:
                    continue

                log.log_info(f'{func.start:#x}  {len(instrs)}')

def _window2(it):
    it = iter(it)
    prev = next(it)
    for x in it:
        yield prev, x
        prev = x
