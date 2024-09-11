import argparse
import inspect
import os
import warnings
from typing import Generator, Iterable, List, Optional, Tuple, Union

IDA_MODULE = False

try:
    import ida_bytes
    import ida_ida
    import ida_idp
    import ida_ua
    import idaapi
    import idautils
    import idc

    IDA_MODULE = True
except ImportError:
    pass

MAX_NUMBER_OF_OPERANDS = 6


def index_of(needle, haystack):
    try:
        return haystack.index(needle)
    except ValueError:
        return -1


def find_raw(needle, segments=None):
    if segments is None:
        segments = dict()

    if IDA_MODULE:
        # ida optimization
        needle = bytearray(needle)
        payload = ' '.join(['{:02x}'.format(b) for b in needle])
        for address in ida_find_all(payload):
            yield address
        return

    for segment_ea, data in segments.items():
        offset = index_of(needle, data)
        extra_offset = 0

        while offset != -1:
            address = segment_ea + offset + extra_offset
            yield address

            extra_offset += offset + 1
            data = data[offset + 1:]

            offset = index_of(needle, data)


def ida_find_all(payload: Union[bytes, bytearray, str]) -> Generator[int, None, None]:
    if float(idaapi.get_kernel_version()) < 9:
        ea = idc.find_binary(0, idc.SEARCH_DOWN | idc.SEARCH_REGEX, payload)
        while ea != idc.BADADDR:
            yield ea
            ea = idc.find_binary(ea + 1, idc.SEARCH_DOWN | idc.SEARCH_REGEX, payload)
    else:
        ea = ida_bytes.find_bytes(payload, 0)
        while ea != idc.BADADDR:
            yield ea
            ea = ida_bytes.find_bytes(payload, ea + 1)


def read_memory(segments, ea, size):
    if IDA_MODULE:
        return idc.get_bytes(ea, size)

    for segment_ea, data in segments.items():
        if (ea <= segment_ea + len(data)) and (ea >= segment_ea):
            offset = ea - segment_ea
            return data[offset:offset + size]


def yield_unique(func):
    def wrapper(*args, **kwargs):
        results = set()
        for i in func(*args, **kwargs):
            if i not in results:
                yield i
                results.add(i)

    return wrapper


class ArgumentParserNoExit(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(message)


def deprecated(function):
    frame = inspect.stack()[1]
    module = inspect.getmodule(frame[0])
    filename = module.__file__
    command_name = os.path.splitext(os.path.basename(filename))[0]

    warnings.warn('command: "{}" is deperected and will be removed in '
                  'the future.'.format(command_name, DeprecationWarning))
    return function


def add_struct_to_idb(name):
    idc.import_type(-1, name)


def find_or_create_struct(name):
    sid = idc.get_struc_id(name)
    if sid == idc.BADADDR:
        sid = idc.add_struc(-1, name, 0)
        print("added struct \"{0}\", id: {1}".format(name, sid))
    else:
        print("struct \"{0}\" already exists, id: ".format(name, sid))

    add_struct_to_idb(name)

    return sid


def create_regs_description(*regs) -> List[Tuple[int, str]]:
    result = []
    for i, r in enumerate(regs):
        if r is not None:
            result.append((i, r))
    return result


def add_operand_args(parser: argparse.ArgumentParser) -> None:
    for op_ix in range(MAX_NUMBER_OF_OPERANDS):
        parser.add_argument(f'--op{op_ix}', default=None)


def create_regs_description_from_args(*args) -> List[Tuple[int, str]]:
    regs = []
    for op_ix in range(MAX_NUMBER_OF_OPERANDS):
        v = getattr(args, f'op{op_ix}', None)
        if v is not None:
            v = [i.strip() for i in v.split(',')]
        regs.append(v)
    return create_regs_description(*regs)


def size_of_operand(op: 'ida_ua.op_t') -> int:
    """
    See https://reverseengineering.stackexchange.com/questions/19843/how-can-i-get-the-byte-size-of-an-operand-in-ida-pro
    """
    tbyte = 8
    dt_ldbl = 8
    n_bytes = [1, 2, 4, 4, 8,
               tbyte, -1, 8, 16, -1,
               -1, 6, -1, 4, 4,
               dt_ldbl, 32, 64]
    return n_bytes[op.dtype]


def get_operand_width(ea: int, index: int) -> int:
    """
    See https://reverseengineering.stackexchange.com/questions/19843/how-can-i-get-the-byte-size-of-an-operand-in-ida-pro
    """
    insn = idautils.DecodeInstruction(ea)
    return size_of_operand(insn.ops[index])


def resolve_expr(s: str, raise_on_failure: bool = True) -> Optional[int]:
    try:
        return int(s, 0)
    except ValueError:
        v = idc.get_name_ea_simple(s)
        if v == idc.BADADDR:
            if raise_on_failure:
                raise
            return None
        return v


def is_arch_arm() -> bool:
    return ida_ida.getinf_str(ida_ida.INF_PROCNAME).lower().split('\x00', 1)[0] == 'arm'


def get_reg_num(reg_name: str, raise_on_failure: bool = True) -> Optional[int]:
    ri = ida_idp.reg_info_t()
    status = ida_idp.parse_reg_name(ri, reg_name)
    if not status:
        if raise_on_failure:
            raise ValueError(f'invalid register name: {reg_name}')
        return None
    return ri.reg


def parse_displacement_syntax(string: str) -> Tuple[Optional[int], Optional[int]]:
    split_plus = string.find('+')
    split_minus = string.find('-')
    if split_plus != -1 and split_minus != -1:
        raise ValueError(f'Invalid values format: "{string}" (both "+" and "-" signs found)')
    if split_minus != -1:
        parts = string.split('-')
        minus = True
    else:
        parts = string.split('+')
        minus = False

    if len(parts) > 2:
        raise ValueError(f'Invalid values format: "{string}" (too many values)')

    if len(parts) == 1:
        disp = 0
    else:
        displacement_str = parts[1].strip()
        if not displacement_str:
            disp = None
        else:
            disp = resolve_expr(displacement_str)
            if minus:
                disp = -disp

    reg_str = parts[0].strip()
    if not reg_str:
        reg_num = None
    else:
        reg_num = get_reg_num(reg_str)

    return reg_num, disp


def compare_immediate_value(op_val: Optional[int], values: Iterable[str]) -> bool:
    return any(op_val == resolve_expr(v, raise_on_failure=False) for v in values)


def compare_reg_value(op_val: Optional[int], values: Iterable[str]) -> bool:
    return any(op_val == get_reg_num(v, raise_on_failure=False) for v in values)


def compare_cr_reg(op_val: Optional[int], values: Iterable[str]) -> bool:
    for v in values:
        if v.startswith('c'):
            try:
                n = int(v[1:])
            except ValueError:
                continue
            if n == op_val:
                return True
    return False


def compare_arm_coprocessor_operand(ea: int, index: int, values: Iterable[str]) -> bool:
    assert idc.get_operand_type(ea, 0) == idc.o_imm
    assert idc.get_operand_type(ea, 1) >= 8  # processor specific type
    assert idc.get_operand_type(ea, 2) == idc.o_imm

    if index == 0:
        return any(v.lower() == 'p15' for v in values)

    if index == 1:
        op_val = idc.get_operand_value(ea, 0)
        return compare_immediate_value(op_val, values)

    if index == 5:
        op_val = idc.get_operand_value(ea, 2)
        return compare_immediate_value(op_val, values)

    insn = idautils.DecodeInstruction(ea)
    operand = insn.ops[1]

    if index == 2:
        op_val = operand.reg
        return compare_reg_value(op_val, values)

    if index == 3:
        op_val = operand.specflag1
        return compare_cr_reg(op_val, values)

    if index == 4:
        op_val = operand.specflag2
        return compare_cr_reg(op_val, values)

    raise ValueError(f'Unrecognized index {index} for "MCR" or "MRC" opcode')


def compare_operand_arm(ea: int, index: int, values: Iterable[str]) -> bool:
    """
    Compare a list of values to the operand in the given index, at the given address.
    Supports various formats, including:

    0x00000000: LDR R1, [SP, #0x34]
    0x00000004: ADD, R2, SP, #0x2C

    > add 0
    > verify-opcode ldr --op0 r1
    > verify-opcode ldr --op1 +0x34
    > verify-opcode ldr --op1 sp+
    > verify-opcode ldr --op1 sp+52

    > offset 4
    > verify-opcode add --op2 0x2c

    Note that the following syntax
    > verify-opcode ldr --op1 sp
    implies the displacement must be 0 (or non-existent), whereas sp+ implies that the displacement is unimportant.
    """
    insn = idautils.DecodeInstruction(ea)
    operand = insn.ops[index]
    op_type = operand.type
    op_val = idc.get_operand_value(ea, index)
    op_width = size_of_operand(operand)

    mnem = insn.get_canon_mnem()

    if mnem.lower() in ('mcr', 'mrc'):
        return compare_arm_coprocessor_operand(ea, index, values)

    if op_type == idc.o_void:
        return False

    if op_type == idc.o_imm:
        return compare_immediate_value(op_val, values)

    if op_type == idc.o_reg:
        return compare_reg_value(op_val, values)

    if op_type == idc.o_mem:
        for v in values:
            comp = op_val
            if v.startswith('='):
                v = v[1:]
                bs = idc.get_bytes(op_val, op_width)
                comp = int.from_bytes(bs, 'little')
            expected = resolve_expr(v)
            if comp == expected:
                return True
        return False

    if op_type == idc.o_displ:
        for v in values:
            try:
                reg_num, disp = parse_displacement_syntax(v)
            except ValueError as e:
                message = str(e)
                print(f'{message}, skipping...')
                continue

            found = True
            if reg_num is not None and reg_num != operand.reg:
                found = False
            if disp is not None and disp != op_val:
                found = False
            if found:
                return True
        return False

    print(f'Unknown op_type 0x{op_type:x} @ ea 0x{ea:x}, skipping...')
    return False


def compare_operand(ea: int, index: int, values: Iterable[str]) -> bool:
    # First handle specialized cases
    if is_arch_arm():
        return compare_operand_arm(ea, index, values)

    # Default logic
    return idc.get_operand_value(ea, index) in values
