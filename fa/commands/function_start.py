# flake8: noqa

from capstone import *
import argparse

from fa.commands import utils

try:
    import idc
    import idaapi
except ImportError:
    pass


def locate_start_ppc(segments, ea, max_offset=0x1000):
    start_ea = ea
    inf = idaapi.get_inf_structure()
    opcode_size = 4

    mode = CS_MODE_32
    mode |= CS_MODE_BIG_ENDIAN if inf.mf else CS_MODE_LITTLE_ENDIAN
    cs = Cs(CS_ARCH_PPC, mode)

    while ea - start_ea <= max_offset:
        inst = list(cs.disasm(
            utils.read_memory(segments, ea, opcode_size), ea))[0]

        if ((inst.mnemonic == 'stwu') and
            (inst.op_str.startswith('r1'))) or \
                ((inst.mnemonic == 'mr') and
                 (inst.op_str.startswith('r12, r1'))):
            return ea

        ea -= opcode_size

    return idc.BADADDR


LOCATE_START_BY_ARCH = {
    'PPC': locate_start_ppc
}


def get_function_start(segments, ea):
    start = idc.GetFunctionAttr(ea, idc.FUNCATTR_START)
    return start

    # TODO: consider add support locate of function heads manually

    # # extract load address ourselves
    # inf = idaapi.get_inf_structure()
    # proc_name = inf.procName
    #
    # if proc_name in LOCATE_START_BY_ARCH.keys():
    #     return LOCATE_START_BY_ARCH[proc_name](segments, ea)


def get_parser():
    p = argparse.ArgumentParser()
    return p


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()
    results = set()
    for ea in addresses:
        result = get_function_start(segments, ea)
        if result != idc.BADADDR:
            results.add(result)
    return list(results)
