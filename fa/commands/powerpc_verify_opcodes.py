from keystone import *
from fa.commands import utils


def run(segments, manner, manner_args, addresses, args, **kwargs):
    mode = KS_MODE_PPC32
    if 'endianity' in kwargs:
        mode |= KS_MODE_BIG_ENDIAN if kwargs['endianity'] == '>' else KS_MODE_LITTLE_ENDIAN

    ks = Ks(KS_ARCH_PPC, mode)
    code = args
    compiled_buf = bytearray(ks.asm(code)[0])

    return [ea for ea in addresses if utils.read_memory(segments, ea, len(compiled_buf)) == compiled_buf]
