from keystone import *
from fa.commands import utils


def run(segments, manner, manner_args, addresses, args, **kwargs):
    arch, mode, code = args.split(' ', 2)
    arch = eval(arch)
    mode = eval(mode)

    if manner == 'bele':
        if 'endianity' in kwargs:
            mode |= KS_MODE_BIG_ENDIAN if kwargs['endianity'] == '>' else KS_MODE_LITTLE_ENDIAN

    ks = Ks(arch, mode)
    compiled_buf = bytearray(ks.asm(code)[0])

    return [ea for ea in addresses if utils.read_memory(segments, ea, len(compiled_buf)) == compiled_buf]
