from keystone import *
from fa.commands import find_bytes

# TODO: remove
reload(find_bytes)


def run(segments, manner, manner_args, current_ea, args, **kwargs):
    mode = KS_MODE_PPC32
    if 'endianity' in kwargs:
        mode |= KS_MODE_BIG_ENDIAN if kwargs['endianity'] == '>' else KS_MODE_LITTLE_ENDIAN

    ks = Ks(KS_ARCH_PPC, mode)
    code = args
    compiled_buf = bytearray(ks.asm(code)[0])
    retval = find_bytes.find_raw(segments, manner, manner_args, current_ea, compiled_buf)
    print(retval)
    return retval
