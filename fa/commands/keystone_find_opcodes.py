try:
    # flake8: noqa
    from keystone import *
except ImportError:
    print('keystone-engine module not installed')

import binascii

from fa.commands import find_bytes, utils


def get_parser():
    p = utils.ArgumentParserNoExit('keystone-find-opcodes', description='use keystone to search for the supplied'
                                                                        'opcodes')
    p.add_argument('--bele', action='store_true', help='figure out the endianity from IDA instead of explicit mode')
    p.add_argument('--or', action='store_true', help='mandatory. expands search results')
    p.add_argument('arch', help='keystone architecture const (evaled)')
    p.add_argument('mode', help='keystone mode const (evald)')
    p.add_argument('code', help='keystone architecture const (opcodes to compile)')
    return p


def run(segments, args, addresses, **kwargs):
    arch = eval(args.arch)
    mode = eval(args.mode)

    if args.bele:
        if 'endianity' in kwargs:
            mode |= KS_MODE_BIG_ENDIAN if \
                kwargs['endianity'] == '>' else KS_MODE_LITTLE_ENDIAN

    ks = Ks(arch, mode)
    compiled_buf = bytearray(ks.asm(args.code)[0])

    setattr(args, 'hex_str', binascii.hexlify(compiled_buf))
    return find_bytes.run(segments, args, addresses, **kwargs)
