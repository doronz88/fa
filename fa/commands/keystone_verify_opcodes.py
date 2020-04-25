# flake8: noqa

import binascii

from keystone import *

from fa.commands import verify_bytes, utils


def get_parser():
    p = utils.ArgumentParserNoExit()
    p.add_argument('--bele', action='store_true')
    p.add_argument('--until', type=int)
    p.add_argument('arch')
    p.add_argument('mode')
    p.add_argument('code')
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
    return verify_bytes.run(segments, args, addresses, **kwargs)
