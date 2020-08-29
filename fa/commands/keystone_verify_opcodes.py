from argparse import RawTextHelpFormatter
try:
    # flake8: noqa
    from keystone import *
except ImportError:
    print('keystone-engine module not installed')


import binascii

from fa.commands import verify_bytes
from fa import utils

DESCRIPTION = '''use keystone to verify the result-set matches the given
opcodes

EXAMPLE:
    0x00000000: push {r4-r7, lr}
    0x00000004: mov r0, r1

    results = [0, 4]
    -> keystone-verify-opcodes --bele KS_ARCH_ARM KS_MODE_ARM 'mov r0, r1'
    result = [4]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('keystone-verify-opcodes',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('--bele', action='store_true',
                   help='figure out the endianity from IDA instead of '
                        'explicit mode')
    p.add_argument('--until', type=int,
                   help='keep going onwards opcode-opcode until verified')
    p.add_argument('arch',
                   help='keystone architecture const (evaled)')
    p.add_argument('mode',
                   help='keystone mode const (evald)')
    p.add_argument('code',
                   help='keystone architecture const (opcodes to compile)')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    arch = eval(args.arch)
    mode = eval(args.mode)

    if args.bele:
        mode |= KS_MODE_BIG_ENDIAN if \
            interpreter.endianity == '>' else KS_MODE_LITTLE_ENDIAN

    ks = Ks(arch, mode)
    compiled_buf = bytearray(ks.asm(args.code)[0])

    setattr(args, 'hex_str', binascii.hexlify(compiled_buf).decode('utf8'))
    return verify_bytes.run(segments, args, addresses, **kwargs)
