from argparse import RawTextHelpFormatter
import binascii

from fa.commands import verify_bytes

DESCRIPTION = '''reduce the result-set to those matching the given string

EXAMPLE:
    0x00000000: 01 02 03 04
    0x00000004: 30 31 32 33 -> ascii '0123'

    results = [0, 2, 4]
    -> verify-str '0123'
    results = [4]
'''


def get_parser():
    p = verify_bytes.get_parser()
    p.add_argument('--null-terminated', action='store_true')

    p.prog = 'verify-str'
    p.description = DESCRIPTION
    p.formatter_class = RawTextHelpFormatter
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    hex_str = binascii.hexlify(args.hex_str)
    hex_str += '00' if args.null_terminated else ''

    setattr(args, 'hex_str', hex_str)
    return verify_bytes.run(segments, args, addresses, **kwargs)
