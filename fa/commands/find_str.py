import sys
from argparse import RawTextHelpFormatter
import binascii
import six

from fa.commands import find_bytes

DESCRIPTION = '''expands the result-set with the occurrences of the given
string

EXAMPLE:
    0x00000000: 01 02 03 04
    0x00000004: 05 06 07 08
    0x00000008: 30 31 32 33 -> ASCII '0123'

    results = []
    -> find-str '0123'

    result = [8]
'''


def get_parser():
    p = find_bytes.get_parser()
    p.prog = 'find-str'
    p.description = DESCRIPTION
    p.formatter_class = RawTextHelpFormatter
    p.add_argument('--null-terminated', action='store_true')
    return p


def find_str(string, null_terminated=False):
    hex_str = binascii.hexlify(string)
    if null_terminated:
        hex_str += '00'
    return find_bytes.find_bytes(hex_str)


def run(segments, args, addresses, interpreter=None, **kwargs):
    hex_str = binascii.hexlify(six.b(args.hex_str))
    
    if sys.version[0] == '3':
        hex_str = hex_str.decode()
    
    if args.null_terminated:
        hex_str += '00'
    setattr(args, 'hex_str', hex_str)
    return find_bytes.run(segments, args, addresses, **kwargs)
