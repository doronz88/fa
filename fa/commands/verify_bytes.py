from argparse import RawTextHelpFormatter
import binascii

from fa import utils

DESCRIPTION = '''reduce the result-set to those matching the given bytes

EXAMPLE:
    0x00000000: 01 02 03 04
    0x00000004: 05 06 07 08

    results = [0, 2, 4, 6, 8]
    -> verify-bytes '05 06 07 08'
    results = [4]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('verify-bytes',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('hex_str')
    return p


def verify_bytes(addresses, hex_str, segments=None, until=None):
    magic = binascii.unhexlify(''.join(hex_str.split(' ')))

    results = [ea for ea in addresses
               if utils.read_memory(segments, ea, len(magic)) == magic]

    if len(results) > 0:
        return results

    return results


def run(segments, args, addresses, interpreter=None, **kwargs):
    until = None
    if 'until' in args and args.until is not None:
        until = args.until
    return verify_bytes(addresses, args.hex_str,
                        segments=segments, until=until)
