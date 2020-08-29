from argparse import RawTextHelpFormatter
import binascii

from fa import utils

DESCRIPTION = '''expands the result-set with the occurrences of the given bytes

EXAMPLE:
    0x00000000: 01 02 03 04
    0x00000004: 05 06 07 08

    results = []
    -> find-bytes 01020304
    result = [0]

    -> find-bytes 05060708
    results = [0, 4]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('find-bytes',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('hex_str')
    return p


def find_bytes(hex_str, segments=None):
    needle = binascii.unhexlify(''.join(hex_str.split(' ')))
    return utils.find_raw(needle, segments=segments)


def run(segments, args, addresses, interpreter=None, **kwargs):
    results = list(find_bytes(args.hex_str, segments=segments))
    return addresses + results
