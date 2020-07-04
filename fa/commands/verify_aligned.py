from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''leave only results fitting required alignment

EXAMPLE:
    results = [0, 2, 4, 6, 8]
    -> verify-aligned 4
    results = [0, 4, 8]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('verify-aligned',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('value', type=int)
    return p


def aligned(addresses, value):
    return [ea for ea in addresses if ea % value == 0]


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(aligned(addresses, args.value))
