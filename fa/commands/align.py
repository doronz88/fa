from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''align results to given base (round-up)

EXAMPLE:
    results = [0, 2, 4, 6, 8]
    -> align 4
    results = [0, 4, 4, 8, 8]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('align',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('value', type=int)
    return p


def align(addresses, value):
    return [((ea + (value - 1)) // value) * value for ea in addresses]


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(align(addresses, args.value))
