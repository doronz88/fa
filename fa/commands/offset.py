from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''advance the result-set by a given offset

EXAMPLE:
    results = [0, 4, 8, 12]
    -> offset 4
    result = [4, 8, 12, 16]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('offset',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('offset')
    return p


def offset(addresses, advance_by):
    for ea in addresses:
        yield ea + advance_by


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(offset(addresses, eval(args.offset)))
