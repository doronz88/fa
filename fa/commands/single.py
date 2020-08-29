from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''peek a single result from the result-set (zero-based)

EXAMPLE:
    results = [0, 4, 8, 12]
    -> single 2
    result = [8]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('single',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('index', default='0', help='result index')
    return p


def single(addresses, index):
    if index + 1 > len(addresses):
        return []
    else:
        return [addresses[index]]


def run(segments, args, addresses, interpreter=None, **kwargs):
    return single(addresses, eval(args.index))
