from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''add an hard-coded value into resultset

EXAMPLE:
    results = []
    -> add 80
    result = [80]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('add',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('value', type=int)
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    return addresses + [args.value]
