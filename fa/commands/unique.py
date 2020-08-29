from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''make the resultset unique

EXAMPLE:
    results = [0, 4, 8, 8, 12]
    -> unique
    result = [0, 4, 8, 12]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('unique',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(set(addresses))
