from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''performs a sort on the current result-set

EXAMPLE:
    results = [4, 12, 0, 8]
    -> sort
    result = [0, 4, 8 ,12]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('sort',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    return p


def sort(addresses):
    addresses.sort()
    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return sort(addresses)
