from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''get the result appearing the most in the result-set

EXAMPLE:
    results = [0, 4, 4, 8, 12]
    -> most-common
    result = [4]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('most-common',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    return p


def most_common(addresses):
    addresses = list(addresses)
    if len(addresses) == 0:
        return []
    return [max(set(addresses), key=addresses.count)]


def run(segments, args, addresses, interpreter=None, **kwargs):
    return most_common(addresses)
