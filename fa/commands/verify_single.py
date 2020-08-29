from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''verifies the result-list contains a single value

EXAMPLE #1:
    results = [4, 12, 0, 8]
    -> unique
    result = []

EXAMPLE #2:
    results = [4]
    -> unique
    result = [4]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('verify-single',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    return p


def verify_single(addresses):
    return addresses if len(addresses) == 1 else []


def run(segments, args, addresses, interpreter=None, **kwargs):
    return verify_single(addresses)
