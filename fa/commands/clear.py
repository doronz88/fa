from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''clears the current result-set

EXAMPLE:
    results = [0, 4, 8]
    -> clear
    results = []
'''


def get_parser():
    p = utils.ArgumentParserNoExit('clear',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    return []
