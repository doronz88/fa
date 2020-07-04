from argparse import RawTextHelpFormatter
from fa import utils


DESCRIPTION = '''go back to previous result-set

EXAMPLE:
    find-bytes --or 01 02 03 04
    results = [0, 0x100, 0x200]

    find-bytes --or 05 06 07 08
    results = [0, 0x100, 0x200, 0x300, 0x400]

    -> back -3
    results = [0, 0x100, 0x200]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('back',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('amount', type=int,
                   help='amount of command results to go back by')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    return interpreter.history[-args.amount]
