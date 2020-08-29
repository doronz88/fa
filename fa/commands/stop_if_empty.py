from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''exit if current resultset is empty

EXAMPLE:
    results = []

    -> stop-if-empty
    add 1

    results = []
'''


def get_parser():
    p = utils.ArgumentParserNoExit('stop-if-empty',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    if len(addresses) == 0:
        # just a big enough value which is always greater
        # then max available pc
        interpreter.set_pc(0xffffffff)
    return addresses
