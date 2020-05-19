import pdb

from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit('trace',
                                   description='sets a pdb breakpoint')
    return p


def run(segments, args, addresses, **kwargs):
    pdb.set_trace()
    return addresses
