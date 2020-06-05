import pdb

from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('trace',
                                   description='sets a pdb breakpoint')
    return p


def trace(addresses):
    pdb.set_trace()
    return addresses


def run(segments, args, addresses, **kwargs):
    return trace(addresses)
