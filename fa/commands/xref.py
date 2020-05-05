import idautils

from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit()
    return p


@utils.yield_unique
def xref(addresses):
    for address in addresses:
        for ref in idautils.XrefsTo(address):
            yield ref.frm


def run(segments, args, addresses, **kwargs):
    return list(xref(addresses))
