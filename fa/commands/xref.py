import idautils

from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit()
    return p


def run(segments, args, addresses, **kwargs):
    xrefs = []
    for address in addresses:
        xrefs.extend(ref.frm for ref in idautils.XrefsTo(address))
    return list(set(xrefs))
