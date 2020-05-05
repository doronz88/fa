from fa.commands import utils

try:
    import idautils
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit()
    return p


def data_refs(addresses):
    for address in addresses:
        for ref in idautils.DataRefsFrom(address):
            yield ref


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()
    return list(data_refs(addresses))
