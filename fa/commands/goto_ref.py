from fa.commands import utils

try:
    import idautils
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit()
    return p


@utils.yield_unique
def goto_ref(addresses):
    for address in addresses:
        refs = list(idautils.CodeRefsFrom(address, 1))
        if len(refs) > 1:
            yield refs[1]


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()
    return list(goto_ref(addresses))
