from fa.commands import utils

try:
    import idautils
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit()
    return p


def goto_ref(addresses):
    for address in addresses:
        refs = list(idautils.CodeRefsFrom(address, 1))
        if len(refs) == 0:
            continue

        for ref in refs:
            if address + 4 != ref:
                yield ref


@utils.yield_unique
def goto_ref_unique(addresses):
    for address in goto_ref(addresses):
        yield address


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()
    return list(set(goto_ref(addresses)))
