from fa.commands import utils

try:
    import idautils
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit()
    return p


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()

    results = []
    for address in addresses:
        refs = list(idautils.CodeRefsFrom(address, 1))
        if len(refs) > 1:
            results.append(refs[1])

    return list(set(results))
