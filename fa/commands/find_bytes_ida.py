from collections import OrderedDict

from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit()
    p.add_argument('--or', action='store_true')
    p.add_argument('expression')
    return p


@utils.yield_unique
def find_bytes_ida(expression, segments=None):
    for address in utils.ida_find_all(expression):
        yield address


def run(segments, args, addresses, **kwargs):
    results = find_bytes_ida(args.expression)

    retval = set(addresses)
    if getattr(args, 'or'):
        retval.update(results)
    elif getattr(args, 'and'):
        raise ValueError("not supported")
    else:
        raise ValueError("must specify or manner")

    return list(OrderedDict.fromkeys(retval))
