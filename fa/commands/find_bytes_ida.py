from collections import OrderedDict

from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('find-bytes-ida',
                                   description='expands the search results '
                                               'by an ida-bytes expression '
                                               '(Alt+B)')
    p.add_argument('--or', action='store_true')
    p.add_argument('expression')
    return p


@utils.yield_unique
def find_bytes_ida(expression, segments=None):
    for address in utils.ida_find_all(expression):
        yield address


def run(segments, args, addresses, interpreter=None, **kwargs):
    results = find_bytes_ida(args.expression)

    retval = set(addresses)
    if getattr(args, 'or'):
        retval.update(results)
    else:
        raise ValueError("must specify --or option")

    return list(OrderedDict.fromkeys(retval))
