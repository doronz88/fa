from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('single',
                                   description='reduces the result list '
                                               'into a singleton')
    p.add_argument('index', type=int, default=0, help='get item by an index')
    return p


def run(segments, args, addresses, **kwargs):
    if args.index + 1 > len(addresses):
        return []
    else:
        return [addresses[args.index]]
