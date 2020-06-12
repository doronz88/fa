from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('single',
                                   description='reduces the result list '
                                               'into a singleton')
    p.add_argument('index', type=int, default=0, help='get item by an index')
    return p


def single(addresses, index):
    if index + 1 > len(addresses):
        return []
    else:
        return [addresses[index]]


def run(segments, args, addresses, interpreter=None, **kwargs):
    return single(addresses, args.index)
