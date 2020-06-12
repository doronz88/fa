from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('offset',
                                   description='advance by a given offset')
    p.add_argument('offset', type=int)
    return p


def offset(addresses, length):
    for ea in addresses:
        yield ea + length


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(offset(addresses, args.offset))
