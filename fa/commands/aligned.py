from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('aligned',
                                   description='reduces the list to only '
                                               'those aligned to a specific '
                                               'value')
    p.add_argument('value', type=int)
    return p


def aligned(addresses, value):
    return [ea for ea in addresses if ea % value == 0]


def run(segments, args, addresses, **kwargs):
    return list(aligned(addresses, args.value))
