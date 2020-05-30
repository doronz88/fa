from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('aligned',
                                   description='reduces the list to only '
                                               'those aligned to a specific '
                                               'value')
    p.add_argument('value', type=int)
    return p


def run(segments, args, addresses, **kwargs):
    args, rest = args
    return [ea for ea in addresses if ea % args.value == 0]
