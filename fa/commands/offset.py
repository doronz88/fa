from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit()
    p.add_argument('offset', type=int)
    return p


def run(segments, args, addresses, **kwargs):
    return [ea + args.offset for ea in addresses]
