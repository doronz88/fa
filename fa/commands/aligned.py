from fa.commands import utils


def get_parser():
    p = utils.ArgumentParserNoExit()
    p.add_argument('value', type=int)
    return p


def run(segments, args, addresses, **kwargs):
    args, rest = args
    return [ea for ea in addresses if ea % args.value == 0]
