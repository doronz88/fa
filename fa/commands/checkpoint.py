from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('checkpoint',
                                   description='saves current result-set '
                                               'in checkpoint named "name"')
    p.add_argument('name', help='name of checkpoint to use')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    interpreter.checkpoints[args.name] = addresses
    return addresses
