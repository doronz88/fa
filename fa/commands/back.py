from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('back',
                                   description='goes back in history '
                                               'of search results to '
                                               'those returned from a '
                                               'previous command')
    p.add_argument('amount', type=int,
                   help='amount of command results to go back by')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    return interpreter.history[-args.amount]
