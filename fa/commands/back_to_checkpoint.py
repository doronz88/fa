from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('back-to-checkpoint',
                                   description='goes back in history to '
                                               'the result-set saved by a '
                                               'previous checkpoint')
    p.add_argument('name', help='name of checkpoint in history to go back '
                                'to')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    return interpreter.checkpoints[args.name]
