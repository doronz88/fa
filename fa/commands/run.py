from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('run',
                                   description='run another SIG file')
    p.add_argument('name', help='SIG filename')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    interpreter.find_from_sig_path(args.name)

    # return an empty result-set
    return []
