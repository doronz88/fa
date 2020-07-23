from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('find',
                                   description='find another symbol defined '
                                               'in other SIG files')
    p.add_argument('name', help='symbol name')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    interpreter.find(args.name)

    # return an empty result-set
    return []
