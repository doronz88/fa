from fa import utils


def get_parser():
    p = utils.ArgumentParserNoExit('append',
                                   description='append results from another '
                                               'command')
    p.add_argument('cmd', nargs='+', help='command')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    cmd = args.cmd[0] + ' ' + ''.join('"{}"'.format(c) for c in args.cmd[1:])
    return addresses + interpreter.find_from_instructions_list(
        [cmd], addresses=addresses)
