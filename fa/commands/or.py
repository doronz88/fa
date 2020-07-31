from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''[DEPRECATED]
unite with another command's resultset

EXAMPLE:
    results = [80]
    -> or offset 0
    results = [80]

EXAMPLE #2:
    results = [80]
    -> or offset 1
    results = [80, 81]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('or',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('cmd', nargs='+', help='command')
    return p


@utils.deprecated
def or_(addresses, cmd, interpreter):
    results = set(addresses)
    results.update(
        interpreter.find_from_instructions_list([cmd], addresses=addresses))

    return list(results)


def run(segments, args, addresses, interpreter=None, **kwargs):
    cmd = args.cmd[0] + ' ' + ''.join('"{}"'.format(c) for c in args.cmd[1:])
    return or_(addresses, cmd, interpreter)
