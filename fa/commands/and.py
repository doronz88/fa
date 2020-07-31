from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''[DEPRECATED]
intersect with another command's resultset

EXAMPLE:
    results = [80]
    -> and offset 0
    results = [80]

EXAMPLE #2:
    results = [80]
    -> and offset 1
    results = []
'''


def get_parser():
    p = utils.ArgumentParserNoExit('and',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('cmd', nargs='+', help='command')
    return p


@utils.deprecated
def and_(addresses, cmd, interpreter):
    results = set(addresses)
    innert_command_results = interpreter.find_from_instructions_list(
        [cmd], addresses=addresses)
    results.intersection_update(innert_command_results)
    return list(results)


def run(segments, args, addresses, interpreter=None, **kwargs):
    cmd = args.cmd[0] + ' ' + ''.join('"{}"'.format(c) for c in args.cmd[1:])
    return and_(addresses, cmd, interpreter)
