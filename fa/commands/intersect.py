from argparse import RawTextHelpFormatter
from typing import List

from fa import utils

DESCRIPTION = '''intersect two or more variables

EXAMPLE:
    results = [0, 4, 8]
    store a
    ...
    results = [0, 12, 20]
    store b

    -> intersect a b
    results = [0]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('intersect',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('variables', nargs='+', help='variable names')
    p.add_argument('--piped', '-p', action='store_true')
    return p


def run(segments, args, addresses: List[int], interpreter=None, **kwargs):
    if args.piped:
        first_var = addresses
    else:
        first_var = interpreter.get_variable(args.variables.pop(0))

    results = set(first_var)

    for c in args.variables:
        results.intersection_update(interpreter.get_variable(c))

    return list(results)
