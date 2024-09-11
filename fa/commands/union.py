from argparse import RawTextHelpFormatter
from typing import List

from fa import utils

DESCRIPTION = '''union two or more variables

EXAMPLE:
    results = [0, 4, 8]
    store a
    ...
    results = [0, 12, 20]
    store b

    -> union a b
    results = [0, 4, 8, 12, 20]
'''


def get_parser() -> utils.ArgumentParserNoExit:
    p = utils.ArgumentParserNoExit('union',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('variables', nargs='+', help='variable names')
    p.add_argument('--piped', '-p', action='store_true')
    return p


def run(segments, args, addresses: List[int], interpreter=None, **kwargs) -> List[int]:
    if args.piped:
        first_var = addresses
    else:
        first_var = interpreter.get_variable(args.variables.pop(0))

    results = set(first_var)

    for c in args.variables:
        results.update(interpreter.get_variable(c))

    return list(results)
