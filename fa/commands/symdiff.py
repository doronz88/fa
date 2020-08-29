from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''symmetric difference between two or more variables

EXAMPLE:
    results = [0, 4, 8]
    store a
    ...
    results = [0, 12, 20]
    store b

    -> symdiff a b
    results = [4, 8, 12, 20]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('symdiff',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('variables', nargs='+', help='variable names')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    first_var = args.variables[0]
    results = set(interpreter.get_variable(first_var))

    for c in args.variables[1:]:
        results.symmetric_difference_update(interpreter.get_variable(c))

    return list(results)
