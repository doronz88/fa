from argparse import RawTextHelpFormatter
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
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    first_var = args.variables[0]
    results = set(interpreter.get_variable(first_var))

    for c in args.variables[1:]:
        results.intersection_update(interpreter.get_variable(c))

    return list(results)
