from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''save current result-set in a variable.
You can later load the result-set using 'load'

EXAMPLE:
    results = [0, 4, 8]
    -> store foo

    find-bytes --or 12345678
    results = [0, 4, 8, 10, 20]

    load foo
    results = [0, 4, 8]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('store',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('name', help='name of variable to use')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    interpreter.set_variable(args.name, addresses)
    return addresses
