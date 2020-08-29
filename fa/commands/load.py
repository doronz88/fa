from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''go back to previous result-set saved by 'store' command.

EXAMPLE:
    results = [0, 4, 8]
    store foo

    find-bytes 12345678
    results = [0, 4, 8, 10, 20]

    -> load foo
    results = [0, 4, 8]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('load',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('name', help='name of variable in history to go back '
                                'to')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    return interpreter.get_variable(args.name)
