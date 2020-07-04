from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''go back to previous result-set saved by 'checkpoint' command.

EXAMPLE:
    results = [0, 4, 8]
    checkpoint foo

    find-bytes --or 12345678
    results = [0, 4, 8, 10, 20]

    -> back-to-checkpoint foo
    results = [0, 4, 8]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('back-to-checkpoint',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('name', help='name of checkpoint in history to go back '
                                'to')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    return interpreter.checkpoints[args.name]
