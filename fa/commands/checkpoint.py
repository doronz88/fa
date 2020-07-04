from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''save current result-set as a checkpoint.
You can later restore the result-set using 'back-to-checkpoint'

EXAMPLE:
    results = [0, 4, 8]
    -> checkpoint foo

    find-bytes --or 12345678
    results = [0, 4, 8, 10, 20]

    back-to-checkpoint foo
    results = [0, 4, 8]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('checkpoint',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('name', help='name of checkpoint to use')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    interpreter.checkpoints[args.name] = addresses
    return addresses
