from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''intersection between N checkpoints

EXAMPLE:
    results1 = []
    checkpoint a
    results2 = []
    checkpoint b
    -> intersect a b 
'''


def get_parser():
    p = utils.ArgumentParserNoExit('intersect',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('checkpoints', nargs='+')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    results = set()
    for checkpoint in args.checkpoints:
        results.intersection_update(interpreter.checkpoints[checkpoint])
    return list(results)
