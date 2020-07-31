from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''intersect two or more checkpoints

EXAMPLE:
    results = [0, 4, 8]
    checkpoint a
    ...
    results = [0, 12, 20]
    checkpoint b

    -> intersect a b
    results = [0]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('intersect',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('checkpoints', nargs='+', help='checkpoint names')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    first_checkpoint = args.checkpoints[0]
    results = set(interpreter.checkpoints[first_checkpoint])

    for c in args.checkpoints[1:]:
        results.intersection_update(interpreter.checkpoints[c])

    return list(results)
