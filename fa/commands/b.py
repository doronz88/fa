from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''branch unconditionally to label

EXAMPLE:
    results = []

    add 1
    -> b skip
    add 2
    label skip
    add 3

    results = [1, 3]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('b',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('label', help='label to jump to')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    interpreter.set_pc(args.label)
    # pc is incremented by 1, after each instruction
    interpreter.dec_pc()
    return addresses
