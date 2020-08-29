from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''perform an 'if' statement to create conditional branches
using an eval'ed expression

EXAMPLE:
    results = [0, 4, 8]

    verify-single
    store a

    # jump to a_is_single_label since a == []
    -> python-if a a_is_single_label
    set-name a_isnt_single
    b end

    label a_is_single_label
    set-name a_is_single

    label end
'''


def get_parser():
    p = utils.ArgumentParserNoExit('python-if',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('cond', help='condition to evaluate (being eval\'ed)')
    p.add_argument('label', help='label to jump to if condition is true')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    if eval(args.cond, interpreter.get_all_variables()):
        interpreter.set_pc(args.label)
        # pc is incremented by 1, after each instruction
        interpreter.dec_pc()
    return addresses
