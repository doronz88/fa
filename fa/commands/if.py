from argparse import RawTextHelpFormatter
from fa import utils

DESCRIPTION = '''perform an 'if' statement to create conditional branches
using an FA command

EXAMPLE:
    results = [0, 4, 8]

    -> if 'verify-single' a_is_single_label

    set-name a_isnt_single
    b end

    label a_is_single_label
    set-name a_is_single

    label end
'''


def get_parser():
    p = utils.ArgumentParserNoExit('if',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('cond', help='condition as an FA command')
    p.add_argument('label', help='label to jump to if condition is true')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    if len(interpreter.find_from_instructions_list([args.cond],
                                                   addresses=addresses)):
        interpreter.set_pc(args.label)

        # pc is incremented by 1, after each instruction
        interpreter.dec_pc()
    return addresses
