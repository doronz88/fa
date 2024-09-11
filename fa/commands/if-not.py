from argparse import RawTextHelpFormatter

from fa import utils

DESCRIPTION = '''perform an 'if not' statement to create conditional branches
using an FA command

EXAMPLE:
    results = [0, 4, 8]

    -> if-not 'verify-single' a_is_single_label

    set-name a_is_single
    b end

    label a_is_not_single_label
    set-name a_is_not_single

    label end
'''


def get_parser():
    p = utils.ArgumentParserNoExit('if-not',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('cond', help='condition as an FA command')
    p.add_argument('label', help='label to jump to if condition is false')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    if len(interpreter.find_from_instructions_list([args.cond],
                                                   addresses=addresses[:])) == 0:
        interpreter.set_pc(args.label)

        # pc is incremented by 1, after each instruction
        interpreter.dec_pc()
    return addresses
