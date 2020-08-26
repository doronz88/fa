from argparse import RawTextHelpFormatter
from fa import utils, context

try:
    import idc
except ImportError:
    pass

DESCRIPTION = '''get operand value from given instruction

EXAMPLE #1:
    0x00000000: mov r0, r1
    0x00000004: mov r1, r2
    0x00000008: push {r4}

    results = [4]
    -> operand 1
    results = [2]  # because r2
'''


def get_parser():
    p = utils.ArgumentParserNoExit('operand',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('op', help='operand number')
    return p


@context.ida_context
def operand(addresses, op):
    for address in addresses:
        yield idc.get_operand_value(address, op)


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(operand(addresses, eval(args.op)))
