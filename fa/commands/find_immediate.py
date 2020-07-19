from argparse import RawTextHelpFormatter

from fa import utils, context

try:
    import idc
    import ida_search
except ImportError:
    pass

DESCRIPTION = '''expands the result-set with the occurrences of the given
immediate in "ida immediate syntax"

EXAMPLE:
    0x00000000: ldr r0, =0x1234
    0x00000004: add r0, #2 ; 0x1236

    results = []
    -> find-immediate 0x1236
    result = [4]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('find-immediate',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('expression')
    return p


@context.ida_context
def find_immediate(expression):
    if isinstance(expression, str):
        expression = eval(expression)

    ea, imm = ida_search.find_imm(0, idc.SEARCH_DOWN, expression)
    while ea != idc.BADADDR:
        yield ea
        ea, imm = idc.find_imm(ea + 1, idc.SEARCH_DOWN,
                               expression)


def run(segments, args, addresses, interpreter=None, **kwargs):
    results = list(find_immediate(args.expression))
    return addresses + results
