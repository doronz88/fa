from argparse import RawTextHelpFormatter
from fa import utils, context

try:
    import idautils
except ImportError:
    pass

DESCRIPTION = '''get all function's lines

EXAMPLE:
    0x00000000: push {r4-r7, lr} -> function's prolog
    0x00000004: mov r1, r0
    ...
    0x000000c0: mov r0, r5
    ...
    0x000000f0: push {r4-r7, pc} -> function's epilog

    results = [0xc0]
    -> function-lines
    result = [0, 4, ..., 0xc0, ..., 0xf0]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('function-lines',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('--after', action='store_true',
                   help='include only function lines which occur after current'
                        'resultset')
    return p


@context.ida_context
def function_lines(addresses, after=False):
    for address in addresses:
        for item in idautils.FuncItems(address):
            if not after:
                yield item
            else:
                if item > address:
                    yield item


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(function_lines(addresses, args.after))
