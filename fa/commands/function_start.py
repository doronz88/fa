from argparse import RawTextHelpFormatter
from fa import utils, context

try:
    import idc
except ImportError:
    pass

DESCRIPTION = '''goto function's start

EXAMPLE:
    0x00000000: push {r4-r7, lr} -> function's prolog
    ...
    0x000000f0: pop {r4-r7, pc} -> function's epilog

    results = [0xf0]
    -> function-start
    result = [0]
'''


def get_function_start(segments, ea):
    start = idc.get_func_attr(ea, idc.FUNCATTR_START)
    return start

    # TODO: consider add support locate of function heads manually


def get_parser():
    p = utils.ArgumentParserNoExit('function-start',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    p.add_argument('cmd', nargs='*', default='', help='command')
    return p


@context.ida_context
def function_start(addresses):
    for ea in addresses:
        if ea != idc.BADADDR:
            func_start = idc.get_func_attr(ea, idc.FUNCATTR_START)
            if func_start != idc.BADADDR:
                yield func_start


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(function_start(addresses))
