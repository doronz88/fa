from argparse import RawTextHelpFormatter
from fa import utils
from fa import context

try:
    import idc
except ImportError:
    pass

DESCRIPTION = '''goto function's end

EXAMPLE:
    0x00000000: push {r4-r7, lr} -> function's prolog
    ...
    0x000000f0: push {r4-r7, pc} -> function's epilog

    results = [0]
    -> function-end
    result = [0xf0]
'''


def get_parser():
    p = utils.ArgumentParserNoExit('function-end',
                                   description=DESCRIPTION,
                                   formatter_class=RawTextHelpFormatter)
    return p


@context.ida_context
def function_end(addresses):
    for ea in addresses:
        if ea != idc.BADADDR:
            func_end = idc.get_func_attr(ea, idc.FUNCATTR_END)
            if func_end != idc.BADADDR:
                yield func_end


def run(segments, args, addresses, interpreter=None, **kwargs):
    return list(function_end(addresses))
