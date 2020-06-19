from fa import utils, context

try:
    import idc
except ImportError:
    pass


def get_function_start(segments, ea):
    start = idc.get_func_attr(ea, idc.FUNCATTR_START)
    return start

    # TODO: consider add support locate of function heads manually


def get_parser():
    p = utils.ArgumentParserNoExit('function-start',
                                   description='goto function\'s prolog')
    p.add_argument('--not-unique', action='store_true')
    return p


@context.ida_context
def function_start(addresses):
    for ea in addresses:
        if ea != idc.BADADDR:
            func_start = idc.get_func_attr(ea, idc.FUNCATTR_START)
            if func_start != idc.BADADDR:
                yield func_start


def run(segments, args, addresses, interpreter=None, **kwargs):
    results = function_start(addresses)
    return list(results) if args.not_unique else list(set(results))
