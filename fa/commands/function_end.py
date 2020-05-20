from fa.commands import utils

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('function-end',
                                   description='goto function\'s end')
    p.add_argument('--not-unique', action='store_true')
    return p


def function_end(addresses):
    for ea in addresses:
        if ea != idc.BADADDR:
            func_end = idc.GetFunctionAttr(ea, idc.FUNCATTR_END)
            if func_end != idc.BADADDR:
                yield func_end


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()
    results = function_end(addresses)
    return list(results) if args.not_unique else list(set(results))
