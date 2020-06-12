from fa import utils

try:
    import ida_funcs
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('make-function',
                                   description='convert into a function')
    return p


def make_code(addresses):
    utils.verify_ida()
    for ea in addresses:
        ida_funcs.add_func(ea)
    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return make_code(addresses)
