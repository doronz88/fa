from fa import utils, context

try:
    import ida_funcs
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('make-function',
                                   description='convert into a function')
    return p


@context.ida_context
def make_function(addresses):
    for ea in addresses:
        ida_funcs.add_func(ea)
    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return make_function(addresses)
