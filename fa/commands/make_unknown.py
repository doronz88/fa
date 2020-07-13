from fa import utils, context

try:
    import ida_bytes
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('make-unknown',
                                   description='convert into an unknown block')
    return p


@context.ida_context
def make_unknown(addresses):
    for ea in addresses:
        ida_bytes.del_items(ea)
    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return make_unknown(addresses)
