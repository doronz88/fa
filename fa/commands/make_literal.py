from fa import utils, context

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('make-literal',
                                   description='convert into a literal')
    return p


@context.ida_context
def make_literal(addresses):
    for ea in addresses:
        idc.create_strlit(ea, idc.BADADDR)
    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return make_literal(addresses)
