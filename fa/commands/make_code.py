from fa import utils, context

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('make-code',
                                   description='convert into a code block')
    return p


@context.ida_context
def make_code(addresses):
    for ea in addresses:
        idc.create_insn(ea)
    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return make_code(addresses)
