from fa import utils

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('make-literal',
                                   description='convert into a literal')
    return p


def make_literal(addresses):
    utils.verify_ida()
    for ea in addresses:
        idc.create_strlit(ea, idc.BADADDR)
    return addresses


def run(segments, args, addresses, **kwargs):
    return make_literal(addresses)
