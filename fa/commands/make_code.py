from fa import utils

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('make-literal',
                                   description='convert into a literal')
    return p


def make_code(addresses):
    for ea in addresses:
        idc.create_insn(ea, idc.BADADDR)


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()

    make_code(addresses)

    return addresses
