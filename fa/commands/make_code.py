from fa import utils

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('make-code',
                                   description='convert into a code block')
    return p


def make_code(addresses):
    for ea in addresses:
        idc.create_insn(ea, idc.BADADDR)
    return addresses


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()

    make_code(addresses)

    return addresses
