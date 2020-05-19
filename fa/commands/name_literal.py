from fa.commands import utils

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('name-literal', description='convert into a literal')
    return p


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()

    for address in addresses:
        idc.create_strlit(address, idc.BADADDR)

    return addresses
