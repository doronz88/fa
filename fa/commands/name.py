from fa.commands import utils

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit()
    p.add_argument('name')
    return p


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()

    for address in addresses:
        idc.MakeName(address, args.name)

    return addresses
