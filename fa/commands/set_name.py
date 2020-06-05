from fa import utils

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('set-name',
                                   description='set name in disassembler')
    p.add_argument('name')
    return p


def set_name(address, name):
    idc.set_name(address, name, idc.SN_CHECK)


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()

    for address in addresses:
        set_name(address, args.name)

    return addresses
