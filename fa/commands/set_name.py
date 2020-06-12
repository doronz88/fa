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


def set_name(addresses, name):
    utils.verify_ida()
    for ea in addresses:
        idc.set_name(ea, name, idc.SN_CHECK)
    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return set_name(addresses, args.name)
