from fa import utils

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('locate',
                                   description='goto label by name')
    p.add_argument('name')
    return p


def locate(name):
    return idc.get_name_ea_simple(name)


def run(segments, args, addresses, **kwargs):
    utils.verify_ida()
    address = locate(args.name)
    return [address] if address != idc.BADADDR else []
