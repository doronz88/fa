from fa import utils, context

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = utils.ArgumentParserNoExit('locate',
                                   description='goto label by name')
    p.add_argument('name')
    return p


@context.ida_context
def locate(name):
    return idc.get_name_ea_simple(name)


def run(segments, args, addresses, interpreter=None, **kwargs):
    address = locate(args.name)
    return [address] if address != idc.BADADDR else []
