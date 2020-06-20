from fa.utils import ArgumentParserNoExit
from fa import context

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = ArgumentParserNoExit('set-name',
                             description='set name in disassembler')
    p.add_argument('name')
    return p


@context.ida_context
def set_name(addresses, name):
    for ea in addresses:
        idc.set_name(ea, name, idc.SN_CHECK)
    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return set_name(addresses, args.name)
