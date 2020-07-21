from fa.utils import ArgumentParserNoExit

try:
    import idc
except ImportError:
    pass


def get_parser():
    p = ArgumentParserNoExit('set-name',
                             description='set symbol name')
    p.add_argument('name')
    return p


def run(segments, args, addresses, interpreter=None, **kwargs):
    for ea in addresses:
        interpreter.set_symbol(args.name, ea)
    return addresses
