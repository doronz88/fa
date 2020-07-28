from fa.utils import ArgumentParserNoExit


def get_parser():
    p = ArgumentParserNoExit('set-name',
                             description='set symbol name')
    p.add_argument('name')
    return p


def set_name(addresses, name, interpreter):
    for ea in addresses:
        interpreter.set_symbol(name, ea)
    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return set_name(addresses, args.name, interpreter)
