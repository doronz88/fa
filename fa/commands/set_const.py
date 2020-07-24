from fa import utils, fa_types, context


def get_parser():
    p = utils.ArgumentParserNoExit('set-const',
                                   description='define a const value')
    p.add_argument('name')
    return p


def set_const(addresses, name):
    for ea in addresses:
        fa_types.add_const(name, ea)
    return addresses


def run(segments, args, addresses, interpreter=None, **kwargs):
    return set_const(addresses, args.name)
